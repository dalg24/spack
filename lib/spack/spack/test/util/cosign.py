# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import json
import os
import sys

import pytest

import spack.util.cosign as cosign
from spack.util.executable import ProcessError

DIGEST = "sha256:" + "a" * 64


def _version_output(major: int) -> str:
    return f"cosign: A tool for Container Signing\n\nGitVersion:    v{major}.1.0\n"


class FakeCosign:
    """Stands in for the cosign Executable and records its invocations."""

    def __init__(self, major: int = 3, fail: bool = False):
        self.calls = []
        self.major = major
        self.fail = fail
        self.on_call = None

    def __call__(self, *args, **kwargs):
        if args == ("version",):
            return _version_output(self.major)
        self.calls.append(args)
        if self.on_call:
            self.on_call(*args, **kwargs)
        if self.fail:
            raise ProcessError("cosign: boom")


def _install(monkeypatch, fake):
    monkeypatch.setattr(cosign, "_COSIGN", fake)
    monkeypatch.setattr(cosign, "_COSIGN_MAJOR", None)
    return fake


@pytest.fixture
def fake_cosign(monkeypatch):
    return _install(monkeypatch, FakeCosign())


def test_sign_image(fake_cosign):
    cosign.sign_image(f"example.com/img@{DIGEST}", "cosign.key")
    (args,) = fake_cosign.calls
    assert args[:4] == ("sign", "--key", "cosign.key", "--yes")
    assert args[-1] == f"example.com/img@{DIGEST}"
    assert "--allow-http-registry" not in args


def test_sign_image_is_offline(fake_cosign):
    """Cosign contacts a public transparency log and timestamp authority even when signing with
    a key, unless given a signing config that has neither."""
    seen = {}

    def record(*args, **kwargs):
        with open(args[args.index("--signing-config") + 1], encoding="utf-8") as f:
            seen["config"] = json.load(f)

    fake_cosign.on_call = record
    cosign.sign_image(f"example.com/img@{DIGEST}", "cosign.key")
    assert seen["config"]["rekorTlogConfig"] == {}
    assert seen["config"]["tsaConfig"] == {}
    assert not any(k in seen["config"] for k in ("rekorTlogUrls", "tsaUrls", "caUrls"))
    assert "--tlog-upload=false" not in fake_cosign.calls[0]


@pytest.mark.parametrize("major", [1, 2])
@pytest.mark.parametrize("fn", [cosign.sign_image, cosign.verify_image])
def test_old_cosign_is_refused(monkeypatch, major, fn):
    """Neither signing nor verifying is done with a cosign that is older than supported."""
    fake = _install(monkeypatch, FakeCosign(major=major))
    with pytest.raises(cosign.CosignError, match=f"cosign {major} is not supported, use cosign 3"):
        fn(f"example.com/img@{DIGEST}", "key")
    assert not fake.calls


def test_newer_cosign_is_accepted(monkeypatch):
    fake = _install(monkeypatch, FakeCosign(major=4))
    cosign.verify_image(f"example.com/img@{DIGEST}", "key")
    assert len(fake.calls) == 1


def test_unparseable_version(monkeypatch):
    monkeypatch.setattr(cosign, "_COSIGN", lambda *args, **kwargs: "garbage")
    monkeypatch.setattr(cosign, "_COSIGN_MAJOR", None)
    with pytest.raises(cosign.CosignError, match="could not determine the version"):
        cosign.sign_image(f"example.com/img@{DIGEST}", "cosign.key")


def test_verify_image(fake_cosign):
    cosign.verify_image(f"example.com/img@{DIGEST}", "cosign.pub")
    assert fake_cosign.calls == [
        ("verify", "--key", "cosign.pub", "--insecure-ignore-tlog", f"example.com/img@{DIGEST}")
    ]


@pytest.mark.parametrize("fn", [cosign.sign_image, cosign.verify_image])
def test_plain_http_registry(fake_cosign, fn):
    fn(f"localhost:5000/img@{DIGEST}", "key", insecure_registry=True)
    assert "--allow-http-registry" in fake_cosign.calls[0]
    assert "--allow-insecure-registry" not in fake_cosign.calls[0]


@pytest.mark.parametrize("fn", [cosign.sign_image, cosign.verify_image])
def test_tag_references_are_refused(fake_cosign, fn):
    with pytest.raises(cosign.CosignError, match="digest reference"):
        fn("example.com/img:latest", "key")
    assert not fake_cosign.calls


@pytest.mark.parametrize("fn", [cosign.sign_image, cosign.verify_image])
def test_cosign_failure_raises(monkeypatch, fn):
    _install(monkeypatch, FakeCosign(fail=True))
    with pytest.raises(cosign.CosignError, match="boom"):
        fn(f"example.com/img@{DIGEST}", "key")


@pytest.fixture
def key_file(tmp_path, monkeypatch):
    path = tmp_path / "cosign.key"
    path.write_text("-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n")
    monkeypatch.delenv("COSIGN_PASSWORD", raising=False)
    monkeypatch.setattr(cosign, "_PASSWORD", None)
    return str(path)


def _terminal(monkeypatch, isatty: bool, answer: str = "secret"):
    prompts = []
    monkeypatch.setattr(sys, "stdin", type("Stdin", (), {"isatty": lambda self: isatty})())
    monkeypatch.setattr(cosign.getpass, "getpass", lambda prompt: prompts.append(prompt) or answer)
    return prompts


def test_password_is_asked_once_and_only_given_to_cosign(fake_cosign, key_file, monkeypatch):
    prompts = _terminal(monkeypatch, isatty=True)
    envs = []
    fake_cosign.on_call = lambda *args, **kwargs: envs.append(kwargs.get("extra_env"))

    cosign.prepare_signing_key(key_file)
    for _ in range(3):
        cosign.sign_image(f"example.com/img@{DIGEST}", key_file)

    assert len(prompts) == 1 and key_file in prompts[0]
    assert envs == [{"COSIGN_PASSWORD": "secret"}] * 3
    assert "COSIGN_PASSWORD" not in os.environ


def test_environment_password_is_not_asked_for(fake_cosign, key_file, monkeypatch):
    prompts = _terminal(monkeypatch, isatty=True)
    monkeypatch.setenv("COSIGN_PASSWORD", "")  # set but empty: the key has no password
    envs = []
    fake_cosign.on_call = lambda *args, **kwargs: envs.append(kwargs.get("extra_env"))

    cosign.prepare_signing_key(key_file)
    cosign.sign_image(f"example.com/img@{DIGEST}", key_file)

    assert not prompts
    assert envs == [None]  # cosign reads it from the environment itself


def test_no_password_without_terminal_is_an_error(fake_cosign, key_file, monkeypatch):
    prompts = _terminal(monkeypatch, isatty=False)
    with pytest.raises(cosign.CosignError, match="COSIGN_PASSWORD"):
        cosign.prepare_signing_key(key_file)
    assert not prompts


def test_signing_never_prompts_by_itself(fake_cosign, key_file, monkeypatch):
    """sign_image runs in worker threads, where a prompt would be invisible, so it must fail
    instead of letting cosign ask."""
    prompts = _terminal(monkeypatch, isatty=True)
    with pytest.raises(cosign.CosignError, match="COSIGN_PASSWORD"):
        cosign.sign_image(f"example.com/img@{DIGEST}", key_file)
    assert not prompts and not fake_cosign.calls


@pytest.mark.parametrize("key", ["awskms:///arn:aws:kms:key", "hashivault://key", "/no/such/file"])
def test_keys_that_are_not_files_are_not_asked_for(fake_cosign, monkeypatch, key):
    monkeypatch.delenv("COSIGN_PASSWORD", raising=False)
    monkeypatch.setattr(cosign, "_PASSWORD", None)
    prompts = _terminal(monkeypatch, isatty=True)
    cosign.prepare_signing_key(key)
    cosign.sign_image(f"example.com/img@{DIGEST}", key)
    assert not prompts and len(fake_cosign.calls) == 1
