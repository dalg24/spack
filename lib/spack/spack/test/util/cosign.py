# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import json

import pytest

import spack.util.cosign as cosign
from spack.util.executable import ProcessError

DIGEST = "sha256:" + "a" * 64


class FakeCosign:
    """Stands in for the cosign Executable and records its invocations."""

    def __init__(self, fail: bool = False):
        self.calls = []
        self.fail = fail
        self.on_call = None

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        if self.on_call:
            self.on_call(*args, **kwargs)
        if self.fail:
            raise ProcessError("cosign: boom")


@pytest.fixture
def fake_cosign(monkeypatch):
    fake = FakeCosign()
    monkeypatch.setattr(cosign, "_COSIGN", fake)
    return fake


def test_sign_image(fake_cosign):
    cosign.sign_image(f"example.com/img@{DIGEST}", "cosign.key")
    (args,) = fake_cosign.calls
    assert args[:4] == ("sign", "--key", "cosign.key", "--yes")
    assert args[-1] == f"example.com/img@{DIGEST}"
    assert "--allow-http-registry" not in args


def test_sign_image_is_offline(fake_cosign, monkeypatch):
    """Signing must pass a signing config without a transparency log or timestamp authority,
    as cosign 3 would otherwise contact public services even when signing with a key."""
    seen = {}

    def record(*args, **kwargs):
        config = args[args.index("--signing-config") + 1]
        with open(config, encoding="utf-8") as f:
            seen["config"] = json.load(f)

    fake_cosign.on_call = record
    cosign.sign_image(f"example.com/img@{DIGEST}", "cosign.key")
    assert seen["config"]["rekorTlogConfig"] == {}
    assert seen["config"]["tsaConfig"] == {}
    assert not any(k in seen["config"] for k in ("rekorTlogUrls", "tsaUrls", "caUrls"))


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
    monkeypatch.setattr(cosign, "_COSIGN", FakeCosign(fail=True))
    with pytest.raises(cosign.CosignError, match="boom"):
        fn(f"example.com/img@{DIGEST}", "key")
