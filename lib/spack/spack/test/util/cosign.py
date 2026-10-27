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


ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY = "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"


def test_verify_keyless(fake_cosign):
    cosign.verify_image_keyless(f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY)
    assert fake_cosign.calls == [
        (
            "verify",
            "--certificate-identity",
            IDENTITY,
            "--certificate-oidc-issuer",
            ISSUER,
            f"example.com/img@{DIGEST}",
        )
    ]


def test_verify_keyless_never_skips_the_transparency_log(fake_cosign):
    """The certificates are only valid for minutes, and the log is what proves the signature was
    made in that time. Skipping it would accept signatures made with long expired certificates."""
    cosign.verify_image_keyless(f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY)
    cosign.verify_image_keyless(f"example.com/img@{DIGEST}", issuer=ISSUER, identity_regexp="a")
    assert not any("--insecure-ignore-tlog" in call for call in fake_cosign.calls)
    assert not any("--key" in call for call in fake_cosign.calls)


def test_verify_keyless_trusted_root(fake_cosign):
    cosign.verify_image_keyless(
        f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY, trusted_root="root.json"
    )
    args = fake_cosign.calls[0]
    assert args[args.index("--trusted-root") + 1] == "root.json"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": ISSUER},  # who?
        {"issuer": ISSUER, "identity": IDENTITY, "identity_regexp": "x"},  # which one?
        {"issuer": "", "identity": IDENTITY},  # vouched for by whom?
    ],
)
def test_verify_keyless_requires_the_signer_to_be_pinned(fake_cosign, kwargs):
    with pytest.raises(cosign.CosignError):
        cosign.verify_image_keyless(f"example.com/img@{DIGEST}", **kwargs)
    assert not fake_cosign.calls


def test_verify_keyless_tag_is_refused(fake_cosign):
    with pytest.raises(cosign.CosignError, match="digest reference"):
        cosign.verify_image_keyless("example.com/img:latest", issuer=ISSUER, identity=IDENTITY)


@pytest.mark.parametrize(
    "pattern,matches,does_not_match",
    [
        (
            "https://github.com/org/repo",
            "https://github.com/org/repo",
            "https://github.com/org/repo-evil",
        ),
        (
            "https://github.com/org/repo/.*",
            "https://github.com/org/repo/x",
            "https://github.com/org/repo-evil/x",
        ),
        (
            "^https://github.com/org/(a|b)$",
            "https://github.com/org/b",
            "https://github.com/org/bc",
        ),
        ("a|b", "b", "xb"),
    ],
)
def test_identity_pattern_must_match_the_whole_identity(pattern, matches, does_not_match):
    import re

    anchored = cosign._anchored(pattern)
    assert re.search(anchored, matches)
    assert not re.search(anchored, does_not_match)


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        ".*",
        ".+",
        "^.*$",
        ".*$",
        "(.*)",
        ".*?",
        "^.*?$",
        r"[\s\S]*",
        ".{0,}",
        "a|.*",
        "(a|.*)",
        "^$|.*",
        ".*@.*",  # any address at any domain
    ],
)
def test_identity_pattern_matching_everyone_is_refused(pattern):
    with pytest.raises(cosign.CosignError, match="matches every signer"):
        cosign._anchored(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"https://github.com/org/repo/.github/workflows/ci.yml@.*",
        r"https://github.com/org/(a|b)/.*",
        r".*@example.com",
        r"^https://github.com/org/repo$",
        r"https://github.com/org/repo/\$",
    ],
)
def test_identity_patterns_that_name_someone_are_accepted(pattern):
    import re

    assert re.compile(cosign._anchored(pattern))


def test_escaped_dollar_is_kept():
    """A literal dollar at the end of a pattern is part of the identity, not an anchor."""
    import re

    anchored = cosign._anchored(r"https://github.com/org/repo/\$")
    assert re.search(anchored, "https://github.com/org/repo/$")
    assert not re.search(anchored, "https://github.com/org/repo/")


def test_invalid_identity_pattern_is_refused():
    with pytest.raises(cosign.CosignError, match="not a valid pattern"):
        cosign._anchored("https://github.com/(org")


def test_old_cosign_cannot_verify_keyless(monkeypatch):
    fake = _install(monkeypatch, FakeCosign(major=2))
    with pytest.raises(cosign.CosignError, match="not supported"):
        cosign.verify_image_keyless(f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY)
    assert not fake.calls


def test_sign_keyless(fake_cosign):
    cosign.sign_image_keyless(f"example.com/img@{DIGEST}")
    (args,) = fake_cosign.calls
    assert args[0] == "sign" and args[-1] == f"example.com/img@{DIGEST}"
    assert "--key" not in args


def test_sign_keyless_never_logs_in_interactively(fake_cosign):
    """Cosign would fall back to an interactive login without an identity token, which cannot
    be seen or answered while its output is captured."""
    cosign.sign_image_keyless(f"example.com/img@{DIGEST}")
    assert "--fulcio-auth-flow=token" in fake_cosign.calls[0]


def test_sign_keyless_plain_http_registry(fake_cosign):
    cosign.sign_image_keyless(f"localhost:5000/img@{DIGEST}", insecure_registry=True)
    assert "--allow-http-registry" in fake_cosign.calls[0]


def test_sign_keyless_tag_is_refused(fake_cosign):
    with pytest.raises(cosign.CosignError, match="digest reference"):
        cosign.sign_image_keyless("example.com/img:latest")
    assert not fake_cosign.calls


def test_sign_keyless_failure_says_what_is_needed(monkeypatch):
    _install(monkeypatch, FakeCosign(fail=True))
    with pytest.raises(cosign.CosignError, match="boom"):  # cosign's own reason is kept
        cosign.sign_image_keyless(f"example.com/img@{DIGEST}")


def test_keyless_signer_signs_then_verifies_the_identity(fake_cosign):
    signer = cosign.KeylessSigner(issuer=ISSUER, identity=IDENTITY)
    signer.sign(f"example.com/img@{DIGEST}")
    sign, verify = fake_cosign.calls
    assert sign[0] == "sign" and verify[0] == "verify"
    assert verify[verify.index("--certificate-identity") + 1] == IDENTITY
    assert verify[verify.index("--certificate-oidc-issuer") + 1] == ISSUER


def test_keyless_signer_fails_when_signed_as_another_identity(monkeypatch):
    """The signature is made, but by someone clients do not trust: that must be an error."""
    fake = FakeCosign()

    def reject_verify(*args, **kwargs):
        if args[0] == "verify":
            raise ProcessError("no matching signatures")

    fake.on_call = reject_verify
    _install(monkeypatch, fake)
    with pytest.raises(cosign.CosignError, match="not by the identity"):
        cosign.KeylessSigner(issuer=ISSUER, identity=IDENTITY).sign(f"example.com/img@{DIGEST}")


def test_keyless_signer_does_not_verify_when_signing_failed(monkeypatch):
    fake = _install(monkeypatch, FakeCosign(fail=True))
    with pytest.raises(cosign.CosignError, match="boom"):
        cosign.KeylessSigner(issuer=ISSUER, identity=IDENTITY).sign(f"example.com/img@{DIGEST}")
    assert [call[0] for call in fake.calls] == ["sign"]


@pytest.mark.parametrize("kwargs", [{}, {"identity": IDENTITY, "identity_regexp": "x"}])
def test_keyless_signer_needs_exactly_one_identity(kwargs):
    with pytest.raises(cosign.CosignError):
        cosign.KeylessSigner(issuer=ISSUER, **kwargs)


@pytest.fixture
def registry_login(monkeypatch):
    """Make a mirror provide credentials for the registry example.com."""
    import spack.oci.opener

    monkeypatch.setattr(
        spack.oci.opener,
        "credentials_from_mirrors",
        lambda domain, **kwargs: (
            spack.oci.opener.UsernamePassword("alice", "s3cret")
            if domain == "example.com"
            else None
        ),
    )


def _record_login(fake_cosign):
    """Record what cosign sees of the login when it runs, since the file is deleted afterwards."""
    seen = []

    def record(*args, **kwargs):
        env = kwargs.get("extra_env") or {}
        if "DOCKER_CONFIG" not in env:
            seen.append(None)
            return
        directory = env["DOCKER_CONFIG"]
        path = os.path.join(directory, "config.json")
        with open(path, encoding="utf-8") as f:
            content = json.load(f)
        seen.append(
            {
                "content": content,
                "file_mode": os.stat(path).st_mode & 0o777,
                "dir_mode": os.stat(directory).st_mode & 0o777,
                "directory": directory,
                "argv": args,
            }
        )

    fake_cosign.on_call = record
    return seen


@pytest.mark.parametrize(
    "call",
    [
        lambda: cosign.sign_image(f"example.com/img@{DIGEST}", "key"),
        lambda: cosign.verify_image(f"example.com/img@{DIGEST}", "key"),
        lambda: cosign.sign_image_keyless(f"example.com/img@{DIGEST}"),
        lambda: cosign.verify_image_keyless(
            f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY
        ),
    ],
    ids=["sign", "verify", "sign-keyless", "verify-keyless"],
)
def test_every_use_of_cosign_is_logged_in_to_the_registry(
    fake_cosign, registry_login, monkeypatch, call
):
    """Cosign has no option for credentials other than a Docker config, and it would otherwise be
    refused by registries that need a login."""
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    seen = _record_login(fake_cosign)
    call()
    (login,) = seen
    assert login is not None, "cosign ran without the credentials of the registry"

    import base64

    auth = login["content"]["auths"]["example.com"]["auth"]
    assert base64.b64decode(auth) == b"alice:s3cret"


def test_login_is_private_and_removed(fake_cosign, registry_login, monkeypatch):
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    seen = _record_login(fake_cosign)
    cosign.sign_image(f"example.com/img@{DIGEST}", "key")
    (login,) = seen
    assert login["file_mode"] == 0o600 and login["dir_mode"] == 0o700
    assert not os.path.exists(login["directory"])


def test_login_is_removed_when_cosign_fails(monkeypatch, registry_login):
    fake = _install(monkeypatch, FakeCosign(fail=True))
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    seen = _record_login(fake)
    with pytest.raises(cosign.CosignError):
        cosign.verify_image(f"example.com/img@{DIGEST}", "key")
    assert not os.path.exists(seen[0]["directory"])


def test_credentials_are_not_on_the_command_line(fake_cosign, registry_login, monkeypatch):
    """The process list, and the command echoed by errors, would show them."""
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    seen = _record_login(fake_cosign)
    cosign.sign_image(f"example.com/img@{DIGEST}", "key")
    assert "s3cret" not in " ".join(seen[0]["argv"])


def test_no_login_without_credentials_for_the_registry(fake_cosign, registry_login, monkeypatch):
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    seen = _record_login(fake_cosign)
    cosign.sign_image(f"other.example.org/img@{DIGEST}", "key")
    assert seen == [None]


def _record_tuf_root(fake_cosign):
    seen = []

    def record(*args, **kwargs):
        env = kwargs.get("extra_env") or {}
        root = env.get("TUF_ROOT")
        seen.append(None if root is None else {"root": root, "writable": os.access(root, os.W_OK)})

    fake_cosign.on_call = record
    return seen


@pytest.mark.parametrize(
    "call",
    [
        lambda: cosign.sign_image_keyless(f"example.com/img@{DIGEST}"),
        lambda: cosign.verify_image_keyless(
            f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY
        ),
    ],
    ids=["sign-keyless", "verify-keyless"],
)
def test_keyless_runs_have_their_own_sigstore_cache(fake_cosign, call):
    """Images are signed from several threads, and cosign rewrites its shared cache of the
    Sigstore trust metadata every time it runs."""
    seen = _record_tuf_root(fake_cosign)
    call()
    call()
    first, second = seen
    assert first["writable"] and second["writable"]
    assert first["root"] != second["root"]
    assert not os.path.exists(first["root"]) and not os.path.exists(second["root"])


@pytest.mark.parametrize(
    "call",
    [
        lambda: cosign.sign_image(f"example.com/img@{DIGEST}", "key"),
        lambda: cosign.verify_image(f"example.com/img@{DIGEST}", "key"),
    ],
    ids=["sign-key", "verify-key"],
)
def test_runs_with_a_key_do_not_use_sigstore_at_all(fake_cosign, monkeypatch, call):
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    seen = _record_tuf_root(fake_cosign)
    call()
    assert seen == [None]


@pytest.fixture
def no_cosign(monkeypatch):
    import spack.bootstrap

    monkeypatch.setattr(cosign, "_COSIGN", None)
    monkeypatch.setattr(cosign, "_COSIGN_MAJOR", None)

    def cannot_bootstrap(*args, **kwargs):
        raise RuntimeError("no network to build cosign")

    monkeypatch.setattr(spack.bootstrap, "ensure_cosign_in_path_or_raise", cannot_bootstrap)


@pytest.mark.parametrize(
    "call",
    [
        lambda: cosign.sign_image(f"example.com/img@{DIGEST}", "/no/such/key"),
        lambda: cosign.verify_image(f"example.com/img@{DIGEST}", "key"),
        lambda: cosign.sign_image_keyless(f"example.com/img@{DIGEST}"),
        lambda: cosign.verify_image_keyless(
            f"example.com/img@{DIGEST}", issuer=ISSUER, identity=IDENTITY
        ),
    ],
    ids=["sign", "verify", "sign-keyless", "verify-keyless"],
)
def test_missing_cosign_is_a_cosign_error(no_cosign, call):
    """Callers handle CosignError. A bare RuntimeError from a failed bootstrap would abort an
    install that could have used another mirror."""
    with pytest.raises(cosign.CosignError, match="no network to build cosign"):
        call()


def test_cosign_is_looked_up_once_from_many_threads(monkeypatch):
    import concurrent.futures
    import time

    import spack.bootstrap

    monkeypatch.setattr(cosign, "_COSIGN", None)
    lookups = []

    def slow_lookup():
        lookups.append(1)
        time.sleep(0.05)
        return FakeCosign()

    monkeypatch.setattr(spack.bootstrap, "ensure_cosign_in_path_or_raise", slow_lookup)
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda _: cosign._cosign(), range(8)))
    assert len(lookups) == 1


@pytest.fixture
def public_key_file(tmp_path):
    path = tmp_path / "cosign.pub"
    path.write_text("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n")
    return str(path)


def test_public_key_is_not_asked_a_password_for(fake_cosign, public_key_file, monkeypatch):
    """The key of a mirror is the public key where images are installed. Asking for a password
    for it, or letting cosign wait for one, would send the user the wrong way."""
    monkeypatch.delenv("COSIGN_PASSWORD", raising=False)
    monkeypatch.setattr(cosign, "_PASSWORD", None)
    prompts = _terminal(monkeypatch, isatty=True)
    with pytest.raises(cosign.CosignError, match="is a public key"):
        cosign.prepare_signing_key(public_key_file)
    assert not prompts


def test_signing_with_a_public_key_is_refused_before_cosign_runs(fake_cosign, public_key_file):
    with pytest.raises(cosign.CosignError, match="signing needs the private key"):
        cosign.sign_image(f"example.com/img@{DIGEST}", public_key_file)
    assert not fake_cosign.calls


def test_verifying_with_a_public_key_is_fine(fake_cosign, public_key_file):
    cosign.verify_image(f"example.com/img@{DIGEST}", public_key_file)
    assert len(fake_cosign.calls) == 1
