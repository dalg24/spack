# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import pytest

import spack.util.cosign as cosign
from spack.util.executable import ProcessError

DIGEST = "sha256:" + "a" * 64


class FakeCosign:
    """Stands in for the cosign Executable and records its invocations."""

    def __init__(self, fail: bool = False):
        self.calls = []
        self.fail = fail

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        if self.fail:
            raise ProcessError("cosign: boom")


@pytest.fixture
def fake_cosign(monkeypatch):
    fake = FakeCosign()
    monkeypatch.setattr(cosign, "_COSIGN", fake)
    return fake


def test_sign_image(fake_cosign):
    cosign.sign_image(f"example.com/img@{DIGEST}", "cosign.key")
    assert fake_cosign.calls == [
        ("sign", "--key", "cosign.key", "--yes", f"example.com/img@{DIGEST}")
    ]


def test_verify_image(fake_cosign):
    cosign.verify_image(f"example.com/img@{DIGEST}", "cosign.pub", insecure_registry=True)
    assert fake_cosign.calls == [
        ("verify", "--key", "cosign.pub", "--allow-insecure-registry", f"example.com/img@{DIGEST}")
    ]


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
