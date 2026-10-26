# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Thin wrapper around the ``cosign`` executable, used to sign and verify OCI images with a
key. Neither signing nor verification contacts any Sigstore service, so this works on machines
without access to the public internet."""

import json
import os
import tempfile
from typing import List, Optional

import spack.error
import spack.util.executable
from spack.util.executable import Executable

#: Executable instance for "cosign", initialized lazily
_COSIGN: Optional[Executable] = None

#: A signing config without any Fulcio, Rekor or timestamp authority service. Cosign 3 would
#: otherwise contact a public timestamp authority and transparency log when signing, also when
#: signing with a key.
_OFFLINE_SIGNING_CONFIG = {
    "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
    "rekorTlogConfig": {},
    "tsaConfig": {},
}


class CosignError(spack.error.SpackError):
    """Raised when cosign fails to sign or verify."""


def _cosign() -> Executable:
    global _COSIGN
    if _COSIGN is None:
        import spack.bootstrap

        with spack.bootstrap.ensure_bootstrap_configuration():
            _COSIGN = spack.bootstrap.ensure_cosign_in_path_or_raise()
    return _COSIGN


def _registry_args(insecure_registry: bool) -> List[str]:
    return ["--allow-http-registry"] if insecure_registry else []


def sign_image(ref: str, key: str, insecure_registry: bool = False) -> None:
    """Sign an image with a key-based cosign signature, stored in the image's repository.

    Args:
        ref: image reference *by digest* (``domain/name@sha256:...``). Signing a tag is
            refused, since the tag may be moved after the signature is made.
        key: path to a cosign private key, or a KMS URI understood by cosign. If the key is
            encrypted, cosign reads the password from ``COSIGN_PASSWORD``.
        insecure_registry: the registry speaks plain http
    """
    _require_digest(ref)
    with tempfile.TemporaryDirectory() as tmpdir:
        config = os.path.join(tmpdir, "signing-config.json")
        with open(config, "w", encoding="utf-8") as f:
            json.dump(_OFFLINE_SIGNING_CONFIG, f)
        try:
            _cosign()(
                "sign",
                "--key",
                key,
                "--yes",
                "--signing-config",
                config,
                *_registry_args(insecure_registry),
                ref,
                output=str,
                error=str,
            )
        except spack.util.executable.ProcessError as e:
            raise CosignError(f"cosign failed to sign {ref}: {e}") from e


def verify_image(ref: str, key: str, insecure_registry: bool = False) -> None:
    """Verify the cosign signature of an image against a public key.

    Raises:
        CosignError: if there is no signature, or it does not verify against ``key``
    """
    _require_digest(ref)
    try:
        _cosign()(
            "verify",
            "--key",
            key,
            "--insecure-ignore-tlog",
            *_registry_args(insecure_registry),
            ref,
            output=str,
            error=str,
        )
    except spack.util.executable.ProcessError as e:
        raise CosignError(f"cosign could not verify {ref}: {e}") from e


def _require_digest(ref: str) -> None:
    if "@sha256:" not in ref:
        raise CosignError(f"cosign operations require a digest reference, got '{ref}'")
