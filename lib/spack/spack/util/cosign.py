# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Thin wrapper around the ``cosign`` executable, used to sign and verify OCI images."""
from typing import List, Optional

import spack.error
import spack.util.executable
from spack.util.executable import Executable

#: Executable instance for "cosign", initialized lazily
_COSIGN: Optional[Executable] = None


class CosignError(spack.error.SpackError):
    """Raised when cosign fails to sign or verify."""


def _cosign() -> Executable:
    global _COSIGN
    if _COSIGN is None:
        import spack.bootstrap

        with spack.bootstrap.ensure_bootstrap_configuration():
            _COSIGN = spack.bootstrap.ensure_cosign_in_path_or_raise()
    return _COSIGN


def _common_args(insecure_registry: bool) -> List[str]:
    args = ["--yes"]
    if insecure_registry:
        args.append("--allow-insecure-registry")
    return args


def sign_image(ref: str, key: str, insecure_registry: bool = False) -> None:
    """Sign an image with a key-based cosign signature.

    Args:
        ref: image reference *by digest* (``domain/name@sha256:...``). Signing a tag is
            refused, since the tag may be moved after the signature is made.
        key: path to a cosign private key, or a KMS URI understood by cosign
        insecure_registry: allow plain-http registries
    """
    _require_digest(ref)
    try:
        _cosign()("sign", "--key", key, *_common_args(insecure_registry), ref, output=str, error=str)
    except spack.util.executable.ProcessError as e:
        raise CosignError(f"cosign failed to sign {ref}: {e}") from e


def verify_image(ref: str, key: str, insecure_registry: bool = False) -> None:
    """Verify the cosign signature of an image against a public key.

    Raises:
        CosignError: if there is no signature, or it does not verify against ``key``
    """
    _require_digest(ref)
    args = ["verify", "--key", key]
    if insecure_registry:
        args.append("--allow-insecure-registry")
    try:
        _cosign()(*args, ref, output=str, error=str)
    except spack.util.executable.ProcessError as e:
        raise CosignError(f"cosign could not verify {ref}: {e}") from e


def _require_digest(ref: str) -> None:
    if "@sha256:" not in ref:
        raise CosignError(f"cosign operations require a digest reference, got '{ref}'")
