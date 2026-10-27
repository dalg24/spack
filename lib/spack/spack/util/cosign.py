# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Thin wrapper around the ``cosign`` executable, used to sign and verify OCI images with a
key. Neither signing nor verification contacts any Sigstore service, so this works on machines
without access to the public internet. Cosign 2 and 3 are supported."""

import getpass
import json
import os
import re
import sys
import tempfile
from typing import List, Optional

import spack.error
import spack.util.executable
from spack.util.executable import Executable

#: Executable instance for "cosign", initialized lazily
_COSIGN: Optional[Executable] = None

#: Password of the private key, if it was asked for. It is only handed to the cosign process.
_PASSWORD: Optional[str] = None

#: Major version of the cosign executable, determined on first use
_COSIGN_MAJOR: Optional[int] = None

#: A signing config without any Fulcio, Rekor or timestamp authority service. Cosign 3 would
#: otherwise contact a public timestamp authority and transparency log when signing, also when
#: signing with a key. Cosign 2 has no signing configs, and uses ``--tlog-upload=false``.
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


def _major_version() -> int:
    global _COSIGN_MAJOR
    if _COSIGN_MAJOR is None:
        try:
            out = _cosign()("version", output=str, error=str)
        except spack.util.executable.ProcessError as e:
            raise CosignError(f"could not determine the version of cosign: {e}") from e
        match = re.search(r"GitVersion:\s+v?(\d+)\.", out if isinstance(out, str) else "")
        if not match:
            raise CosignError("could not determine the version of cosign")
        _COSIGN_MAJOR = int(match.group(1))
    return _COSIGN_MAJOR


def _needs_password(key: str) -> bool:
    """Whether signing with this key needs a password that is not available yet. Only key files
    are protected by a password. Other key references, like KMS URIs, are not."""
    return os.path.isfile(key) and "COSIGN_PASSWORD" not in os.environ and _PASSWORD is None


def prepare_signing_key(key: str) -> None:
    """Ask for the password of a private key file, if needed, so that signing never has to.

    Call this once from the main thread before signing: cosign would otherwise ask for the
    password itself, which cannot be seen while Spack captures its output, and it would ask
    for every image. The password is kept in memory and only given to cosign. If
    ``COSIGN_PASSWORD`` is set, it is used instead, and an empty value means the key has no
    password.

    Raises:
        CosignError: if the password is needed and cannot be asked for
    """
    global _PASSWORD
    if not _needs_password(key):
        return
    if not sys.stdin.isatty():
        raise CosignError(_NO_PASSWORD_MESSAGE.format(key=key))
    _PASSWORD = getpass.getpass(f"Password for cosign key {key} (empty if it has none): ")


_NO_PASSWORD_MESSAGE = (
    "The password for the cosign key {key} is needed, but cannot be asked for without a "
    "terminal. Set the COSIGN_PASSWORD environment variable, to an empty value if the key has "
    "no password."
)


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
    if _needs_password(key):
        # Never let cosign prompt: this may run in a thread, and the prompt would be invisible
        raise CosignError(_NO_PASSWORD_MESSAGE.format(key=key))
    major = _major_version()
    if major < 2:
        raise CosignError(f"cosign {major} is not supported, use cosign 2 or newer")

    with tempfile.TemporaryDirectory() as tmpdir:
        offline_args = ["--tlog-upload=false"]
        if major >= 3:
            config = os.path.join(tmpdir, "signing-config.json")
            with open(config, "w", encoding="utf-8") as f:
                json.dump(_OFFLINE_SIGNING_CONFIG, f)
            offline_args = ["--signing-config", config]
        try:
            _cosign()(
                "sign",
                "--key",
                key,
                "--yes",
                *offline_args,
                *_registry_args(insecure_registry),
                ref,
                output=str,
                error=str,
                extra_env=(
                    {"COSIGN_PASSWORD": _PASSWORD}
                    if _PASSWORD is not None and "COSIGN_PASSWORD" not in os.environ
                    else None
                ),
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
