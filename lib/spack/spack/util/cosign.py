# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Thin wrapper around the ``cosign`` executable, used to sign and verify OCI images with a
key. Neither signing nor verification contacts any Sigstore service, so this works on machines
without access to the public internet. Cosign 3 or newer is required."""

import base64
import contextlib
import getpass
import json
import os
import re
import sys
import tempfile
from typing import Dict, Iterator, List, Optional

import spack.error
import spack.util.executable
from spack.util.executable import Executable

#: Executable instance for "cosign", initialized lazily
_COSIGN: Optional[Executable] = None

#: Password of the private key, if it was asked for. It is only handed to the cosign process.
_PASSWORD: Optional[str] = None

#: Major version of the cosign executable, determined on first use
_COSIGN_MAJOR: Optional[int] = None

#: The oldest major version of cosign that is supported
MIN_COSIGN_MAJOR = 3

#: A signing config without any Fulcio, Rekor or timestamp authority service. Cosign would
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


def _check_version() -> None:
    """Raise unless the cosign executable is recent enough."""
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
    if _COSIGN_MAJOR < MIN_COSIGN_MAJOR:
        raise CosignError(
            f"cosign {_COSIGN_MAJOR} is not supported, use cosign {MIN_COSIGN_MAJOR} or newer"
        )


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


@contextlib.contextmanager
def _registry_login(ref: str) -> Iterator[Optional[Dict[str, str]]]:
    """Give cosign the credentials of the mirror for the registry of an image.

    Cosign only reads credentials from a Docker config file, and has no environment variable
    for them. Passing them as options would show them in the process list and in error messages.
    They are written to a private file that exists only while cosign runs, and cosign is
    pointed to it with ``DOCKER_CONFIG``.

    Yields:
        the environment variables to run cosign with, or None if no mirror has credentials for
        the registry
    """
    import spack.oci.opener

    domain = ref.split("/", 1)[0]
    credentials = spack.oci.opener.credentials_from_mirrors(domain)
    if not credentials:
        yield None
        return

    with tempfile.TemporaryDirectory(prefix="spack-cosign-") as directory:
        # TemporaryDirectory creates it with permissions for the user only
        path = os.path.join(directory, "config.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        auth = base64.b64encode(f"{credentials.username}:{credentials.password}".encode())
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"auths": {domain: {"auth": auth.decode()}}}, f)
        yield {"DOCKER_CONFIG": directory}


def _extra_env(*envs: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    merged: Dict[str, str] = {}
    for env in envs:
        merged.update(env or {})
    return merged or None


def _run_on_image(ref: str, *args: str, env: Optional[Dict[str, str]] = None) -> None:
    """Run cosign on an image, logged in to its registry with the credentials of the mirror.

    Every use of cosign that talks to the registry goes through here, so that none can forget
    the login. Raises ProcessError, like the executable."""
    with _registry_login(ref) as login:
        _cosign()(*args, output=str, error=str, extra_env=_extra_env(login, env))


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
    _check_version()

    with tempfile.TemporaryDirectory() as tmpdir:
        config = os.path.join(tmpdir, "signing-config.json")
        with open(config, "w", encoding="utf-8") as f:
            json.dump(_OFFLINE_SIGNING_CONFIG, f)
        try:
            _run_on_image(
                ref,
                "sign",
                "--key",
                key,
                "--yes",
                "--signing-config",
                config,
                *_registry_args(insecure_registry),
                ref,
                env=(
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
    _check_version()
    try:
        _run_on_image(
            ref,
            "verify",
            "--key",
            key,
            "--insecure-ignore-tlog",
            *_registry_args(insecure_registry),
            ref,
        )
    except spack.util.executable.ProcessError as e:
        raise CosignError(f"cosign could not verify {ref}: {e}") from e


def _require_digest(ref: str) -> None:
    if "@sha256:" not in ref:
        raise CosignError(f"cosign operations require a digest reference, got '{ref}'")


def _anchored(regexp: str) -> str:
    """Make cosign match the whole identity. It otherwise matches anywhere in it, so that
    ``github.com/org/repo`` also matches ``github.com/org/repo-evil``."""
    if regexp in ("", ".*", ".+", "^.*$", "^.+$", "^.*", ".*$"):
        raise CosignError(f"the identity pattern '{regexp}' matches every signer")
    return f"^(?:{regexp.removeprefix('^').removesuffix('$')})$"


def verify_image_keyless(
    ref: str,
    *,
    issuer: str,
    identity: Optional[str] = None,
    identity_regexp: Optional[str] = None,
    trusted_root: Optional[str] = None,
    insecure_registry: bool = False,
) -> None:
    """Verify that an image was signed by a given identity, with a certificate that Sigstore
    issued to it.

    Unlike verifying with a key, this needs a trusted record of *when* the image was signed,
    since such certificates are only valid for minutes. Cosign gets it from the Sigstore
    transparency log, which needs access to the network, and it cannot be skipped.

    Args:
        ref: image reference *by digest*
        issuer: the OIDC issuer that vouched for the identity
        identity: the exact identity that signed, such as the URL of a CI workflow
        identity_regexp: a regular expression that must match the whole identity, instead of
            ``identity``
        trusted_root: a Sigstore trusted root file, for private Sigstore deployments

    Raises:
        CosignError: if there is no signature, or it was not made by this identity
    """
    _require_digest(ref)
    if bool(identity) == bool(identity_regexp):
        raise CosignError("specify exactly one of an identity and an identity pattern")
    if not issuer:
        raise CosignError("the OIDC issuer of the signer is required to verify its identity")
    _check_version()

    identity_args = (
        ["--certificate-identity", identity]
        if identity
        else ["--certificate-identity-regexp", _anchored(identity_regexp or "")]
    )
    root_args = ["--trusted-root", trusted_root] if trusted_root else []
    try:
        _run_on_image(
            ref,
            "verify",
            *identity_args,
            "--certificate-oidc-issuer",
            issuer,
            *root_args,
            *_registry_args(insecure_registry),
            ref,
        )
    except spack.util.executable.ProcessError as e:
        raise CosignError(
            f"cosign could not verify that {ref} was signed by the expected identity: {e}"
        ) from e


def sign_image_keyless(ref: str, insecure_registry: bool = False) -> None:
    """Sign an image with a short-lived certificate that Sigstore issues to the identity the CI
    job runs as, which cosign finds in the environment of the job.

    This contacts Sigstore, so it needs access to the network, and a CI job with permission to
    request an identity token.

    Args:
        ref: image reference *by digest*
        insecure_registry: the registry speaks plain http

    Raises:
        CosignError: if signing fails, in particular when there is no identity to sign as
    """
    _require_digest(ref)
    _check_version()
    try:
        _run_on_image(
            ref,
            "sign",
            "--yes",
            # Only use a token from the environment of the job. Cosign would otherwise fall back
            # to logging in interactively, which cannot be seen while its output is captured.
            "--fulcio-auth-flow=token",
            *_registry_args(insecure_registry),
            ref,
        )
    except spack.util.executable.ProcessError as e:
        raise CosignError(
            f"cosign failed to sign {ref} without a key: {e}\n"
            "Keyless signing needs a CI job that can request an identity token, and access to "
            "the Sigstore services."
        ) from e


class KeylessSigner:
    """Signs images without a key, and checks the signature is from the identity expected by
    clients, so that a job running as the wrong identity fails instead of publishing images that
    no one will install."""

    def __init__(
        self,
        issuer: str,
        identity: Optional[str] = None,
        identity_regexp: Optional[str] = None,
        trusted_root: Optional[str] = None,
    ):
        if bool(identity) == bool(identity_regexp):
            raise CosignError("specify exactly one of an identity and an identity pattern")
        self.issuer = issuer
        self.identity = identity
        self.identity_regexp = identity_regexp
        self.trusted_root = trusted_root

    def is_signed(self, ref: str, insecure_registry: bool = False) -> bool:
        """Whether the image is already signed by the identity that clients expect."""
        try:
            verify_image_keyless(
                ref,
                issuer=self.issuer,
                identity=self.identity,
                identity_regexp=self.identity_regexp,
                trusted_root=self.trusted_root,
                insecure_registry=insecure_registry,
            )
        except CosignError:
            return False
        return True

    def sign(self, ref: str, insecure_registry: bool = False) -> None:
        sign_image_keyless(ref, insecure_registry)
        try:
            verify_image_keyless(
                ref,
                issuer=self.issuer,
                identity=self.identity,
                identity_regexp=self.identity_regexp,
                trusted_root=self.trusted_root,
                insecure_registry=insecure_registry,
            )
        except CosignError as e:
            raise CosignError(
                f"{ref} was signed, but not by the identity that the mirror is configured to "
                f"trust, so clients would refuse it. Check which identity this job runs as: {e}"
            ) from e
