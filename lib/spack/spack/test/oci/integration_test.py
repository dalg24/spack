# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

# These are slow integration tests that do concretization, install, tarballing
# and compression. They still use an in-memory OCI registry.

import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
from contextlib import contextmanager

import pytest

import spack.binary_distribution
import spack.config
import spack.database
import spack.deptypes as dt
import spack.environment as ev
import spack.error
import spack.mirrors.mirror
import spack.oci.opener
import spack.spec
import spack.traverse
import spack.util.cosign
import spack.util.executable
from spack.database import Database
from spack.main import SpackCommand
from spack.oci.image import Digest, ImageReference, default_config, default_manifest
from spack.oci.oci import blob_exists, get_manifest_and_config, upload_blob, upload_manifest
from spack.test.oci.mock_registry import DummyServer, InMemoryOCIRegistry, create_opener
from spack.util.archive import gzip_compressed_tarfile

buildcache = SpackCommand("buildcache")
mirror = SpackCommand("mirror")
env = SpackCommand("env")
install = SpackCommand("install")


@contextmanager
def oci_servers(*servers: DummyServer):
    old_opener = spack.oci.opener.urlopen
    spack.oci.opener.urlopen = create_opener(*servers).open
    yield
    spack.oci.opener.urlopen = old_opener


def test_buildcache_push_command(mutable_database: Database):
    with oci_servers(InMemoryOCIRegistry("example.com")):
        mirror("add", "oci-test", "oci://example.com/image")

        # Push the package(s) to the OCI registry
        buildcache("push", "--update-index", "oci-test", "mpileaks^mpich")

        # Remove mpileaks from the database
        matches = mutable_database.query_local("mpileaks^mpich")
        assert len(matches) == 1
        spec = matches[0]
        spec.package.do_uninstall()

        # Reinstall mpileaks from the OCI registry
        buildcache("install", "--unsigned", "mpileaks^mpich")

        # Now it should be installed again
        assert mutable_database.installed(spec)

        # And let's check that the bin/mpileaks executable is there (fake installs create
        # executables with a .exe extension on Windows)
        exe_suffix = ".exe" if sys.platform == "win32" else ""
        assert os.path.exists(os.path.join(spec.prefix, "bin", f"mpileaks{exe_suffix}"))


def test_buildcache_tag(install_mockery, mock_fetch, mutable_mock_env_path):
    """Tests whether we can create an OCI image from a full environment with multiple roots."""
    env("create", "test")
    with ev.read("test"):
        install("--fake", "--add", "libelf")
        install("--fake", "--add", "trivial-install-test-package")

    registry = InMemoryOCIRegistry("example.com")

    with oci_servers(registry):
        mirror("add", "oci-test", "oci://example.com/image")

        with ev.read("test"):
            buildcache("push", "--tag", "full_env", "oci-test")

        name = ImageReference.from_string("example.com/image:full_env")

        with ev.read("test") as e:
            specs = [
                x
                for x in spack.traverse.traverse_nodes(
                    e.concrete_roots(), deptype=dt.LINK | dt.RUN
                )
                if not x.external
            ]

        manifest, config = get_manifest_and_config(name)

        # without a base image, we should have one layer per spec
        assert len(manifest["layers"]) == len(specs)

        # Now create yet another tag, but with just a single selected spec as root. This should
        # also test the case where Spack doesn't have to upload any binaries, it just has to create
        # a new tag.
        libelf = next(s for s in specs if s.name == "libelf")
        with ev.read("test"):
            # Get libelf spec
            buildcache("push", "--tag", "single_spec", "oci-test", libelf.format("libelf{/hash}"))

        name = ImageReference.from_string("example.com/image:single_spec")
        manifest, config = get_manifest_and_config(name)
        assert len(manifest["layers"]) == len(
            [x for x in libelf.traverse(deptype=dt.LINK | dt.RUN) if not x.external]
        )


def test_buildcache_push_with_base_image_command(mutable_database, tmp_path: pathlib.Path):
    """Test that we can push a package with a base image to an OCI registry.

    This test is a bit involved, cause we have to create a small base image."""

    registry_src = InMemoryOCIRegistry("src.example.com")
    registry_dst = InMemoryOCIRegistry("dst.example.com")

    base_image = ImageReference.from_string("src.example.com/my-base-image:latest")

    with oci_servers(registry_src, registry_dst):
        mirror("add", "oci-test", "oci://dst.example.com/image")

        # TODO: simplify creation of images...
        # We create a rootfs.tar.gz, a config file and a manifest file,
        # and upload those.

        config, manifest = default_config(architecture="amd64", os="linux"), default_manifest()

        # Create a small rootfs
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        (rootfs / "bin").mkdir()
        (rootfs / "bin" / "sh").touch()

        # Create a tarball of it.
        tarball = tmp_path / "base.tar.gz"
        with gzip_compressed_tarfile(str(tarball)) as (tar, tar_gz_checksum, tar_checksum):
            tar.add(str(rootfs), arcname=".")

        tar_gz_digest = Digest.from_sha256(tar_gz_checksum.hexdigest())
        tar_digest = Digest.from_sha256(tar_checksum.hexdigest())

        # Save the config file
        config["rootfs"]["diff_ids"] = [str(tar_digest)]
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        config_digest = Digest.from_sha256(hashlib.sha256(config_file.read_bytes()).hexdigest())

        # Register the layer in the manifest
        manifest["layers"].append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": str(tar_gz_digest),
                "size": tarball.stat().st_size,
            }
        )
        manifest["config"]["digest"] = str(config_digest)
        manifest["config"]["size"] = config_file.stat().st_size

        # Upload the layer and config file
        upload_blob(base_image, str(tarball), tar_gz_digest)
        upload_blob(base_image, str(config_file), config_digest)

        # Upload the manifest
        upload_manifest(base_image, manifest)

        # END TODO

        # Finally... use it as a base image
        buildcache("push", "--base-image", str(base_image), "oci-test", "mpileaks^mpich")

        # Figure out what tag was produced
        tag = next(tag for _, tag in registry_dst.manifests.keys() if tag.startswith("mpileaks-"))
        assert tag is not None

        # Fetch the manifest and config
        dst_image = ImageReference.from_string(f"dst.example.com/image:{tag}")
        retrieved_manifest, retrieved_config = get_manifest_and_config(dst_image)

        # Check that the media type is OCI
        assert retrieved_manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
        assert (
            retrieved_manifest["config"]["mediaType"] == "application/vnd.oci.image.config.v1+json"
        )

        # Check that the base image layer is first.
        assert retrieved_manifest["layers"][0]["digest"] == str(tar_gz_digest)
        assert retrieved_config["rootfs"]["diff_ids"][0] == str(tar_digest)

        # And also check that we have layers for each link-run dependency
        matches = mutable_database.query_local("mpileaks^mpich")
        assert len(matches) == 1
        spec = matches[0]

        num_runtime_deps = len(list(spec.traverse(root=True, deptype=("link", "run"))))

        # One base layer + num_runtime_deps
        assert len(retrieved_manifest["layers"]) == 1 + num_runtime_deps

        # And verify that all layers including the base layer are present
        for layer in retrieved_manifest["layers"]:
            assert blob_exists(dst_image, digest=Digest.from_string(layer["digest"]))
            assert layer["mediaType"] == "application/vnd.oci.image.layer.v1.tar+gzip"


def test_uploading_with_base_image_in_docker_image_manifest_v2_format(
    tmp_path: pathlib.Path, mutable_database
):
    """If the base image uses an old manifest schema, Spack should also use that.
    That is necessary for container images to work with Apptainer, which is rather strict about
    mismatching manifest/layer types."""

    registry_src = InMemoryOCIRegistry("src.example.com")
    registry_dst = InMemoryOCIRegistry("dst.example.com")

    base_image = ImageReference.from_string("src.example.com/my-base-image:latest")

    with oci_servers(registry_src, registry_dst):
        mirror("add", "oci-test", "oci://dst.example.com/image")

        # Create a dummy base image (blob, config, manifest) in registry A in the Docker Image
        # Manifest V2 format.
        rootfs = tmp_path / "rootfs"
        (rootfs / "bin").mkdir(parents=True)
        (rootfs / "bin" / "sh").write_text("hello world")
        tarball = tmp_path / "base.tar.gz"
        with gzip_compressed_tarfile(str(tarball)) as (tar, tar_gz_checksum, tar_checksum):
            tar.add(rootfs, arcname=".")
        tar_gz_digest = Digest.from_sha256(tar_gz_checksum.hexdigest())
        tar_digest = Digest.from_sha256(tar_checksum.hexdigest())
        upload_blob(base_image, str(tarball), tar_gz_digest)
        config = {
            "created": "2015-10-31T22:22:56.015925234Z",
            "author": "Foo <example@example.com>",
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "foo",
                "Memory": 2048,
                "MemorySwap": 4096,
                "CpuShares": 8,
                "ExposedPorts": {"8080/tcp": {}},
                "Env": ["PATH=/usr/bin:/bin"],
                "Entrypoint": ["/bin/sh"],
                "Cmd": ["-c", "'echo hello world'"],
                "Volumes": {"/x": {}},
                "WorkingDir": "/",
            },
            "rootfs": {"diff_ids": [str(tar_digest)], "type": "layers"},
            "history": [
                {
                    "created": "2015-10-31T22:22:54.690851953Z",
                    "created_by": "/bin/sh -c #(nop) ADD file:a3bc1e842b69636f9df5256c49c5374fb4eef1e281fe3f282c65fb853ee171c5 in /",  # noqa: E501
                }
            ],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        config_digest = Digest.from_sha256(hashlib.sha256(config_file.read_bytes()).hexdigest())
        upload_blob(base_image, str(config_file), config_digest)
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": config_file.stat().st_size,
                "digest": str(config_digest),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": tarball.stat().st_size,
                    "digest": str(tar_gz_digest),
                }
            ],
        }
        upload_manifest(base_image, manifest)

        # Finally upload some package to registry B with registry A's image as base
        buildcache("push", "--base-image", str(base_image), "oci-test", "mpileaks^mpich")

    # Should have some manifests uploaded to registry B now.
    assert registry_dst.manifests

    # Verify that all manifest are in the Docker Image Manifest V2 format, not OCI.
    # And also check that we're not using annotations, which is an OCI-only "feature".
    for m in registry_dst.manifests.values():
        assert m["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json"
        assert m["config"]["mediaType"] == "application/vnd.docker.container.image.v1+json"
        for layer in m["layers"]:
            assert layer["mediaType"] == "application/vnd.docker.image.rootfs.diff.tar.gzip"
        assert "annotations" not in m


def test_best_effort_upload(mutable_database: spack.database.Database, monkeypatch):
    """Failure to upload a blob or manifest should not prevent others from being uploaded -- it
    should be a best-effort operation. If any runtime dep fails to upload, it results in a missing
    layer for dependents. But we do still create manifests for dependents, so that the build cache
    is maximally useful. (The downside is that container images are not runnable)."""

    _push_blob = spack.binary_distribution._oci_push_pkg_blob
    _push_manifest = spack.binary_distribution._oci_put_manifest

    def push_blob(image_ref, spec, tmpdir):
        # fail to upload the blob of mpich
        if spec.name == "mpich":
            raise Exception("Blob Server Error")
        return _push_blob(image_ref, spec, tmpdir)

    def put_manifest(
        base_images, checksums, image_ref, tmpdir, extra_config, annotations, *specs, **kwargs
    ):
        # fail to upload the manifest of libdwarf
        if "libdwarf" in (s.name for s in specs):
            raise Exception("Manifest Server Error")
        return _push_manifest(
            base_images, checksums, image_ref, tmpdir, extra_config, annotations, *specs, **kwargs
        )

    monkeypatch.setattr(spack.binary_distribution, "_oci_push_pkg_blob", push_blob)
    monkeypatch.setattr(spack.binary_distribution, "_oci_put_manifest", put_manifest)

    mirror("add", "oci-test", "oci://example.com/image")
    registry = InMemoryOCIRegistry("example.com")
    image = ImageReference.from_string("example.com/image")

    with oci_servers(registry):
        with pytest.raises(spack.error.SpackError, match="The following 2 errors occurred") as e:
            buildcache("push", "--update-index", "oci-test", "mpileaks^mpich")

            # mpich's blob failed to upload and libdwarf's manifest failed to upload
            assert re.search("mpich.+: Exception: Blob Server Error", e.value)
            assert re.search("libdwarf.+: Exception: Manifest Server Error", e.value)

        mpileaks: spack.spec.Spec = mutable_database.query_local("mpileaks^mpich")[0]

        without_manifest = ("mpich", "libdwarf")

        # Verify that manifests of mpich/libdwarf are missing due to upload failure.
        for name in without_manifest:
            tagged_img = image.with_tag(spack.binary_distribution._oci_default_tag(mpileaks[name]))
            with pytest.raises(urllib.error.HTTPError, match="404"):
                get_manifest_and_config(tagged_img)

        # Collect the layer digests of successfully uploaded packages. Every package should refer
        # to its own tarballs and those of its runtime deps that were uploaded.
        pkg_to_all_digests = {}
        pkg_to_own_digest = {}
        for s in mpileaks.traverse():
            if s.name in without_manifest:
                continue

            if s.external:
                continue

            # This should not raise a 404.
            manifest, _ = get_manifest_and_config(
                image.with_tag(spack.binary_distribution._oci_default_tag(s))
            )

            # Collect layer digests
            pkg_to_all_digests[s.name] = {layer["digest"] for layer in manifest["layers"]}
            pkg_to_own_digest[s.name] = manifest["layers"][-1]["digest"]

        # Verify that all packages reference blobs of their runtime deps that uploaded fine.
        for s in mpileaks.traverse():
            if s.name in without_manifest:
                continue

            if s.external:
                continue

            expected_digests = {
                pkg_to_own_digest[t.name]
                for t in s.traverse(deptype=("link", "run"), root=True)
                if t.name not in without_manifest
            }

            # Test with issubset, cause we don't have the blob of libdwarf as it has no manifest.
            assert expected_digests and expected_digests.issubset(pkg_to_all_digests[s.name])


class _RecordingCosign:
    def __init__(self, reject_verify: bool = False):
        self.signed = []
        self.verified = []
        self.reject_verify = reject_verify

    def __call__(self, *args, **kwargs):
        if args[0] == "version":
            return "GitVersion:    v3.1.4\n"
        if args[0] == "sign":
            self.signed.append(args[-1])
        elif args[0] == "verify":
            self.verified.append(args[-1])
            if self.reject_verify:
                raise spack.util.executable.ProcessError("no matching signatures")


@pytest.fixture
def recording_cosign(monkeypatch):
    fake = _RecordingCosign()
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", fake)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    return fake


def test_buildcache_push_signs_manifest_digests(mutable_database, recording_cosign):
    """Every pushed spec image is signed by digest, using the key from the mirror config."""
    registry = InMemoryOCIRegistry("example.com")
    with oci_servers(registry):
        spack.config.CONFIG.set(
            "mirrors:oci-test",
            {
                "url": "oci://example.com/image",
                "signed": {"method": "cosign", "key": "cosign.key"},
            },
            scope="user",
        )
        buildcache("push", "oci-test", "mpileaks^mpich")

    # One signature per pushed spec image (tagged `*.spack`)
    spec_tags = [tag for (_, tag) in registry.manifests if tag.endswith(".spack")]
    assert len(spec_tags) > 1
    assert len(recording_cosign.signed) == len(spec_tags)

    # The signed references are the digests of the manifests that were pushed, as opposed to
    # tags, which may be moved after signing
    expected = {
        "sha256:" + hashlib.sha256(json.dumps(m, separators=(",", ":")).encode()).hexdigest()
        for (_, tag), m in registry.manifests.items()
        if tag.endswith(".spack")
    }
    signed = {ref.split("@")[1] for ref in recording_cosign.signed}
    assert signed == expected
    assert all(ref.startswith("example.com/image@sha256:") for ref in recording_cosign.signed)


def test_buildcache_push_cosign_key_override(mutable_database, recording_cosign):
    with oci_servers(InMemoryOCIRegistry("example.com")):
        mirror("add", "oci-test", "oci://example.com/image")
        buildcache("push", "--key", "other.key", "oci-test", "mpich")
    assert recording_cosign.signed


def test_buildcache_push_signed_oci_without_key_fails(mutable_database, recording_cosign):
    """Requesting a signed push to an OCI mirror without a cosign key must not silently
    downgrade to an unsigned push."""
    with oci_servers(InMemoryOCIRegistry("example.com")):
        mirror("add", "oci-test", "oci://example.com/image")
        with pytest.raises(spack.error.SpackError, match="requires a cosign key"):
            buildcache("push", "--signed", "oci-test", "mpich")
    assert not recording_cosign.signed


def test_buildcache_push_unsigned_oci_does_not_sign(mutable_database, recording_cosign):
    with oci_servers(InMemoryOCIRegistry("example.com")):
        mirror("add", "oci-test", "oci://example.com/image")
        buildcache("push", "oci-test", "mpich")
    assert not recording_cosign.signed


def test_buildcache_push_cosign_failure_fails_push(mutable_database, monkeypatch):
    class Failing:
        def __call__(self, *args, **kwargs):
            if args[0] == "version":
                return "GitVersion:    v3.1.4\n"
            raise spack.util.executable.ProcessError("signing failed")

    monkeypatch.setattr(spack.util.cosign, "_COSIGN", Failing())
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(InMemoryOCIRegistry("example.com")):
        mirror("add", "oci-test", "oci://example.com/image")
        with pytest.raises(spack.error.SpackError, match="signing failed"):
            buildcache("push", "--key", "cosign.key", "oci-test", "mpich")


def _cosign_mirror(name: str = "oci-test"):
    spack.config.CONFIG.set(
        f"mirrors:{name}",
        {"url": "oci://example.com/image", "signed": {"method": "cosign", "key": "cosign.pub"}},
        scope="user",
    )


def _push_and_uninstall(mutable_database, spec_str: str = "mpich"):
    buildcache("push", "--update-index", "oci-test", spec_str)
    spec = mutable_database.query_local(spec_str)[0]
    spec.package.do_uninstall(force=True)
    return spec


def test_buildcache_install_verifies_manifest_digest(mutable_database, recording_cosign):
    """Install verifies the digest of the manifest it got from the registry, before using it."""
    registry = InMemoryOCIRegistry("example.com")
    with oci_servers(registry):
        _cosign_mirror()
        spec = _push_and_uninstall(mutable_database)
        buildcache("install", "mpich")

        assert mutable_database.installed(spec)
        raw = registry.raw_manifests[("image", spack.binary_distribution._oci_default_tag(spec))]
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        assert f"example.com/image@{digest}" in recording_cosign.verified


def test_buildcache_install_rejects_bad_signature(mutable_database, monkeypatch):
    """A binary whose signature does not verify is not installed."""
    registry = InMemoryOCIRegistry("example.com")
    signer = _RecordingCosign()
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", signer)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(registry):
        _cosign_mirror()
        spec = _push_and_uninstall(mutable_database)

        signer.reject_verify = True
        with pytest.raises(RuntimeError, match="download of binary cache file"):
            buildcache("install", "mpich")

        assert signer.verified
        assert not mutable_database.installed(spec)


def test_buildcache_install_unsigned_skips_verification(mutable_database, recording_cosign):
    with oci_servers(InMemoryOCIRegistry("example.com")):
        _cosign_mirror()
        spec = _push_and_uninstall(mutable_database)
        buildcache("install", "--unsigned", "mpich")

        assert mutable_database.installed(spec)
        assert not recording_cosign.verified


def test_buildcache_install_oci_without_cosign_config_does_not_verify(
    mutable_database, recording_cosign
):
    """OCI mirrors that don't configure cosign keep working as before."""
    with oci_servers(InMemoryOCIRegistry("example.com")):
        mirror("add", "oci-test", "oci://example.com/image")
        spec = _push_and_uninstall(mutable_database)
        buildcache("install", "mpich")

        assert mutable_database.installed(spec)
        assert not recording_cosign.verified


class _DigestBoundCosign(_RecordingCosign):
    """Accepts a signature only for the exact digest that was signed, like real cosign."""

    def __call__(self, *args, **kwargs):
        result = super().__call__(*args, **kwargs)
        if args[0] == "verify" and args[-1] not in self.signed:
            raise spack.util.executable.ProcessError("no matching signatures")
        return result


def test_buildcache_install_rejects_manifest_changed_after_signing(mutable_database, monkeypatch):
    """If the manifest served for a tag is not the one that was signed, it is not installed."""
    registry = InMemoryOCIRegistry("example.com")
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", _DigestBoundCosign())
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(registry):
        _cosign_mirror()
        spec = _push_and_uninstall(mutable_database)

        # Someone with write access to the registry re-points the tag to a different manifest
        key = ("image", spack.binary_distribution._oci_default_tag(spec))
        tampered = dict(registry.manifests[key])
        tampered["annotations"] = {"tampered": "yes"}
        registry.manifests[key] = tampered
        registry.raw_manifests[key] = json.dumps(tampered, separators=(",", ":")).encode()

        with pytest.raises(RuntimeError, match="download of binary cache file"):
            buildcache("install", "mpich")
        assert not mutable_database.installed(spec)


_ISSUER = "https://token.actions.githubusercontent.com"
_IDENTITY = "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"


def _keyless_mirror(name: str = "oci-test", **signed):
    spack.config.CONFIG.set(
        f"mirrors:{name}",
        {"url": "oci://example.com/image", "signed": {"method": "cosign", **signed}},
        scope="user",
    )


class _KeylessCosign(_RecordingCosign):
    """Accepts a signature only if the verification asks for the identity that signed."""

    def __init__(self, signer: str = _IDENTITY):
        super().__init__()
        self.signer = signer
        self.verify_calls = []

    def __call__(self, *args, **kwargs):
        if args[0] == "version":
            return "GitVersion:    v3.1.4\n"
        if args[0] == "sign":
            self.signed.append(args[-1])
        elif args[0] == "verify":
            self.verify_calls.append(args)
            asked = args[args.index("--certificate-identity") + 1]
            if asked != self.signer:
                raise spack.util.executable.ProcessError("no matching signatures")


def _push_with_key_then_uninstall(mutable_database):
    """Push signed with a key, so the registry has something to install, and uninstall it."""
    spack.config.CONFIG.set(
        "mirrors:oci-test",
        {"url": "oci://example.com/image", "signed": {"method": "cosign", "key": "cosign.key"}},
        scope="user",
    )
    buildcache("push", "--update-index", "oci-test", "mpich")
    spec = mutable_database.query_local("mpich")[0]
    spec.package.do_uninstall(force=True)
    return spec


def test_buildcache_install_keyless_checks_the_identity(mutable_database, monkeypatch):
    cosign = _KeylessCosign()
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", cosign)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(InMemoryOCIRegistry("example.com")):
        spec = _push_with_key_then_uninstall(mutable_database)
        _keyless_mirror(identity=_IDENTITY, issuer=_ISSUER)
        buildcache("install", "mpich")

    assert mutable_database.installed(spec)
    (call,) = cosign.verify_calls
    assert call[call.index("--certificate-oidc-issuer") + 1] == _ISSUER
    assert "--key" not in call and "--insecure-ignore-tlog" not in call


def test_buildcache_install_keyless_rejects_another_signer(mutable_database, monkeypatch):
    monkeypatch.setattr(
        spack.util.cosign, "_COSIGN", _KeylessCosign(signer="https://github.com/evil/repo")
    )
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(InMemoryOCIRegistry("example.com")):
        spec = _push_with_key_then_uninstall(mutable_database)
        _keyless_mirror(identity=_IDENTITY, issuer=_ISSUER)
        with pytest.raises(RuntimeError, match="download of binary cache file"):
            buildcache("install", "mpich")

    assert not mutable_database.installed(spec)


def test_install_without_a_pinned_signer_is_refused(recording_cosign):
    """A mirror that requires signatures but does not say whose must never accept any signature.
    The schema rejects such a config, so this is a safety net for mirrors built in code."""
    mirror_obj = spack.mirrors.mirror.Mirror(
        {"url": "oci://example.com/image", "signed": {"method": "cosign"}}, name="oci-test"
    )
    with pytest.raises(spack.util.cosign.CosignError, match="not configured with a key"):
        spack.binary_distribution._oci_verify_signature(
            mirror_obj,
            "example.com/image@sha256:" + "a" * 64,
            ImageReference.from_string("example.com/image"),
        )
    assert not recording_cosign.verified


class _FakeKeylessSigning(_KeylessCosign):
    """Signs as ``signer``, as cosign does with the identity token of the CI job."""

    def __init__(self, signer: str, no_token: bool = False):
        super().__init__(signer=signer)
        self.no_token = no_token
        self.sign_calls = []

    def __call__(self, *args, **kwargs):
        if args[0] == "sign":
            self.sign_calls.append(args)
            if self.no_token:
                raise spack.util.executable.ProcessError("retrieving ID token: empty input")
        return super().__call__(*args, **kwargs)


def test_buildcache_push_keyless_signs_and_checks_the_identity(mutable_database, monkeypatch):
    cosign = _FakeKeylessSigning(signer=_IDENTITY)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", cosign)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    registry = InMemoryOCIRegistry("example.com")
    with oci_servers(registry):
        _keyless_mirror(identity=_IDENTITY, issuer=_ISSUER)
        buildcache("push", "oci-test", "mpich")

    # Every spec image was signed without a key, and checked against the configured identity
    spec_tags = [tag for (_, tag) in registry.manifests if tag.endswith(".spack")]
    assert spec_tags and len(cosign.sign_calls) == len(spec_tags)
    for call in cosign.sign_calls:
        assert "--key" not in call
        assert "--fulcio-auth-flow=token" in call  # never an interactive login
        assert call[-1].startswith("example.com/image@sha256:")
    assert len(cosign.verify_calls) == len(spec_tags)


def test_buildcache_push_keyless_as_another_identity_fails(mutable_database, monkeypatch):
    """A job that runs as a different identity than the mirror trusts would publish images that
    every client refuses. It must fail instead."""
    cosign = _FakeKeylessSigning(signer="https://github.com/other/repo/.github/workflows/x.yml@r")
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", cosign)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(InMemoryOCIRegistry("example.com")):
        _keyless_mirror(identity=_IDENTITY, issuer=_ISSUER)
        with pytest.raises(spack.error.SpackError, match="not by the identity"):
            buildcache("push", "oci-test", "mpich")


def test_buildcache_push_keyless_without_identity_token_fails(mutable_database, monkeypatch):
    cosign = _FakeKeylessSigning(signer=_IDENTITY, no_token=True)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN", cosign)
    monkeypatch.setattr(spack.util.cosign, "_COSIGN_MAJOR", None)
    with oci_servers(InMemoryOCIRegistry("example.com")):
        _keyless_mirror(identity=_IDENTITY, issuer=_ISSUER)
        with pytest.raises(spack.error.SpackError, match="allowed to request an identity token"):
            buildcache("push", "oci-test", "mpich")
