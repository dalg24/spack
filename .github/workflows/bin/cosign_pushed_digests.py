#!/usr/bin/env python3
# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Print the image reference, by digest, of the images pushed for installed specs, one per line.

Only the specs given, and their dependencies, are looked at, and not everything in the registry:
it can hold images from earlier runs, which this job did not push and cannot sign.

This hashes the manifest the registry returns, which is what Spack verifies when installing.

Usage: spack python cosign_pushed_digests.py URL SPEC...
"""

import hashlib
import sys
import urllib.request

import spack.binary_distribution as bd
import spack.oci.image
import spack.oci.opener
import spack.store
import spack.traverse


def main(url: str, spec_strings: list) -> int:
    image = spack.oci.image.ImageReference.from_url(url)

    roots = []
    for string in spec_strings:
        roots.extend(spack.store.STORE.db.query(string))
    if not roots:
        print(f"no installed spec matches {spec_strings}", file=sys.stderr)
        return 1

    # What `spack buildcache push` pushes: the specs and all of their dependencies
    specs = list(spack.traverse.traverse_nodes(roots, order="topo", root=True))
    refs = []
    for spec in specs:
        if spec.external:
            continue
        tag = bd._oci_default_tag(spec)
        request = urllib.request.Request(
            url=image.with_tag(tag).manifest_url(),
            headers={"Accept": ", ".join(spack.oci.oci.manifest_content_type)},
        )
        with spack.oci.opener.urlopen(request) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        refs.append(f"{image.domain}/{image.name}@sha256:{digest}")
        print(f"{spec.format('{name}@{version}/{hash:7}')} -> {refs[-1]}", file=sys.stderr)
    print("\n".join(refs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
