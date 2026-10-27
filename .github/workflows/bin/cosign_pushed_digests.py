#!/usr/bin/env python3
# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Print the image reference, by digest, of every spec image in an OCI build cache, one per line.

This hashes the manifest the registry returns, which is what Spack verifies when installing.

Usage: spack python cosign_pushed_digests.py URL
"""

import hashlib
import sys
import urllib.request

import spack.binary_distribution as bd
import spack.oci.image
import spack.oci.oci
import spack.oci.opener


def main(url: str) -> int:
    image = spack.oci.image.ImageReference.from_url(url)
    refs = []
    for tag in spack.oci.oci.list_tags(image):
        if not bd.tag_is_spec(tag):
            continue
        request = urllib.request.Request(
            url=image.with_tag(tag).manifest_url(),
            headers={"Accept": ", ".join(spack.oci.oci.manifest_content_type)},
        )
        with spack.oci.opener.urlopen(request) as response:
            digest = hashlib.sha256(response.read()).hexdigest()
        refs.append(f"{image.domain}/{image.name}@sha256:{digest}")
    if not refs:
        print("no spec images found", file=sys.stderr)
        return 1
    print("\n".join(refs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
