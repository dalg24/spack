#!/usr/bin/env python3
# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
"""Write a mirrors.yaml for the cosign-oci-keyless workflow, to the user config scope.

Usage: spack python cosign_mirror_config.py URL ISSUER
           (--identity IDENTITY | --identity-regexp PATTERN)
"""

import argparse
import os
import sys

import spack.util.spack_yaml as syaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("issuer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--identity")
    group.add_argument("--identity-regexp")
    args = parser.parse_args()

    signed = {"method": "cosign", "issuer": args.issuer}
    if args.identity:
        signed["identity"] = args.identity
    else:
        signed["identity_regexp"] = args.identity_regexp

    config = {
        "mirrors": {
            "test-cache": {
                "url": args.url,
                "signed": signed,
                # Credentials are read from the environment, and never written to a file
                "access_pair": {
                    "id_variable": "REGISTRY_USER",
                    "secret_variable": "REGISTRY_TOKEN",
                },
            }
        }
    }
    path = os.path.join(os.environ["SPACK_USER_CONFIG_PATH"], "mirrors.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        syaml.dump(config, f, default_flow_style=False)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
