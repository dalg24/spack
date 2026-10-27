#!/usr/bin/env bash
# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
#
# Usage: cosign_expect_refused.sh SPEC MESSAGE
#
# Succeed only if installing SPEC from the build cache was refused because its signature does not
# verify, so that a network error or a missing image cannot make a test pass by accident.
set -u

spec="$1"
message="$2"

if spack buildcache install "$spec" > install.log 2>&1; then
    cat install.log
    echo "::error::$message"
    exit 1
fi
cat install.log

if ! grep -q "Failed to verify signature for binary package" install.log; then
    echo "::error::the install failed, but not because of the signature"
    exit 1
fi

if spack find "$spec"; then
    echo "::error::$spec is installed"
    exit 1
fi
