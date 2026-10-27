# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

"""Schema for mirrors.yaml configuration file.

.. literalinclude:: _spack_root/lib/spack/spack/schema/mirrors.py
   :lines: 13-
"""

from typing import Any, Dict

#: Properties that can be set at mirror-level and overridden for fetch/push directions
overridable_per_direction = {
    "url": {
        "type": "string",
        "description": "URL pointing to the mirror directory, can be local filesystem "
        "(file://) or remote server (http://, https://, s3://, oci://)",
    },
    "view": {"type": "string"},
    "access_pair": {
        "type": "object",
        "description": "Authentication credentials for accessing private mirrors with ID and "
        "secret pairs",
        "required": ["secret_variable"],
        # Only allow id or id_variable to be set, not both
        "oneOf": [{"required": ["id"]}, {"required": ["id_variable"]}],
        "properties": {
            "id": {
                "type": "string",
                "description": "Static access ID or username for authentication",
            },
            "id_variable": {
                "type": "string",
                "description": "Environment variable name containing the access ID or username",
            },
            "secret_variable": {
                "type": "string",
                "description": "Environment variable name containing the secret key, password, "
                "or access token",
            },
        },
    },
    "profile": {
        "type": ["string", "null"],
        "description": "AWS profile name to use for S3 mirror authentication",
    },
    "endpoint_url": {
        "type": ["string", "null"],
        "description": "Custom endpoint URL for S3-compatible storage services",
    },
    "access_token_variable": {
        "type": ["string", "null"],
        "description": "Environment variable containing an access token for OCI registry "
        "authentication",
    },
    "include_binary": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of spec patterns to include for this build cache. "
        "If specified, only specs matching at least one pattern will be "
        "pushed or pulled (default: all specs).",
    },
    "exclude_binary": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of spec patterns to exclude from this build cache "
        "(default: exclude nothing).",
    },
}


#: Mirror connection inside fetch/push keys
fetch_and_push = {
    "description": "Mirror connection configuration for fetching or pushing packages, can be a"
    "simple URL string or detailed connection object",
    "anyOf": [
        {
            "type": "string",
            "description": "Simple URL string for basic mirror connections without authentication",
        },
        {
            "type": "object",
            "description": "Detailed connection configuration with authentication and custom "
            "settings",
            "additionalProperties": False,
            "properties": {**overridable_per_direction},
        },
    ],
}

#: Mirror connection when no fetch/push keys are set
mirror_entry = {
    "type": "object",
    "description": "Mirror configuration entry supporting both source package archives and "
    "binary build caches with optional authentication",
    "additionalProperties": False,
    "anyOf": [{"required": ["url"]}, {"required": ["fetch"]}, {"required": ["push"]}],
    "properties": {
        "source": {
            "type": "boolean",
            "description": "Whether this mirror provides source package archives (tarballs) for "
            "building from source",
        },
        "binary": {
            "type": "boolean",
            "description": "Whether this mirror provides binary build caches for installing "
            "precompiled packages",
        },
        "signed": {
            "description": "Whether to require signature verification for packages from this "
            "mirror. A boolean selects GPG signatures (build caches that are not OCI images). "
            "An object selects another signing method.",
            "anyOf": [
                {"type": "boolean"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["method"],
                    "properties": {
                        "method": {
                            "type": "string",
                            "enum": ["cosign"],
                            "description": "Sign and verify OCI images with cosign",
                        },
                        "key": {
                            "type": "string",
                            "description": "Cosign key: path to a private key (used when "
                            "pushing) or public key (used when installing), or a KMS URI",
                        },
                        "identity": {
                            "type": "string",
                            "description": "Keyless signing: the identity, such as the URL of "
                            "a CI workflow, that must have signed the images. Requires issuer",
                        },
                        "identity_regexp": {
                            "type": "string",
                            "description": "Keyless signing: a regular expression that the "
                            "whole identity must match, as an alternative to identity. "
                            "Requires issuer",
                        },
                        "issuer": {
                            "type": "string",
                            "description": "Keyless signing: the OIDC issuer that vouches for "
                            "the identity, such as https://token.actions.githubusercontent.com",
                        },
                        "trusted_root": {
                            "type": "string",
                            "description": "Keyless signing: path to a Sigstore trusted root "
                            "file, for private Sigstore deployments. Defaults to the public "
                            "Sigstore instance",
                        },
                    },
                    "oneOf": [
                        {"required": ["key"], "not": {"required": ["trusted_root"]}},
                        {
                            "required": ["issuer", "identity"],
                            "not": {"required": ["identity_regexp", "key"]},
                        },
                        {
                            "required": ["issuer", "identity_regexp"],
                            "not": {"required": ["identity", "key"]},
                        },
                    ],
                },
            ],
        },
        "fetch": {
            **fetch_and_push,
            "description": "Configuration for fetching/downloading packages from this mirror",
        },
        "push": {
            **fetch_and_push,
            "description": "Configuration for pushing/uploading packages to this mirror for "
            "build cache creation",
        },
        "autopush": {
            "type": "boolean",
            "description": "Automatically push packages to this build cache immediately after "
            "they are installed locally",
        },
        **overridable_per_direction,
    },
}

#: Properties for inclusion in other schemas
properties: Dict[str, Any] = {
    "mirrors": {
        "type": "object",
        "default": {},
        "description": "Configure local and remote mirrors that provide repositories of source "
        "tarballs and binary build caches for faster package installation",
        "additionalProperties": {
            "description": "Named mirror configuration that can be a simple URL string or "
            "detailed mirror entry with authentication and build cache settings",
            "anyOf": [
                {
                    "type": "string",
                    "description": "Simple mirror URL for basic source package or build "
                    "cache access",
                },
                mirror_entry,
            ],
        },
    }
}


#: Full schema with metadata
schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Spack mirror configuration file schema",
    "type": "object",
    "additionalProperties": False,
    "properties": properties,
}
