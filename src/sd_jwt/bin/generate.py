#!/usr/bin/env python3
"""
This utility uses the SD-JWT library to update the static test case data in the
sd_jwt/test_cases directory. It is intended to be run after changes to the
library that affect the test cases.
"""


import argparse
import logging
import sys
from typing import Dict
from pathlib import Path

from sd_jwt import __version__
from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.demo_utils import get_jwk, load_yaml_settings
from sd_jwt.verifier import SDJWTVerifier

from sd_jwt.utils import formatting
from sd_jwt.utils.yaml_specification import (
    load_yaml_specification,
    remove_sdobj_wrappers,
)

logger = logging.getLogger("sd_jwt")

# Set logging to stdout
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def generate_test_case_data(settings: Dict, testcase_path: Path, type: str):
    seed = settings["random_seed"]
    demo_keys = get_jwk(settings["key_settings"], True, seed)

    ### Load test case data
    testcase = load_yaml_specification(testcase_path)
    use_decoys = testcase.get("add_decoy_claims", False)
    serialization_format = testcase.get("serialization_format", "compact")
    include_default_claims = testcase.get("include_default_claims", True)
    extra_header_parameters = testcase.get("extra_header_parameters", {})

    claims = {}
    if include_default_claims:
        claims = {
            "iss": settings["identifiers"]["issuer"],
            "iat": settings["iat"],
            "exp": settings["exp"],
        }

    claims.update(testcase["user_claims"])

    ### Produce SD-JWT and SVC for selected example
    SDJWTIssuer.unsafe_randomness = True
    sdjwt_at_issuer = SDJWTIssuer(
        claims,
        demo_keys["issuer_key"],
        demo_keys["holder_key"] if testcase.get("key_binding", False) else None,
        add_decoy_claims=use_decoys,
        serialization_format=serialization_format,
        extra_header_parameters=extra_header_parameters,
    )

    ### Produce SD-JWT-R for selected example

    sdjwt_at_holder = SDJWTHolder(
        sdjwt_at_issuer.sd_jwt_issuance,
        serialization_format=serialization_format,
    )
    sdjwt_at_holder.create_presentation(
        testcase["holder_disclosed_claims"],
        settings["key_binding_nonce"]
        if testcase.get("key_binding", False)
        else None,
        settings["identifiers"]["verifier"]
        if testcase.get("key_binding", False)
        else None,
        demo_keys["holder_key"] if testcase.get("key_binding", False) else None,
    )

    ### Verify the SD-JWT using the SD-JWT-R

    # Define a function to check the issuer and retrieve the
    # matching public key
    def cb_get_issuer_key(issuer, header_parameters):
        # Do not use in production - this allows to use any issuer name for demo purposes
        if issuer == claims.get("iss", None):
            return demo_keys["issuer_public_key"]
        else:
            raise Exception(f"Unknown issuer: {issuer}")

    sdjwt_at_verifier = SDJWTVerifier(
        sdjwt_at_holder.sd_jwt_presentation,
        cb_get_issuer_key,
        settings["identifiers"]["verifier"]
        if testcase.get("key_binding", False)
        else None,
        settings["key_binding_nonce"]
        if testcase.get("key_binding", False)
        else None,
        serialization_format=serialization_format,
    )
    verified = sdjwt_at_verifier.get_verified_payload()

    # Write the test case data to the directory of the test case

    _artifacts = {
        "user_claims": (
            remove_sdobj_wrappers(testcase["user_claims"]),
            "User Claims",
            "json",
        ),
        "sd_jwt_payload": (
            sdjwt_at_issuer.sd_jwt_payload,
            "Payload of the SD-JWT",
            "json",
        ),
        "sd_jwt_jws_part": (
            sdjwt_at_issuer.serialized_sd_jwt,
            "Serialized SD-JWT",
            "txt" if serialization_format == "compact" else "json",
        ),
        "sd_jwt_issuance": (
            sdjwt_at_issuer.sd_jwt_issuance,
            "Combined SD-JWT and Disclosures",
            "txt" if serialization_format == "compact" else "json",
        ),
        "sd_jwt_presentation": (
            sdjwt_at_holder.sd_jwt_presentation,
            "Combined representation of SD-JWT and HS-Disclosures",
            "txt" if serialization_format == "compact" else "json",
        ),
        "verified_contents": (
            verified,
            "Verified released contents of the SD-JWT",
            "json",
        ),
    }

    if testcase.get("key_binding", False):
        _artifacts.update(
            {
                "kb_jwt_header": (
                    sdjwt_at_holder.key_binding_jwt_header
                    if testcase.get("key_binding")
                    else None,
                    "Header of the Holder Binding JWT",
                    "json",
                ),
                "kb_jwt_payload": (
                    sdjwt_at_holder.key_binding_jwt_payload
                    if testcase.get("key_binding")
                    else None,
                    "Payload of the Holder Binding JWT",
                    "json",
                ),
                "kb_jwt_serialized": (
                    sdjwt_at_holder.serialized_key_binding_jwt,
                    "Serialized Holder Binding JWT",
                    "txt",
                ),
            }
        )

    # When type is example, add info about disclosures
    if type == "example":
        _artifacts["disclosures"] = (
            formatting.markdown_disclosures(
                sdjwt_at_issuer.ii_disclosures,
            ),
            "Payloads of the II-Disclosures",
            "md",
        )

    # When decoys were used, list those as well (here as a json array)
    if use_decoys:
        if type == "example":
            _artifacts.update(
                {
                    "decoy_digests": (
                        formatting.markdown_decoy_digests(
                            sdjwt_at_issuer.decoy_digests
                        ),
                        "Decoy Claims",
                        "md",
                    )
                }
            )
        else:
            _artifacts.update(
                {
                    "decoy_digests": (
                        sdjwt_at_issuer.decoy_digests,
                        "Decoy Claims",
                        "json",
                    )
                }
            )

    output_dir = testcase_path.parent

    logger.info(f"Writing test case data to '{output_dir}'.")

    if not output_dir.exists():
        sys.exit(f"Output directory '{output_dir}' does not exist.")

    formatter = (
        formatting.format_for_example
        if type == "example"
        else formatting.format_for_testcase
    )

    for key, data_item in _artifacts.items():
        if data_item is None:
            continue

        logger.info(f"Writing {key} to '{output_dir / key}'.")

        data, _, ftype = data_item

        with open(output_dir / f"{key}.{ftype}", "w") as f:
            f.write(formatter(data, ftype))


# For all *.yml files in subdirectories of the working directory, run the test case generation
def run():
    # This tool must be called with either "testcase" or "example" as the first argument in order
    # to specify which type of output to generate.

    parser = argparse.ArgumentParser(
        description=(
            "Generate test cases or examples for SD-JWT library. "
            "Test case data is suitable for use in other SD-JWT libraries. "
            "Examples are formatted in a markdown-friendly way (e.g., line breaks, "
            "markdown formatting) for direct inclusion into the specification text."
        )
    )

    # Type is a positional argument, either testcase or example
    parser.add_argument(
        "type",
        choices=["testcase", "example"],
        help="Whether to generate test cases or examples.",
    )

    # Optional: One or more names of directories containing test cases to generate
    parser.add_argument(
        "directories",
        nargs="*",
        help=(
            "One or more names of directories containing test cases to generate. "
            "If no directories are specified, all directories containing a file "
            "named 'specification.yml' respectively are processed."
        ),
    )
    args = parser.parse_args()

    basedir = Path.cwd()
    settings_file = basedir / "settings.yml"

    if not settings_file.exists():
        sys.exit(f"Settings file '{settings_file}' does not exist.")

    if args.directories:
        glob = [basedir / d / "specification.yml" for d in args.directories]
    else:
        glob = basedir.glob("*/specification.yml")

    # load keys and other information from test_settings.yml
    settings = load_yaml_settings(settings_file)

    for case_path in glob:
        logger.info(f"Generating data for '{case_path}'")
        generate_test_case_data(settings, case_path, args.type)


if __name__ == "__main__":
    run()
