#!/usr/bin/env python3
import argparse
import logging
import pathlib
import random
import sys
import datetime


from sd_jwt import __version__
from sd_jwt.utils.demo_utils import (
    get_jwk,
    print_decoded_repr,
    load_yaml_settings,
)
from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.verifier import SDJWTVerifier

from sd_jwt.utils.formatting import (
    textwrap_json,
    textwrap_text,
    multiline_code,
    EXAMPLE_SHORT_WIDTH,
)
from sd_jwt.utils.yaml_specification import load_yaml_specification

logger = logging.getLogger("sd_jwt")


# Generate a 16-bit random number
def generate_nonce():
    return bytes(random.getrandbits(8) for _ in range(16)).hex()


DEFAULT_EXP_MINS = 15

def run():
    parser = argparse.ArgumentParser(
        description=f"{__file__} demo.",
        epilog=f"{__file__}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "example",
        help=(
            "Yaml file containing the SD-JWT demo to process. See examples/simple.yml for an example."
        ),
        type=pathlib.Path,
    )
    parser.add_argument(
        "-d",
        "--debug",
        required=False,
        choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"),
        default="INFO",
        help="Debug level, see python logging; defaults to INFO if omitted",
    )
    parser.add_argument(
        "-nr",
        "--no-randomness",
        required=False,
        action="store_true",
        default=False,
        help=(
            "For the purpose of generating static examples for the spec, this command line "
            "switch disables randomness. Using this in production is highly insecure!"
        ),
    )
    parser.add_argument(
        "--nonce",
        required=False,
        type=str,
        default=generate_nonce(),
        help=("given example of a nonce: 'XZOUco1u_gEPknxS78sWWg'"),
    )
    parser.add_argument(
        "--iat", required=False, type=int, help=("issued at, UTC Timestamp")
    )
    parser.add_argument(
        "--exp", required=False, type=int, help=("expire at, UTC Timestamp")
    )
    parser.add_argument(
        "--settings-path",
        required=False,
        type=str,
        help=("Path to YAML file containing keys and other settings for the demo."),
        default="utils/demo_settings.yml",
    )
    parser.add_argument(
        "--indent",
        required=False,
        type=int,
        default=4,
        help=("json output indentation level"),
    )
    # new option to put examples into a directory
    parser.add_argument(
        "--output-dir",
        required=False,
        type=pathlib.Path,
        help=(
            "path/to/directory - Write all the examples into separate files in this directory"
        ),
    )
    parser.add_argument(
        "-v",
        "--version",
        required=False,
        action="store_true",
        help="Print version and exit",
    )

    _args = parser.parse_args()
    logger.setLevel(_args.debug)

    if _args.version:
        sys.exit(f"{__version__}")

    ### Load settings
    settings = load_yaml_settings(_args.settings_path)

    # If "no randomness" is requested, we hash the file name of the example
    # file to use it as the random seed. This ensures that the same example
    # file always generates the same output, but the output between
    # different example files is different.
    if _args.no_randomness:
        import hashlib

        hash_object = hashlib.sha256(_args.example.read_bytes())
        # Extract the hash as integer
        seed = int(hash_object.hexdigest(), 16)
    else:
        seed = None

    demo_keys = get_jwk(settings["key_settings"], _args.no_randomness, seed)

    ### Load example file

    example_identifer = _args.example.stem
    example = load_yaml_specification(_args.example)
    use_decoys = example.get("add_decoy_claims", False)

    ### Add default claims if necessary
    iat = _args.iat or int(datetime.datetime.utcnow().timestamp())
    exp = _args.exp or iat + (DEFAULT_EXP_MINS * 60)
    claims = {
        "iss": settings.ISSUER,
        "iat": iat,
        "exp": exp,
    }

    claims.update(example["user_claims"])

    ### Produce SD-JWT and SVC for selected example
    SDJWTIssuer.unsafe_randomness = _args.no_randomness
    sdjwt_at_issuer = SDJWTIssuer(
        claims,
        demo_keys["issuer_key"],
        demo_keys["holder_key"] if example.get("key_binding", False) else None,
        add_decoy_claims=use_decoys,
    )

    ### Produce SD-JWT-R for selected example

    # Note: The only input from the issuer is the combined SD-JWT and SVC!

    sdjwt_at_holder = SDJWTHolder(sdjwt_at_issuer.sd_jwt_issuance)
    sdjwt_at_holder.create_presentation(
        example["holder_disclosed_claims"],
        _args.nonce if example.get("key_binding", False) else None,
        settings.VERIFIER if example.get("key_binding", False) else None,
        demo_keys["holder_key"] if example.get("key_binding", False) else None,
    )

    ### Verify the SD-JWT using the SD-JWT-R


    # Define a function to check the issuer and retrieve the
    # matching public key
    def cb_get_issuer_key(issuer):
        # Do not use in production - this allows to use any issuer name for demo purposes
        if issuer == claims["iss"]:
            return demo_keys["issuer_public_key"]
        else:
            raise Exception(f"Unknown issuer: {issuer}")


    # Note: The only input from the holder is the combined presentation!
    sdjwt_at_verifier = SDJWTVerifier(
        sdjwt_at_holder.sd_jwt_presentation,
        cb_get_issuer_key,
        settings.VERIFIER if example.get("key_binding", False) else None,
        _args.nonce if example.get("key_binding", False) else None,
    )
    verified = sdjwt_at_verifier.get_verified_payload()

    ### Done - now output everything to CLI (unless --replace-examples-in was used)

    iid_payload = ""
    for hash in sdjwt_at_holder._hash_to_decoded_disclosure:
        salt, claim_name, claim_value = sdjwt_at_holder._hash_to_decoded_disclosure[hash]
        b64 = sdjwt_at_holder._hash_to_disclosure[hash]
        encoded_json = sdjwt_at_holder._base64url_decode(b64).decode("utf-8")

        iid_payload += (
            f"__Claim `{claim_name}`:__\n\n"
            f" * SHA-256 Hash: `{hash}`\n"
            f" * Disclosure:\\\n"
            f"{multiline_code(textwrap_text(b64, EXAMPLE_SHORT_WIDTH))}\n"
            f" * Contents:\n"
            f"{multiline_code(textwrap_text(encoded_json, EXAMPLE_SHORT_WIDTH))}\n\n\n"
        )

    iid_payload = iid_payload.strip()

    _artifacts = {
        "user_claims": (example["user_claims"], "User Claims", "json"),
        "sd_jwt_payload": (sdjwt_at_issuer.sd_jwt_payload, "Payload of the SD-JWT", "json"),
        "sd_jwt_jws_part": (
            sdjwt_at_issuer.serialized_sd_jwt,
            "Serialized SD-JWT",
            "txt",
        ),
        "disclosures": (iid_payload, "Payloads of the II-Disclosures", "md"),
        "sd_jwt_issuance": (
            sdjwt_at_issuer.sd_jwt_issuance,
            "Combined SD-JWT and Disclosures",
            "txt",
        ),
        "kb_jwt_payload": (
            sdjwt_at_holder.key_binding_jwt_payload
            if example.get("key_binding")
            else None,
            "Payload of the Holder Binding JWT",
            "json",
        ),
        "kb_jwt_serialized": (
            sdjwt_at_holder.serialized_key_binding_jwt,
            "Serialized Holder Binding JWT",
            "txt",
        ),
        "sd_jwt_presentation": (
            sdjwt_at_holder.sd_jwt_presentation,
            "Combined representation of SD-JWT and HS-Disclosures",
            "txt",
        ),
        "verified_contents": (verified, "Verified released contents of the SD-JWT", "json"),
    }

    # When decoys were used, list those as well
    if use_decoys:
        # create a list of decoy digests in markdown format
        decoy_digests = ""

        for digest in sdjwt_at_issuer.decoy_digests:
            decoy_digests += f" * `{digest}`\n"

        _artifacts["decoy_digests"] = (
            decoy_digests,
            "Decoy Claims",
            "md",
        )


    if _args.output_dir:
        logger.info(
            f"Writing all the examples into separate files in '{_args.output_dir}'."
        )

        output_dir = _args.output_dir / example_identifer

        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        for key, (data, _, ftype) in _artifacts.items():
            if data is None:
                continue

            if ftype == "json":
                out = textwrap_json(data)
            elif ftype == "txt":
                out = textwrap_text(data)
            else:
                out = data

            with open(output_dir / f"{key}.{ftype}", "w") as f:
                f.write(out)

    else:
        for key, (data, description, ftype) in _artifacts.items():
            print(f"{description} ({key}):")
            if ftype == "json":
                out = textwrap_json(data)
            elif ftype == "txt":
                out = textwrap_text(data)
            else:
                out = data

            print(out)

            # Small hack to display some values in decoded form
            if key.startswith("serialized_"):
                print(" - decodes to - ")
                print_decoded_repr(data)

        sys.exit(0)

if __name__ == "__main__":
    run()
