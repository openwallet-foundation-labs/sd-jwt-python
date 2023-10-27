import base64
import json
import logging
import random
import yaml
import sys

from jwcrypto.jwk import JWK
from typing import Union

logger = logging.getLogger("sd_jwt")


def load_yaml_settings(file):
    with open(file, "r") as f:
        settings = yaml.safe_load(f)

    for property in ("identifiers", "key_settings"):
        if property not in settings:
            sys.exit(f"Settings file must define '{property}'.")

    return settings


def print_repr(values: Union[str, list], nlines=2):
    value = "\n".join(values) if isinstance(values, (list, tuple)) else values
    _nlines = "\n" * nlines if nlines else ""
    print(value, end=_nlines)


def print_decoded_repr(value: str, nlines=2):
    seq = []
    for i in value.split("."):
        try:
            padded = f"{i}{'=' * divmod(len(i),4)[1]}"
            seq.append(f"{base64.urlsafe_b64decode(padded).decode()}")
        except Exception as e:
            logging.debug(f"{e} - for value: {i}")
            seq.append(i)
    _nlines = "\n" * nlines if nlines else ""
    print("\n.\n".join(seq), end=_nlines)


def get_jwk(jwk_kwargs: dict = {}, no_randomness: bool = False, random_seed: int = 0):
    """
    jwk_kwargs = {
        issuer_key:dict : {},
        holder_key:dict : {},
        key_size: int : 0,
        kty: str : "RSA"
    }

    returns static or random JWK
    """
    if no_randomness:
        random.seed(random_seed)
        issuer_key = JWK.from_json(json.dumps(jwk_kwargs["issuer_key"]))
        holder_key = JWK.from_json(json.dumps(jwk_kwargs["holder_key"]))
        logger.warning("Using fixed randomness for demo purposes")
    else:
        _kwargs = {"key_size": jwk_kwargs["key_size"], "kty": jwk_kwargs["kty"]}
        issuer_key = JWK.generate(**_kwargs)
        holder_key = JWK.generate(**_kwargs)

    issuer_public_key = JWK.from_json(issuer_key.export_public())
    return dict(
        issuer_key=issuer_key,
        holder_key=holder_key,
        issuer_public_key=issuer_public_key,
    )
