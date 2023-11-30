import logging
import os
import random
import secrets

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from json import loads
from typing import List

DEFAULT_SIGNING_ALG = "ES256"
SD_DIGESTS_KEY = "_sd"
DIGEST_ALG_KEY = "_sd_alg"
KB_DIGEST_KEY = "sd_hash"
SD_LIST_PREFIX = "..."

logger = logging.getLogger("sd_jwt")


@dataclass
class SDObj:
    """This class can be used to make this part of the object selective disclosable."""

    value: any

    # Make hashable
    def __hash__(self):
        return hash(self.value)


class SDJWTHasSDClaimException(Exception):
    """Exception raised when input data contains the special _sd claim reserved for SD-JWT internal data."""

    def __init__(self, error_location: any):
        super().__init__(
            f"Input data contains the special claim '{SD_DIGESTS_KEY}' reserved for SD-JWT internal data. Location: {error_location!r}"
        )


class SDJWTCommon:
    SD_JWT_HEADER = os.getenv("SD_JWT_HEADER", "example+sd-jwt") # overwriteable with extra_header_parameters = {"typ": "other-example+sd-jwt"}
    KB_JWT_TYP_HEADER = "kb+jwt"
    JWS_KEY_DISCLOSURES = "disclosures"
    JWS_KEY_KB_JWT = "kb_jwt"
    HASH_ALG = {"name": "sha-256", "fn": sha256}

    COMBINED_SERIALIZATION_FORMAT_SEPARATOR = "~"

    unsafe_randomness = False

    def __init__(self, serialization_format):
        if serialization_format not in ("compact", "json"):
            raise ValueError(f"Unknown serialization format: {serialization_format}")
        self._serialization_format = serialization_format

    def _b64hash(self, raw):
        # Calculate the SHA 256 hash and output it base64 encoded
        return self._base64url_encode(self.HASH_ALG["fn"](raw).digest())

    def _combine(self, *parts):
        return self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR.join(parts)

    def _split(self, combined):
        return combined.split(self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR)

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return urlsafe_b64encode(data).decode("ascii").strip("=")

    @staticmethod
    def _base64url_decode(b64data: str) -> bytes:
        padded = f"{b64data}{'=' * divmod(len(b64data),4)[1]}"
        return urlsafe_b64decode(padded)

    def _generate_salt(self):
        if self.unsafe_randomness:
            # This is not cryptographically secure, but it is deterministic
            # and allows for repeatable output for the generation of the examples.
            logger.warning(
                "Using unsafe randomness is not suitable for production use."
            )
            return self._base64url_encode(
                bytes(random.getrandbits(8) for _ in range(16))
            )
        else:
            return self._base64url_encode(secrets.token_bytes(16))

    def _create_hash_mappings(self, disclosurses_list: List):
        # Mapping from hash of disclosure to the decoded disclosure
        self._hash_to_decoded_disclosure = {}

        # Mapping from hash of disclosure to the raw disclosure
        self._hash_to_disclosure = {}

        for disclosure in disclosurses_list:
            decoded_disclosure = loads(
                self._base64url_decode(disclosure).decode("utf-8")
            )
            _hash = self._b64hash(disclosure.encode("ascii"))
            if _hash in self._hash_to_decoded_disclosure:
                raise ValueError(
                    f"Duplicate disclosure hash {_hash} for disclosure {decoded_disclosure}"
                )

            self._hash_to_decoded_disclosure[_hash] = decoded_disclosure
            self._hash_to_disclosure[_hash] = disclosure

    def _check_for_sd_claim(self, the_object):
        # Recursively check for the presence of the _sd claim, also
        # works for arrays and nested objects.
        if isinstance(the_object, dict):
            for key, value in the_object.items():
                if key == SD_DIGESTS_KEY:
                    raise SDJWTHasSDClaimException(the_object)
                else:
                    self._check_for_sd_claim(value)
        elif isinstance(the_object, list):
            for item in the_object:
                self._check_for_sd_claim(item)
        else:
            return

    def _parse_sd_jwt(self, sd_jwt):

        if self._serialization_format == "compact":
            (
                self._unverified_input_sd_jwt,
                *self._input_disclosures,
                self._unverified_input_key_binding_jwt
            ) = self._split(sd_jwt)

            # Extract only the body from SD-JWT without verifying the signature
            _, jwt_body, _ = self._unverified_input_sd_jwt.split(".")
            self._unverified_input_sd_jwt_payload = loads(
                self._base64url_decode(jwt_body)
            )

        else:
            # if the SD-JWT is in JSON format, parse the json and extract the disclosures.
            self._unverified_input_sd_jwt = sd_jwt
            self._unverified_input_sd_jwt_parsed = loads(sd_jwt)
            self._input_disclosures = self._unverified_input_sd_jwt_parsed[
                self.JWS_KEY_DISCLOSURES
            ]
            self._unverified_input_key_binding_jwt = (
                self._unverified_input_sd_jwt_parsed.get(self.JWS_KEY_KB_JWT, "")
            )
            self._unverified_input_sd_jwt_payload = loads(
                self._base64url_decode(self._unverified_input_sd_jwt_parsed["payload"])
            )
