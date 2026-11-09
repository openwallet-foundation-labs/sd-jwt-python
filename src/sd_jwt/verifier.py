from .common import (
    SDJWTCommon,
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
    KB_DIGEST_KEY,
)
from .exceptions import (
    SDJWTExpiredException,
    SDJWTNotYetValidException,
    SDJWTTimeValidationException,
)

from json import dumps, loads
import time
from typing import Dict, List, Union, Callable, Optional

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS


class SDJWTVerifier(SDJWTCommon):
    _input_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(
        self,
        sd_jwt_presentation: str,
        cb_get_issuer_key: Callable[[str, Dict], str],
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        serialization_format: str = "compact",
        sign_alg: Union[str, None] = None,
        clock_skew_sec: int = 300,
        current_time: Union[int, float, None] = None,
    ):
        super().__init__(serialization_format=serialization_format)
        self._sign_alg = sign_alg
        self._clock_skew_sec = clock_skew_sec
        self._current_time = current_time

        self._parse_sd_jwt(sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        self._verify_sd_jwt(cb_get_issuer_key, sign_alg=sign_alg)

        # expected aud and nonce either need to be both set or both None
        if expected_aud or expected_nonce:
            if not (expected_aud and expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be provided or both must be None"
                )

            # Verify the SD-JWT-Release
            self._verify_key_binding_jwt(
                expected_aud,
                expected_nonce,
                sign_alg=sign_alg,
            )

    def get_verified_payload(self):
        return self._extract_sd_claims()

    def _validate_time_claims(
        self,
        payload: dict,
        clock_skew_sec: Union[int, float, None] = None,
        current_time: Union[int, float, None] = None,
    ) -> None:
        """
        Validate standard JWT time claims ('exp', 'nbf', 'iat') according to RFC 7519.

        Args:
            payload: Decoded claims dictionary from SD-JWT or Key Binding JWT.
            clock_skew_sec: Acceptable clock skew in seconds (default: 300).
            current_time: Reference timestamp in seconds since epoch (default: time.time()).

        Raises:
            SDJWTExpiredException: If current_time >= exp + clock_skew_sec.
            SDJWTNotYetValidException: If current_time < nbf - clock_skew_sec or iat > current_time + clock_skew_sec.
            ValueError: If a present time claim is not numeric.
        """
        if clock_skew_sec is None:
            clock_skew_sec = getattr(self, "_clock_skew_sec", 300)
        if current_time is None:
            current_time = getattr(self, "_current_time", None)
            if current_time is None:
                current_time = time.time()

        # 1. Validate 'exp' (Expiration Time)
        if "exp" in payload:
            exp = payload["exp"]
            if not isinstance(exp, (int, float)):
                raise ValueError(f"Claim 'exp' must be a number, got {type(exp).__name__}")
            if current_time >= exp + clock_skew_sec:
                raise SDJWTExpiredException(
                    f"Token has expired: exp={exp}, current_time={current_time}, clock_skew={clock_skew_sec}"
                )

        # 2. Validate 'nbf' (Not Before)
        if "nbf" in payload:
            nbf = payload["nbf"]
            if not isinstance(nbf, (int, float)):
                raise ValueError(f"Claim 'nbf' must be a number, got {type(nbf).__name__}")
            if current_time < nbf - clock_skew_sec:
                raise SDJWTNotYetValidException(
                    f"Token is not yet valid: nbf={nbf}, current_time={current_time}, clock_skew={clock_skew_sec}"
                )

        # 3. Validate 'iat' (Issued At)
        if "iat" in payload:
            iat = payload["iat"]
            if not isinstance(iat, (int, float)):
                raise ValueError(f"Claim 'iat' must be a number, got {type(iat).__name__}")
            if iat > current_time + clock_skew_sec:
                raise SDJWTNotYetValidException(
                    f"Token issued in the future: iat={iat}, current_time={current_time}, clock_skew={clock_skew_sec}"
                )

    def _verify_sd_jwt(
        self,
        cb_get_issuer_key,
        sign_alg: str = None,
    ):
        parsed_input_sd_jwt = JWS()
        parsed_input_sd_jwt.deserialize(self._unverified_input_sd_jwt)

        unverified_issuer = self._unverified_input_sd_jwt_payload.get("iss", None)
        unverified_header_parameters = parsed_input_sd_jwt.jose_header
        issuer_public_key = cb_get_issuer_key(
            unverified_issuer, unverified_header_parameters
        )
        parsed_input_sd_jwt.verify(issuer_public_key, alg=sign_alg)

        self._sd_jwt_payload = loads(parsed_input_sd_jwt.payload.decode("utf-8"))
        # Validate time claims on the SD-JWT issuer payload
        self._validate_time_claims(self._sd_jwt_payload)

        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    @staticmethod
    def _derive_alg_from_jwk(jwk: dict) -> Union[str, None]:
        """
        Derive signature algorithm from JWK parameters.
        - If 'alg' is explicitly declared in JWK, use it.
        - If kty == 'OKP' (e.g., Ed25519, Ed448), derive 'EdDSA'.
        - If kty == 'EC', derive based on curve:
            - 'P-256' -> 'ES256'
            - 'P-384' -> 'ES384'
            - 'P-521' -> 'ES512'
            - 'secp256k1' -> 'ES256K'
            - fallback -> 'ES256'
        - If kty == 'RSA', derive 'RS256'.
        - Otherwise, return None (allowing fallback to default).
        """
        if not isinstance(jwk, dict):
            return None
        if "alg" in jwk and isinstance(jwk["alg"], str):
            return jwk["alg"]

        kty = jwk.get("kty")
        if kty == "OKP":
            return "EdDSA"
        elif kty == "EC":
            crv = jwk.get("crv")
            if crv == "P-384":
                return "ES384"
            elif crv == "P-521":
                return "ES512"
            elif crv == "secp256k1":
                return "ES256K"
            return "ES256"
        elif kty == "RSA":
            return "RS256"

        return None

    def _verify_key_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        sign_alg: Union[str, None] = None,
    ):
        parsed_input_key_binding_jwt = JWS()
        parsed_input_key_binding_jwt.deserialize(self._unverified_input_key_binding_jwt)

        # Verify the key binding JWT using the holder public key
        if not self._holder_public_key_payload:
            raise ValueError("No holder public key in SD-JWT")

        holder_public_key_payload_jwk = self._holder_public_key_payload.get("jwk", None)
        if not holder_public_key_payload_jwk:
            raise ValueError(
                "The holder_public_key_payload is malformed. "
                "It doesn't contain the claim jwk: "
                f"{self._holder_public_key_payload}"
            )

        # Derive algorithm from holder key JWK dynamically if not explicitly specified
        derived_alg = self._derive_alg_from_jwk(holder_public_key_payload_jwk)
        _alg = sign_alg or derived_alg or DEFAULT_SIGNING_ALG

        pubkey = JWK.from_json(dumps(holder_public_key_payload_jwk))

        parsed_input_key_binding_jwt.verify(pubkey, alg=_alg)

        # Check header typ
        key_binding_jwt_header = parsed_input_key_binding_jwt.jose_header

        if key_binding_jwt_header["typ"] != self.KB_JWT_TYP_HEADER:
            raise ValueError("Invalid header typ")

        # Check payload
        key_binding_jwt_payload = loads(parsed_input_key_binding_jwt.payload)

        # Validate time claims on the Key Binding JWT payload
        self._validate_time_claims(key_binding_jwt_payload)

        if key_binding_jwt_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience in KB-JWT")
        if key_binding_jwt_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce in KB-JWT")

        # Reassemble the SD-JWT in compact format and check digest
        if self._serialization_format == "compact":
            expected_sd_jwt_presentation_hash = self._calculate_kb_hash(
                self._input_disclosures
            )

            if (
                key_binding_jwt_payload[KB_DIGEST_KEY]
                != expected_sd_jwt_presentation_hash
            ):
                raise ValueError("Invalid digest in KB-JWT")

    def _extract_sd_claims(self):
        if DIGEST_ALG_KEY in self._sd_jwt_payload:
            if self._sd_jwt_payload[DIGEST_ALG_KEY] != self.HASH_ALG["name"]:
                # TODO: Support other hash algorithms
                raise ValueError("Invalid hash algorithm")

        self._duplicate_hash_check = []
        return self._unpack_disclosed_claims(self._sd_jwt_payload)

    def _unpack_disclosed_claims(self, sd_jwt_claims):
        # In a list, unpack each element individually
        if type(sd_jwt_claims) is list:
            output = []
            for element in sd_jwt_claims:
                if (
                    type(element) is dict
                    and len(element) == 1
                    and SD_LIST_PREFIX in element
                    and type(element[SD_LIST_PREFIX]) is str
                ):
                    digest_to_check = element[SD_LIST_PREFIX]
                    if digest_to_check in self._hash_to_decoded_disclosure:
                        _, value = self._hash_to_decoded_disclosure[digest_to_check]
                        output.append(self._unpack_disclosed_claims(value))
                else:
                    output.append(self._unpack_disclosed_claims(element))
            return output

        elif type(sd_jwt_claims) is dict:
            # First, try to figure out if there are any claims to be
            # disclosed in this dict. If so, replace them by their
            # disclosed values.

            pre_output = {
                k: self._unpack_disclosed_claims(v)
                for k, v in sd_jwt_claims.items()
                if k != SD_DIGESTS_KEY and k != DIGEST_ALG_KEY
            }

            for digest in sd_jwt_claims.get(SD_DIGESTS_KEY, []):
                if digest in self._duplicate_hash_check:
                    raise ValueError(f"Duplicate hash found in SD-JWT: {digest}")
                self._duplicate_hash_check.append(digest)

                if digest in self._hash_to_decoded_disclosure:
                    _, key, value = self._hash_to_decoded_disclosure[digest]
                    if key in pre_output:
                        raise ValueError(
                            f"Duplicate key found when unpacking disclosed claim: '{key}' in {pre_output}. This is not allowed."
                        )
                    unpacked_value = self._unpack_disclosed_claims(value)
                    pre_output[key] = unpacked_value

            # Now, go through the dict and unpack any nested dicts.

            return pre_output

        else:
            return sd_jwt_claims
