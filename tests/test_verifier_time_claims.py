"""
Unit tests for SDJWTVerifier time claims validation (RFC 7519 'exp', 'nbf', 'iat').
Covers issue openwallet-foundation-labs/sd-jwt-python#28.
"""

import time
import pytest
from jwcrypto import jwk, jws
import json

from sd_jwt.exceptions import (
    SDJWTExpiredException,
    SDJWTNotYetValidException,
    SDJWTTimeValidationException,
)
from sd_jwt.verifier import SDJWTVerifier


def _create_mock_sd_jwt_presentation(claims: dict, issuer_key: jwk.JWK) -> str:
    """Helper to create a minimal compact SD-JWT presentation for testing."""
    token = jws.JWS(json.dumps(claims).encode("utf-8"))
    token.add_signature(issuer_key, protected=json.dumps({"alg": "ES256", "typ": "example+sd-jwt"}))
    compact_sd_jwt = token.serialize(compact=True)
    # Compact SD-JWT format with 0 disclosures and no KB-JWT ends with single '~': <issuer-jwt>~
    return f"{compact_sd_jwt}~"


def _create_mock_sd_jwt_with_kb(
    claims: dict,
    issuer_key: jwk.JWK,
    holder_key: jwk.JWK,
    kb_claims: dict,
    kb_alg: str = "ES256",
) -> str:
    """Helper to create an SD-JWT presentation with a Key Binding JWT."""
    claims_with_cnf = dict(claims)
    claims_with_cnf["cnf"] = {"jwk": json.loads(holder_key.export_public())}

    token = jws.JWS(json.dumps(claims_with_cnf).encode("utf-8"))
    token.add_signature(issuer_key, protected=json.dumps({"alg": "ES256", "typ": "example+sd-jwt"}))
    compact_sd_jwt = token.serialize(compact=True)

    # Compute sd_hash for compact SD-JWT with 0 disclosures: hash(compact_sd_jwt + "~")
    from hashlib import sha256
    import base64
    string_to_hash = f"{compact_sd_jwt}~"
    b64_hash = base64.urlsafe_b64encode(sha256(string_to_hash.encode("ascii")).digest()).decode("ascii").strip("=")

    full_kb_claims = dict(kb_claims)
    full_kb_claims["sd_hash"] = b64_hash

    kb_token = jws.JWS(json.dumps(full_kb_claims).encode("utf-8"))
    kb_token.add_signature(holder_key, protected=json.dumps({"alg": kb_alg, "typ": "kb+jwt"}))
    compact_kb = kb_token.serialize(compact=True)

    # Compact SD-JWT with 0 disclosures and KB-JWT: <issuer-jwt>~<kb-jwt>
    return f"{compact_sd_jwt}~{compact_kb}"


@pytest.fixture
def keys():
    issuer_key = jwk.JWK.generate(kty="EC", crv="P-256")
    holder_key = jwk.JWK.generate(kty="EC", crv="P-256")
    return {"issuer": issuer_key, "holder": holder_key}


class TestSDJWTVerifierTimeClaims:
    def test_valid_time_claims_within_window(self, keys):
        now = 1700000000
        claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "iat": now - 3600,
            "nbf": now - 1800,
            "exp": now + 3600,
        }
        presentation = _create_mock_sd_jwt_presentation(claims, keys["issuer"])

        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
            current_time=now,
            clock_skew_sec=60,
        )
        verified = verifier.get_verified_payload()
        assert verified["sub"] == "user_123"

    def test_expired_token_raises_sdjwt_expired_exception(self, keys):
        now = 1700000000
        claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "exp": now - 100,  # Expired 100 seconds ago
        }
        presentation = _create_mock_sd_jwt_presentation(claims, keys["issuer"])

        with pytest.raises(SDJWTExpiredException) as exc_info:
            SDJWTVerifier(
                sd_jwt_presentation=presentation,
                cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
                current_time=now,
                clock_skew_sec=30,  # Skew 30s is less than 100s
            )
        assert "Token has expired" in str(exc_info.value)
        assert issubclass(SDJWTExpiredException, ValueError)  # Backward compatibility

    def test_clock_skew_tolerates_minor_expiration(self, keys):
        now = 1700000000
        claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "exp": now - 20,  # Expired 20s ago
        }
        presentation = _create_mock_sd_jwt_presentation(claims, keys["issuer"])

        # With 60s skew, 20s expiration is tolerated
        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
            current_time=now,
            clock_skew_sec=60,
        )
        assert verifier.get_verified_payload()["sub"] == "user_123"

    def test_not_yet_valid_nbf_raises_exception(self, keys):
        now = 1700000000
        claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "nbf": now + 600,  # Valid starting in 10 minutes
        }
        presentation = _create_mock_sd_jwt_presentation(claims, keys["issuer"])

        with pytest.raises(SDJWTNotYetValidException) as exc_info:
            SDJWTVerifier(
                sd_jwt_presentation=presentation,
                cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
                current_time=now,
                clock_skew_sec=60,
            )
        assert "Token is not yet valid" in str(exc_info.value)

    def test_future_iat_past_skew_raises_exception(self, keys):
        now = 1700000000
        claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "iat": now + 300,  # Claimed issue time 5 mins into future
        }
        presentation = _create_mock_sd_jwt_presentation(claims, keys["issuer"])

        with pytest.raises(SDJWTNotYetValidException) as exc_info:
            SDJWTVerifier(
                sd_jwt_presentation=presentation,
                cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
                current_time=now,
                clock_skew_sec=60,
            )
        assert "Token issued in the future" in str(exc_info.value)

    def test_invalid_non_numeric_claim_raises_value_error(self, keys):
        now = 1700000000
        claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "exp": "tomorrow",  # String instead of number
        }
        presentation = _create_mock_sd_jwt_presentation(claims, keys["issuer"])

        with pytest.raises(ValueError) as exc_info:
            SDJWTVerifier(
                sd_jwt_presentation=presentation,
                cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
                current_time=now,
            )
        assert "must be a number" in str(exc_info.value)

    def test_key_binding_jwt_expired_raises_exception(self, keys):
        now = 1700000000
        sd_claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "exp": now + 3600,
        }
        kb_claims = {
            "aud": "https://verifier.example.com",
            "nonce": "nonce_xyz",
            "iat": now - 600,
            "exp": now - 100,  # KB-JWT expired!
        }
        presentation = _create_mock_sd_jwt_with_kb(
            sd_claims, keys["issuer"], keys["holder"], kb_claims
        )

        with pytest.raises(SDJWTExpiredException) as exc_info:
            SDJWTVerifier(
                sd_jwt_presentation=presentation,
                cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
                expected_aud="https://verifier.example.com",
                expected_nonce="nonce_xyz",
                current_time=now,
                clock_skew_sec=30,
            )
        assert "Token has expired" in str(exc_info.value)

    def test_key_binding_jwt_future_iat_raises_exception(self, keys):
        now = 1700000000
        sd_claims = {
            "iss": "https://issuer.example.com",
            "sub": "user_123",
            "exp": now + 3600,
        }
        kb_claims = {
            "aud": "https://verifier.example.com",
            "nonce": "nonce_xyz",
            "iat": now + 500,  # KB-JWT claimed future issue time
        }
        presentation = _create_mock_sd_jwt_with_kb(
            sd_claims, keys["issuer"], keys["holder"], kb_claims
        )

        with pytest.raises(SDJWTNotYetValidException) as exc_info:
            SDJWTVerifier(
                sd_jwt_presentation=presentation,
                cb_get_issuer_key=lambda iss, hdr: keys["issuer"],
                expected_aud="https://verifier.example.com",
                expected_nonce="nonce_xyz",
                current_time=now,
                clock_skew_sec=60,
            )
        assert "Token issued in the future" in str(exc_info.value)
