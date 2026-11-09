"""
Unit tests for SDJWTVerifier Key Binding algorithm dynamic derivation from JWK.
Covers issue openwallet-foundation-labs/sd-jwt-python#29.
"""

import pytest
from jwcrypto import jwk, jws
import json
import base64
from hashlib import sha256

from sd_jwt.verifier import SDJWTVerifier


def _create_presentation_with_holder_key(
    issuer_key: jwk.JWK,
    holder_key: jwk.JWK,
    kb_alg: str,
    holder_jwk_override: dict = None,
) -> str:
    """Helper to build a valid SD-JWT presentation with a specific holder key and algorithm."""
    now = 1700000000
    holder_pub_jwk = holder_jwk_override or json.loads(holder_key.export_public())

    issuer_claims = {
        "iss": "https://issuer.example.com",
        "sub": "user_456",
        "iat": now - 100,
        "exp": now + 3600,
        "cnf": {"jwk": holder_pub_jwk},
    }

    # Sign issuer SD-JWT
    token = jws.JWS(json.dumps(issuer_claims).encode("utf-8"))
    token.add_signature(issuer_key, protected=json.dumps({"alg": "ES256", "typ": "example+sd-jwt"}))
    compact_sd_jwt = token.serialize(compact=True)

    # Calculate KB hash: compact SD-JWT with 0 disclosures ends with single '~'
    string_to_hash = f"{compact_sd_jwt}~"
    b64_hash = base64.urlsafe_b64encode(sha256(string_to_hash.encode("ascii")).digest()).decode("ascii").strip("=")

    kb_claims = {
        "aud": "https://verifier.example.com",
        "nonce": "test_nonce_123",
        "iat": now,
        "sd_hash": b64_hash,
    }

    # Sign Key Binding JWT with holder key using kb_alg
    kb_token = jws.JWS(json.dumps(kb_claims).encode("utf-8"))
    kb_token.add_signature(holder_key, protected=json.dumps({"alg": kb_alg, "typ": "kb+jwt"}))
    compact_kb = kb_token.serialize(compact=True)

    # Presentation format with 0 disclosures and KB-JWT: <issuer-jwt>~<kb-jwt>
    return f"{compact_sd_jwt}~{compact_kb}"


@pytest.fixture
def issuer_key():
    return jwk.JWK.generate(kty="EC", crv="P-256")


class TestKeyBindingAlgDerivation:
    def test_derive_alg_from_jwk_unit(self):
        """Unit test the static helper _derive_alg_from_jwk across key types."""
        # OKP (Ed25519)
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "OKP", "crv": "Ed25519"}) == "EdDSA"
        # EC curves
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "EC", "crv": "P-256"}) == "ES256"
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "EC", "crv": "P-384"}) == "ES384"
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "EC", "crv": "P-521"}) == "ES512"
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "EC", "crv": "secp256k1"}) == "ES256K"
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "EC"}) == "ES256"
        # RSA
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "RSA"}) == "RS256"
        # Explicit alg in JWK
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "RSA", "alg": "PS256"}) == "PS256"
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "EC", "alg": "ES384"}) == "ES384"
        # Unknown/malformed
        assert SDJWTVerifier._derive_alg_from_jwk({"kty": "UNKNOWN"}) is None
        assert SDJWTVerifier._derive_alg_from_jwk(None) is None
        assert SDJWTVerifier._derive_alg_from_jwk("not_a_dict") is None

    def test_ed25519_okp_key_binding_verification(self, issuer_key):
        """
        Verify that an Ed25519 (OKP / EdDSA) holder key verifies successfully
        WITHOUT requiring any sign_alg parameter passed to SDJWTVerifier.
        Fixes openwallet-foundation-labs/sd-jwt-python#29.
        """
        holder_key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
        presentation = _create_presentation_with_holder_key(
            issuer_key=issuer_key,
            holder_key=holder_key,
            kb_alg="EdDSA",
        )

        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: issuer_key,
            expected_aud="https://verifier.example.com",
            expected_nonce="test_nonce_123",
            current_time=1700000000,
        )
        verified = verifier.get_verified_payload()
        assert verified["sub"] == "user_456"
        assert verified["cnf"]["jwk"]["kty"] == "OKP"

    def test_ec_p256_key_binding_verification(self, issuer_key):
        """Verify EC P-256 holder key verifies with derived ES256."""
        holder_key = jwk.JWK.generate(kty="EC", crv="P-256")
        presentation = _create_presentation_with_holder_key(
            issuer_key=issuer_key,
            holder_key=holder_key,
            kb_alg="ES256",
        )

        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: issuer_key,
            expected_aud="https://verifier.example.com",
            expected_nonce="test_nonce_123",
            current_time=1700000000,
        )
        assert verifier.get_verified_payload()["sub"] == "user_456"

    def test_rsa_key_binding_verification(self, issuer_key):
        """Verify RSA holder key verifies with derived RS256."""
        holder_key = jwk.JWK.generate(kty="RSA", size=2048)
        presentation = _create_presentation_with_holder_key(
            issuer_key=issuer_key,
            holder_key=holder_key,
            kb_alg="RS256",
        )

        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: issuer_key,
            expected_aud="https://verifier.example.com",
            expected_nonce="test_nonce_123",
            current_time=1700000000,
        )
        assert verifier.get_verified_payload()["sub"] == "user_456"

    def test_explicit_jwk_alg_parameter_respected(self, issuer_key):
        """Verify that an explicit 'alg' property in the cnf.jwk takes precedence."""
        holder_key = jwk.JWK.generate(kty="EC", crv="P-384")
        holder_pub = json.loads(holder_key.export_public())
        holder_pub["alg"] = "ES384"

        presentation = _create_presentation_with_holder_key(
            issuer_key=issuer_key,
            holder_key=holder_key,
            kb_alg="ES384",
            holder_jwk_override=holder_pub,
        )

        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: issuer_key,
            expected_aud="https://verifier.example.com",
            expected_nonce="test_nonce_123",
            current_time=1700000000,
        )
        assert verifier.get_verified_payload()["sub"] == "user_456"

    def test_explicit_verifier_sign_alg_override(self, issuer_key):
        """Verify that caller-provided sign_alg override is honored."""
        holder_key = jwk.JWK.generate(kty="EC", crv="P-256")
        presentation = _create_presentation_with_holder_key(
            issuer_key=issuer_key,
            holder_key=holder_key,
            kb_alg="ES256",
        )

        verifier = SDJWTVerifier(
            sd_jwt_presentation=presentation,
            cb_get_issuer_key=lambda iss, hdr: issuer_key,
            expected_aud="https://verifier.example.com",
            expected_nonce="test_nonce_123",
            sign_alg="ES256",
            current_time=1700000000,
        )
        assert verifier.get_verified_payload()["sub"] == "user_456"
