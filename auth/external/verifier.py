"""Resource-server-only token verification for an external authorization server."""

from mcp.server.auth.provider import AccessToken, TokenVerifier


class JwtTokenVerifier(TokenVerifier):
    """Verifies JWT access tokens issued by an external authorization server.

    To implement:
      - fetch and cache the issuer's signing keys from `jwks_url` (PyJWT's PyJWKClient;
        PyJWT is already installed as an mcp dependency)
      - verify signature, `iss` == issuer, `aud` contains `audience` (our /mcp URL), `exp`
      - map claims to AccessToken: client_id (e.g. `azp`/`client_id`), scopes (`scope`),
        expires_at (`exp`), subject (`sub`), resource (`aud`)
      - return None for any invalid token (the SDK then answers 401)
    """

    def __init__(self, issuer: str, jwks_url: str, audience: str):
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.audience = audience

    async def verify_token(self, token: str) -> AccessToken | None:
        raise NotImplementedError("JwtTokenVerifier is not implemented yet")
