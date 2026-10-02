"""Keycloak as the external authorization server."""


class KeycloakStravaCredentials:
    """StravaCredentials backed by Keycloak identity brokering.

    Strava would be configured as an identity provider in the realm with "Store tokens"
    enabled; Keycloak then keeps the user's Strava tokens.

    To implement:
      - get_access_token(subject): read the stored Strava token via Keycloak's broker
        endpoint (/realms/{realm}/broker/{idp_alias}/token), handling refresh/rotation
      - check how Keycloak brokers a non-OIDC provider like Strava (generic OAuth 2.0
        identity provider support)
    """

    def __init__(self, server_url: str, realm: str, idp_alias: str = "strava"):
        self.server_url = server_url
        self.realm = realm
        self.idp_alias = idp_alias

    def get_access_token(self, subject: str) -> str:
        raise NotImplementedError("KeycloakStravaCredentials is not implemented yet")
