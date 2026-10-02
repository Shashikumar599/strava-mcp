"""Descope as the external authorization server."""


class DescopeStravaCredentials:
    """StravaCredentials backed by a Descope "Connection" (Descope's third-party token vault).

    Descope stores the user's Strava tokens and refreshes them; we ask for a valid one per call.

    To implement:
      - configure Strava as a custom Connection in the Descope console (open question from
        the earlier research: custom OAuth fields + Strava's refresh-token rotation)
      - get_access_token(subject): call Descope's connection-token API (or descope-mcp's
        get_connection_token) for user `subject` and app `connection_app_id`
    """

    def __init__(self, project_id: str, management_key: str, connection_app_id: str = "strava"):
        self.project_id = project_id
        self.management_key = management_key
        self.connection_app_id = connection_app_id

    def get_access_token(self, subject: str) -> str:
        raise NotImplementedError("DescopeStravaCredentials is not implemented yet")
