"""External mode: a third-party authorization server (Descope, Keycloak, ...) issues the
tokens; this server only verifies them and fetches Strava tokens from the provider's vault.

DEFINED BUT NOT IMPLEMENTED YET. The classes here fix the shape of the integration
(which SDK/port interface each one implements) so it can be filled in later without
touching server.py, the tools, or the embedded mode.
"""
