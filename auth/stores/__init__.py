"""Pick a storage backend from a connection URL.

    sqlite:///store.db          relative to the project root
    sqlite:////abs/path/x.db    absolute path (four slashes)

To add a backend (e.g. postgresql://...), write a class implementing auth.ports.Store
and add a branch here; nothing that uses the store needs to change.
"""

from pathlib import Path

from auth.ports import Store
from auth.stores.sqlite import SqliteStore
from strava.config import PROJECT_ROOT

DEFAULT_DATABASE_URL = "sqlite:///store.db"


def open_store(url: str = DEFAULT_DATABASE_URL) -> Store:
    scheme, separator, rest = url.partition("://")
    if not separator:
        raise ValueError(f"Invalid database URL '{url}'. Expected e.g. {DEFAULT_DATABASE_URL}")
    if scheme == "sqlite":
        path = Path(rest.removeprefix("/"))  # "/store.db" -> "store.db"; "//abs/x.db" -> "/abs/x.db"
        return SqliteStore(path if path.is_absolute() else PROJECT_ROOT / path)
    raise ValueError(f"Unsupported database URL scheme '{scheme}'. Supported: sqlite")
