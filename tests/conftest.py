import pytest

from auth.stores import open_store


@pytest.fixture(params=["sqlite"])
def store(request, tmp_path):
    """A fresh, empty store per test, for every backend listed in params.

    Tests using this fixture are contract tests for auth.ports.Store: a new backend
    (e.g. "postgresql") is added to params and must pass all of them unchanged.
    """
    if request.param == "sqlite":
        return open_store(f"sqlite:///{tmp_path / 'test.db'}")
    raise NotImplementedError(request.param)
