"""
backend/tests/conftest.py
Pytest fixtures and FastAPI dependency overrides for isolated test execution.
"""

from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.main import app


class MockResult:
    def __init__(self, scalar_value=None, scalars_list=None):
        self._scalar_value = scalar_value
        self._scalars_list = scalars_list or []

    def scalar_one_or_none(self):
        return self._scalar_value

    def scalars(self):
        class ScalarSeq:
            def __init__(self, items):
                self._items = items

            def all(self):
                return self._items

        return ScalarSeq(self._scalars_list)


@pytest.fixture(autouse=True)
def override_db_dependency():
    """Override get_db dependency with mock session when DB is offline during unit testing."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute = AsyncMock(return_value=MockResult(scalar_value=None, scalars_list=[]))

    async def _mock_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = _mock_get_db
    yield
    app.dependency_overrides.pop(get_db, None)
