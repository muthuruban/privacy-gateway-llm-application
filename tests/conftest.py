"""Shared fixtures.

The PII mediator is expensive to construct (it loads a spaCy model), so a
single instance is shared across the whole test session. It is stateless
between calls — every ``sanitize`` returns its own mapping — so sharing is
safe.
"""

import pytest

from gateway.config import DEFAULT_POLICY
from gateway.pii_mediator import PIIMediator


@pytest.fixture(scope="session")
def mediator() -> PIIMediator:
    return PIIMediator(policy=dict(DEFAULT_POLICY))
