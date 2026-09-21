"""IDA-independent schema foundations. Does not advertise an analysis capability."""

from .serialization import (
    ContractError,
    SCHEMA_VERSION,
    canonical_json,
    digest,
    stable_id,
)

__all__ = ["ContractError", "SCHEMA_VERSION", "canonical_json", "digest", "stable_id"]
