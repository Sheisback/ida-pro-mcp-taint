"""Source-packaged owned-fixture reviews, never a library/name recognizer."""

import json
from dataclasses import dataclass
from typing import cast

from ._reviewed_fixture_data import REVIEWED_FIXTURE_JSON
from .contracts import SnapshotIdentity
from .profile_registry import REGISTRY
from .serialization import canonical_json, digest
from .states import require
from .summaries import SummaryCatalog


@dataclass(frozen=True)
class ReviewedFixture:
    profile_json: str
    catalog: SummaryCatalog
    baselines: tuple[tuple[int, SnapshotIdentity], ...]
    evidence_path: str = "reviewed_owned_fixture"

    def __post_init__(self):
        profile, _ = self.extraction_profile()
        identities = dict(self.baselines)
        require(len(identities) == len(self.baselines), "Duplicate reviewed callee RVA")
        for summary in self.catalog.summaries:
            identity = summary.identity
            baseline = identities.get(identity.callee_rva)
            require(baseline is not None, "Review lacks pinned baseline")
            assert baseline is not None
            require(
                identity.callee_snapshot_id == baseline.snapshot_id
                and identity.profile_digest
                == baseline.profile_digest
                == digest(profile)
                and "sha256-v1:" + identity.binary_sha256 == baseline.binary_digest,
                "Review/baseline identity mismatch",
            )
        require(
            len({i.binary_digest for _, i in self.baselines}) == 1
            and len({i.environment for _, i in self.baselines}) == 1,
            "Mixed reviewed fixture identities",
        )

    @property
    def binary_digest(self):
        return self.baselines[0][1].binary_digest

    @property
    def profile_id(self):
        return json.loads(self.profile_json)["profile_id"]

    @property
    def abi_id(self):
        return self.baselines[0][1].environment.abi

    @property
    def observed_identity(self):
        env = self.baselines[0][1].environment
        return (
            env.processor,
            env.bitness,
            env.data_endian,
            env.format_id,
            env.ida_build,
            env.hexrays_build,
        )

    def extraction_profile(self):
        # Fresh dict protects the immutable review from caller mutation.
        profile = json.loads(self.profile_json)
        REGISTRY.validate_extraction_profile(profile)
        return profile, REGISTRY


def _load():
    return tuple(
        ReviewedFixture(
            canonical_json(row["profile"]),
            cast(SummaryCatalog, SummaryCatalog.from_data(row["catalog"])),
            tuple(
                (
                    item["rva"],
                    cast(
                        SnapshotIdentity, SnapshotIdentity.from_data(item["identity"])
                    ),
                )
                for item in row["baselines"]
            ),
        )
        for row in json.loads(REVIEWED_FIXTURE_JSON)
    )


REVIEWED_FIXTURES = _load()


def reviewed_fixture(binary_digest):
    return next(
        (f for f in REVIEWED_FIXTURES if f.binary_digest == binary_digest), None
    )
