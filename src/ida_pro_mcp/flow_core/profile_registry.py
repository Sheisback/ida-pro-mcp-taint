"""Pure, versioned extraction-profile evidence registry.

Registry membership is not an analysis-support claim.  Only rows with a pinned
measured receipt may cross the native extractor boundary; every other row stays
explicitly unverified and fails closed.
"""

from dataclasses import dataclass
from typing import Literal

from .serialization import ContractError, Model, digest
from .states import Endian, check_digest, nonempty, require, unique

FormatId = Literal["FMT-ELF", "FMT-PE", "FMT-MACHO", "FMT-RAW"]
ReceiptStatus = Literal["success", "unverified"]
SupportStatus = Literal["unverified"]

PROFILE_IDS = (
    "X86-LE",
    "X64-LE",
    "ARM32-LE",
    "ARM32-BE",
    "THUMB-LE",
    "THUMB-BE",
    "A64-LE",
    "MIPS32-LE",
    "MIPS32-BE",
    "MIPS64-LE",
    "MIPS64-BE",
    "PPC32-LE",
    "PPC32-BE",
    "PPC64-LE",
    "PPC64-BE",
    "RV32-LE",
    "RV64-LE",
)
REQUIRED_FEATURES = (
    "scalar",
    "branch",
    "range_memory",
    "abi",
    "isa_specific_contract",
)


@dataclass(frozen=True)
class MeasuredReceipt(Model):
    """Exact P0 evidence for one extractor configuration, not broad support."""

    file_name: str
    status: Literal["success"]
    maturity: Literal["MMAT_CALLS"]
    digest: str
    repeat_equal: Literal[True]
    roundtrip_equal: Literal[True]
    target_executed: Literal[False]
    processor: str
    abi: str
    format_id: FormatId
    platform_tag: str
    binary_digest: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.file_name,
            self.processor,
            self.abi,
            self.platform_tag,
        ):
            nonempty(value)
        check_digest(self.digest)
        check_digest(self.binary_digest)


@dataclass(frozen=True)
class ProfileSpec(Model):
    """One exact profile row plus its current evidence boundary."""

    profile_id: str
    profile_version: int
    mode: str
    bitness: int
    data_endian: Endian
    instruction_endian: Endian | None
    processor_artifact: str
    decompiler_artifact: str
    abi_ids: tuple[str, ...]
    format_ids: tuple[FormatId, ...]
    receipt_status: ReceiptStatus
    maturity: Literal["MMAT_CALLS"] | None
    normal_status: SupportStatus
    fallback_status: SupportStatus
    required_features: tuple[str, ...]
    measured_receipt: MeasuredReceipt | None
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.profile_id,
            self.mode,
            self.processor_artifact,
            self.decompiler_artifact,
        ):
            nonempty(value)
        require(self.profile_version == 1, "Unsupported profile version")
        require(self.bitness in (32, 64), "Unsupported profile bitness")
        require(bool(self.abi_ids), "Profile requires at least one ABI")
        unique(self.abi_ids)
        unique(self.format_ids)
        require(
            self.required_features == REQUIRED_FEATURES,
            "Unexpected profile feature contract",
        )
        if self.measured_receipt is None:
            require(
                self.receipt_status == "unverified"
                and self.maturity is None
                and not self.format_ids,
                "Unmeasured profile must fail closed",
            )
        else:
            receipt = self.measured_receipt
            require(
                self.receipt_status == "success", "Measured receipt status mismatch"
            )
            require(self.maturity == receipt.maturity, "Measured maturity mismatch")
            require(receipt.abi in self.abi_ids, "Measured ABI missing from profile")
            require(
                self.format_ids == (receipt.format_id,),
                "Measured format mismatch",
            )


@dataclass(frozen=True)
class ProfileRegistry(Model):
    """The complete deterministic 17-row profile-evidence registry."""

    profiles: tuple[ProfileSpec, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            tuple(profile.profile_id for profile in self.profiles) == PROFILE_IDS,
            "Profile registry rows/order mismatch",
        )

    def get(self, profile_id: str) -> ProfileSpec:
        rows = tuple(row for row in self.profiles if row.profile_id == profile_id)
        if len(rows) != 1:
            raise ContractError("Unknown extraction profile")
        return rows[0]

    def measured_extraction_profile(self, profile_id: str) -> dict:
        """Materialize one exact measured extractor profile from registry evidence.

        This binds the runtime configuration to the canonical receipt without
        claiming that the currently open binary supplied ABI evidence.
        """

        spec = self.get(profile_id)
        receipt = spec.measured_receipt
        if receipt is None:
            raise ContractError("Unmeasured extraction profile configuration")
        profile = {
            "format_id": receipt.format_id,
            "platform_tag": receipt.platform_tag,
            "abi_provenance": {
                "kind": "measured_anchor_build",
                "receipt_digest": receipt.digest,
                "binary_digest": receipt.binary_digest,
                "scope": "registry receipt configuration; not runtime binary or ABI inference",
            },
            "profile_id": profile_id,
            "version": spec.profile_version,
            "mode": spec.mode,
            "abi": receipt.abi,
            "maturity": receipt.maturity,
            "bitness": spec.bitness,
            "data_endian": spec.data_endian,
            "instruction_endian": spec.instruction_endian,
            "processor": receipt.processor,
            "normal_status": spec.normal_status,
            "fallback_status": spec.fallback_status,
            "receipt_status": spec.receipt_status,
            "receipt_evidence": receipt.to_data(),
            "registry_digest": digest(self),
            "required_features": list(spec.required_features),
        }
        self.validate_extraction_profile(profile)
        return profile

    def _inventory_rows(self, inventory) -> tuple[dict, ...]:
        if type(inventory) is not dict or inventory.get("schema_version") != (
            "flow-p0-inventory/1"
        ):
            raise ContractError("Unsupported P0 inventory")
        rows = inventory.get("profiles")
        if (
            type(rows) is not list
            or tuple(
                row.get("profile_id") if type(row) is dict else None for row in rows
            )
            != PROFILE_IDS
        ):
            raise ContractError("P0 inventory profile rows/order mismatch")
        return tuple(rows)

    @staticmethod
    def _validate_inventory_row(
        spec: ProfileSpec, row: dict, *, strict_fixture_hash: bool
    ) -> None:
        receipt = spec.measured_receipt
        expected = {
            "profile_id": spec.profile_id,
            "profile_version": spec.profile_version,
            "required": True,
            "mode": spec.mode,
            "bitness": spec.bitness,
            "data_endian": "LE" if spec.data_endian == "little" else "BE",
            "instruction_endian": (
                None
                if spec.instruction_endian is None
                else "LE"
                if spec.instruction_endian == "little"
                else "BE"
            ),
            "abi_ids": list(spec.abi_ids),
            "format_rows": list(spec.format_ids),
            "probe_status": spec.receipt_status,
            "probe_receipt": None if receipt is None else receipt.file_name,
            "maturity": spec.maturity,
            "normal_status": spec.normal_status,
            "fallback_status": spec.fallback_status,
            "required_features": list(spec.required_features),
            "processor_artifact": spec.processor_artifact,
            "decompiler_artifact": spec.decompiler_artifact,
        }
        try:
            actual = {
                "profile_id": row["profile_id"],
                "profile_version": row["profile_version"],
                "required": row["required"],
                "mode": row["mode"],
                "bitness": row["bitness"],
                "data_endian": row["data_endian"],
                "instruction_endian": row["instruction_endian"],
                "abi_ids": row["abi_ids"],
                "format_rows": row["format_rows"],
                "probe_status": row["probe_status"],
                "probe_receipt": row["probe_receipt"],
                "maturity": row["maturity"],
                "normal_status": row["normal_status"],
                "fallback_status": row["fallback_status"],
                "required_features": row["required_features"],
                "processor_artifact": row["artifacts"]["processor"]["artifact"],
                "decompiler_artifact": row["artifacts"]["decompiler"]["artifact"],
            }
        except (KeyError, TypeError) as exc:
            raise ContractError("Malformed P0 inventory profile row") from exc
        require(actual == expected, "P0 inventory profile contract mismatch")
        hashes = row.get("fixture_hashes")
        if strict_fixture_hash:
            expected_hashes = (
                []
                if receipt is None
                else [receipt.binary_digest.removeprefix("sha256-v1:")]
            )
            require(hashes == expected_hashes, "P0 inventory fixture receipt mismatch")
        else:
            require(
                type(hashes) is list
                and all(
                    type(item) is str
                    and len(item) == 64
                    and all(char in "0123456789abcdef" for char in item)
                    for item in hashes
                ),
                "Invalid fixture receipt hashes",
            )

    def validate_inventory(self, inventory) -> None:
        """Validate the canonical P0 inventory including pinned fixture receipts."""

        for spec, row in zip(
            self.profiles, self._inventory_rows(inventory), strict=True
        ):
            self._validate_inventory_row(spec, row, strict_fixture_hash=True)

    def resolve_inventory_profile(self, inventory, profile_id: str) -> ProfileSpec:
        """Resolve a row while allowing separately reviewed build receipts.

        Receipt-generation scripts may replace fixture hashes with a new build
        manifest.  All profile/evidence fields remain exact, while the extractor
        independently requires one matching build receipt for that hash.
        """

        rows = self._inventory_rows(inventory)
        for spec, row in zip(self.profiles, rows, strict=True):
            self._validate_inventory_row(spec, row, strict_fixture_hash=False)
        return self.get(profile_id)

    def validate_probe_receipt(self, profile_id: str, document) -> MeasuredReceipt:
        spec = self.get(profile_id)
        receipt = spec.measured_receipt
        if receipt is None:
            raise ContractError("Profile has no measured extraction receipt")
        try:
            probes = [
                probe
                for probe in document["probes"]
                if probe["maturity"] == receipt.maturity
            ]
            actual = {
                "schema_version": document["schema_version"],
                "binary_digest": "sha256-v1:" + document["binary"]["sha256"],
                "initialization": document["initialization"],
                "target_executed": document["target_executed"],
                "processor": document["environment"]["processor"],
                "bitness": document["environment"]["bits"],
                "data_endian": {
                    "LE": "little",
                    "BE": "big",
                }[document["environment"]["data_endian"]],
                "roundtrip_equal": document["lifetime"]["json_roundtrip"],
                "probes": probes,
            }
        except (KeyError, TypeError) as exc:
            raise ContractError("Malformed extraction probe receipt") from exc
        require(
            actual["schema_version"] == "flow-p0-probe/1", "Receipt version mismatch"
        )
        require(
            actual["binary_digest"] == receipt.binary_digest, "Receipt binary mismatch"
        )
        require(
            actual["initialization"] is True, "Decompiler initialization unmeasured"
        )
        require(actual["target_executed"] is False, "Receipt executed target")
        require(actual["processor"] == receipt.processor, "Receipt processor mismatch")
        require(actual["bitness"] == spec.bitness, "Receipt bitness mismatch")
        require(actual["data_endian"] == spec.data_endian, "Receipt endian mismatch")
        require(
            actual["roundtrip_equal"] is receipt.roundtrip_equal,
            "Receipt roundtrip mismatch",
        )
        require(len(probes) == 1, "Expected one measured maturity receipt")
        probe = probes[0]
        require(probe.get("status") == receipt.status, "Receipt status mismatch")
        require(
            "sha256-v1:" + probe.get("digest", "") == receipt.digest,
            "Receipt digest mismatch",
        )
        require(
            probe.get("repeat_equal") is receipt.repeat_equal,
            "Receipt repeat mismatch",
        )
        return receipt

    def validate_extraction_profile(self, profile) -> ProfileSpec:
        """Fail closed unless a profile exactly binds a measured registry receipt."""

        if type(profile) is not dict:
            raise ContractError("Invalid extraction profile")
        profile_id = profile.get("profile_id")
        if type(profile_id) is not str:
            raise ContractError("Invalid extraction profile")
        spec = self.get(profile_id)
        receipt = spec.measured_receipt
        if receipt is None:
            raise ContractError("Unmeasured extraction profile configuration")
        expected = {
            "version": spec.profile_version,
            "mode": spec.mode,
            "abi": receipt.abi,
            "maturity": receipt.maturity,
            "bitness": spec.bitness,
            "data_endian": spec.data_endian,
            "instruction_endian": spec.instruction_endian,
            "processor": receipt.processor,
            "format_id": receipt.format_id,
            "platform_tag": receipt.platform_tag,
            "normal_status": spec.normal_status,
            "fallback_status": spec.fallback_status,
            "receipt_status": spec.receipt_status,
            "receipt_evidence": receipt.to_data(),
            "registry_digest": digest(self),
            "required_features": list(spec.required_features),
        }
        require(
            all(profile.get(key) == value for key, value in expected.items()),
            "Unmeasured extraction profile configuration",
        )
        provenance = profile.get("abi_provenance")
        require(
            type(provenance) is dict
            and provenance.get("kind") == "measured_anchor_build",
            "Extraction profile lacks measured build provenance",
        )
        return spec


def _receipt(
    file_name: str,
    digest_hex: str,
    processor: str,
    abi: str,
    binary_hex: str,
) -> MeasuredReceipt:
    return MeasuredReceipt(
        file_name,
        "success",
        "MMAT_CALLS",
        "sha256-v1:" + digest_hex,
        True,
        True,
        False,
        processor,
        abi,
        "FMT-MACHO",
        "darwin",
        "sha256-v1:" + binary_hex,
    )


X64_RECEIPT = _receipt(
    "x64.json",
    "11321332d69c6c7e875aaa1a81370db02e5648a5e396a7113c8f4491575599bf",
    "metapc",
    "darwin-x86_64-sysv-derived",
    "015c684b75facbf3e1f8f5928adee695de44d927f2a4b93c5be10261af72350c",
)
A64_RECEIPT = _receipt(
    "a64.json",
    "1fc4b30220054d7c6e36321e7d691bd960c32b36e452bf2439c4f4ac4541be64",
    "ARM",
    "darwin-aarch64",
    "755a8fed2e53d2b6da42067c816a2667c4a307e0a8cdcaca34da9e6e6c3c0b07",
)


def _profile(
    profile_id: str,
    mode: str,
    bitness: int,
    data_endian: Endian,
    instruction_endian: Endian | None,
    processor: str,
    decompiler: str,
    abi_ids: tuple[str, ...],
    receipt: MeasuredReceipt | None = None,
) -> ProfileSpec:
    return ProfileSpec(
        profile_id,
        1,
        mode,
        bitness,
        data_endian,
        instruction_endian,
        processor,
        decompiler,
        abi_ids,
        () if receipt is None else (receipt.format_id,),
        "unverified" if receipt is None else "success",
        None if receipt is None else receipt.maturity,
        "unverified",
        "unverified",
        REQUIRED_FEATURES,
        receipt,
    )


REGISTRY = ProfileRegistry(
    (
        _profile(
            "X86-LE",
            "X86",
            32,
            "little",
            None,
            "procs/pc.dylib",
            "plugins/hexx86.dylib",
            ("sysv-i386",),
        ),
        _profile(
            "X64-LE",
            "X64",
            64,
            "little",
            "little",
            "procs/pc.dylib",
            "plugins/hexx64.dylib",
            ("windows-x64", "sysv-amd64", "darwin-x86_64-sysv-derived"),
            X64_RECEIPT,
        ),
        _profile(
            "ARM32-LE",
            "ARM32",
            32,
            "little",
            None,
            "procs/arm.dylib",
            "plugins/hexarm.dylib",
            ("aapcs32",),
        ),
        _profile(
            "ARM32-BE",
            "ARM32",
            32,
            "big",
            None,
            "procs/arm.dylib",
            "plugins/hexarm.dylib",
            ("aapcs32",),
        ),
        _profile(
            "THUMB-LE",
            "THUMB",
            32,
            "little",
            None,
            "procs/arm.dylib",
            "plugins/hexarm.dylib",
            ("aapcs32",),
        ),
        _profile(
            "THUMB-BE",
            "THUMB",
            32,
            "big",
            None,
            "procs/arm.dylib",
            "plugins/hexarm.dylib",
            ("aapcs32",),
        ),
        _profile(
            "A64-LE",
            "A64",
            64,
            "little",
            "little",
            "procs/arm.dylib",
            "plugins/hexarm.dylib",
            ("aapcs64", "darwin-aarch64"),
            A64_RECEIPT,
        ),
        _profile(
            "MIPS32-LE",
            "MIPS32",
            32,
            "little",
            None,
            "procs/mips.dylib",
            "plugins/hexmips.dylib",
            ("mips-o32",),
        ),
        _profile(
            "MIPS32-BE",
            "MIPS32",
            32,
            "big",
            None,
            "procs/mips.dylib",
            "plugins/hexmips.dylib",
            ("mips-o32",),
        ),
        _profile(
            "MIPS64-LE",
            "MIPS64",
            64,
            "little",
            None,
            "procs/mips.dylib",
            "plugins/hexmips.dylib",
            ("mips-n64",),
        ),
        _profile(
            "MIPS64-BE",
            "MIPS64",
            64,
            "big",
            None,
            "procs/mips.dylib",
            "plugins/hexmips.dylib",
            ("mips-n64",),
        ),
        _profile(
            "PPC32-LE",
            "PPC32",
            32,
            "little",
            None,
            "procs/ppc.dylib",
            "plugins/hexppc.dylib",
            ("sysv-ppc32",),
        ),
        _profile(
            "PPC32-BE",
            "PPC32",
            32,
            "big",
            None,
            "procs/ppc.dylib",
            "plugins/hexppc.dylib",
            ("sysv-ppc32",),
        ),
        _profile(
            "PPC64-LE",
            "PPC64",
            64,
            "little",
            None,
            "procs/ppc.dylib",
            "plugins/hexppc.dylib",
            ("elfv2-ppc64",),
        ),
        _profile(
            "PPC64-BE",
            "PPC64",
            64,
            "big",
            None,
            "procs/ppc.dylib",
            "plugins/hexppc.dylib",
            ("elfv2-ppc64",),
        ),
        _profile(
            "RV32-LE",
            "RV32",
            32,
            "little",
            None,
            "procs/riscv.dylib",
            "plugins/hexrv.dylib",
            ("riscv-ilp32",),
        ),
        _profile(
            "RV64-LE",
            "RV64",
            64,
            "little",
            None,
            "procs/riscv.dylib",
            "plugins/hexrv.dylib",
            ("riscv-lp64",),
        ),
    )
)
REGISTRY_DIGEST = digest(REGISTRY)

__all__ = [
    "A64_RECEIPT",
    "PROFILE_IDS",
    "REGISTRY",
    "REGISTRY_DIGEST",
    "X64_RECEIPT",
    "MeasuredReceipt",
    "ProfileRegistry",
    "ProfileSpec",
]
