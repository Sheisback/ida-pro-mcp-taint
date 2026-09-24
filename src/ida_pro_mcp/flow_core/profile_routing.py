"""Public routing over frozen evidence and explicit analyst selections.

The canonical registry remains conservative: its rows are configuration facts,
not broad support claims. Exact-fixture routing admits an extraction profile only
when the open database matches a committed normal semantic receipt. Analyst mode
instead requires an explicit profile and ABI whose observed processor, bitness,
endianness, format, and IDA/Hex-Rays builds match that same evidence. The current
binary digest scopes runtime state and staleness; it is never treated as ABI or
support evidence. Both modes build an ephemeral one-row measured registry and
never mutate or promote :data:`profile_registry.REGISTRY`.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from .profile_registry import (
    REGISTRY,
    FormatId,
    MeasuredReceipt,
    ProfileRegistry,
)
from .reviewed_fixtures import REVIEWED_FIXTURES, ReviewedFixture
from .serialization import ContractError, Model, digest
from .states import Endian, check_digest, nonempty, require

MANIFEST_DIGEST = (
    "sha256-v1:a6e8d41dfab09875b439ac726d0a1dcf067abc3354ccadb1cd20c8d462f46b9a"
)
RoutingMode = Literal["exact_fixture", "analyst_selected"]


@dataclass(frozen=True)
class OpenDatabaseEvidence(Model):
    """IDA-observed identity used to select one exact frozen route."""

    binary_digest: str
    processor: str
    bits: int
    data_endian: Endian
    format_id: FormatId
    ida_build: str
    hexrays_build: str
    schema_version: Literal[1] = 1

    def __post_init__(self) -> None:
        super().__post_init__()
        check_digest(self.binary_digest)
        nonempty(self.processor)
        nonempty(self.ida_build)
        nonempty(self.hexrays_build)
        require(self.bits in (32, 64), "Unsupported database bitness")


@dataclass(frozen=True)
class FrozenProfileEvidence(Model):
    """Minimal source-packaged binding to one accepted semantic receipt."""

    profile_id: str
    abi_id: str
    format_id: FormatId
    platform_tag: str
    processor: str
    instruction_endian: Endian
    binary_digest: str
    build_row_digest: str
    p0_receipt: str
    p0_mmat_calls_digest: str
    registry_digest: str
    profile_digest: str
    semantic_receipt_digest: str
    semantic_receipt_file: str
    evidence_path: Literal["normal", "format"]
    ida_build: str = "9.3"
    hexrays_build: str = "9.3.0.260213"
    schema_version: Literal[1] = 1

    def __post_init__(self) -> None:
        super().__post_init__()
        for value in (
            self.profile_id,
            self.abi_id,
            self.platform_tag,
            self.processor,
            self.p0_receipt,
            self.semantic_receipt_file,
            self.ida_build,
            self.hexrays_build,
        ):
            nonempty(value)
        for value in (
            self.binary_digest,
            self.build_row_digest,
            self.p0_mmat_calls_digest,
            self.registry_digest,
            self.profile_digest,
            self.semantic_receipt_digest,
        ):
            check_digest(value)
        spec = REGISTRY.get(self.profile_id)
        require(self.abi_id in spec.abi_ids, "Frozen route ABI/profile mismatch")

    @property
    def observed_identity(self) -> tuple[str, int, Endian, FormatId, str, str]:
        spec = REGISTRY.get(self.profile_id)
        return (
            self.processor,
            spec.bitness,
            spec.data_endian,
            self.format_id,
            self.ida_build,
            self.hexrays_build,
        )

    def extraction_profile(self) -> tuple[dict, ProfileRegistry]:
        """Rebuild and verify the exact ephemeral registry/profile pair."""

        target = REGISTRY.get(self.profile_id)
        measured = MeasuredReceipt(
            self.p0_receipt,
            "success",
            "MMAT_CALLS",
            self.p0_mmat_calls_digest,
            True,
            True,
            False,
            self.processor,
            self.abi_id,
            self.format_id,
            self.platform_tag,
            self.binary_digest,
        )
        updated = replace(
            target,
            instruction_endian=self.instruction_endian,
            format_ids=(self.format_id,),
            receipt_status="success",
            maturity="MMAT_CALLS",
            measured_receipt=measured,
        )
        registry = ProfileRegistry(
            tuple(
                updated if row.profile_id == self.profile_id else row
                for row in REGISTRY.profiles
            )
        )
        require(
            digest(registry) == self.registry_digest,
            "Frozen profile registry evidence is stale",
        )
        profile = registry.measured_extraction_profile(self.profile_id)
        profile["abi_provenance"] = {
            "kind": "measured_anchor_build",
            "manifest_sha256": MANIFEST_DIGEST.removeprefix("sha256-v1:"),
            "build_row_digest": self.build_row_digest,
            "binary_sha256": self.binary_digest.removeprefix("sha256-v1:"),
            "p0_receipt": self.p0_receipt,
            "p0_mmat_calls_digest": self.p0_mmat_calls_digest,
            "scope": "exact semantic-matrix fixture; not registry promotion",
        }
        registry.validate_extraction_profile(profile)
        require(
            digest(profile) == self.profile_digest, "Frozen profile evidence is stale"
        )
        return profile, registry


@dataclass(frozen=True)
class ResolvedProfile:
    evidence: (
        FrozenProfileEvidence
        | RegistryProfileEvidence
        | AnalystProfileEvidence
        | ReviewedFixture
    )
    profile: dict
    registry: ProfileRegistry


@dataclass(frozen=True)
class RegistryProfileEvidence:
    """Existing X64/A64 Mach-O configuration routes retained for compatibility."""

    profile_id: str
    evidence_path: Literal["registry"] = "registry"
    ida_build: str = "9.3"
    hexrays_build: str = "9.3.0.260213"

    def __post_init__(self) -> None:
        receipt = REGISTRY.get(self.profile_id).measured_receipt
        require(receipt is not None, "Registry route lacks measured evidence")

    @property
    def abi_id(self) -> str:
        receipt = REGISTRY.get(self.profile_id).measured_receipt
        if receipt is None:
            raise ContractError("Registry route lacks measured evidence")
        return receipt.abi

    @property
    def format_id(self) -> FormatId:
        receipt = REGISTRY.get(self.profile_id).measured_receipt
        if receipt is None:
            raise ContractError("Registry route lacks measured evidence")
        return receipt.format_id

    @property
    def observed_identity(self) -> tuple[str, int, Endian, FormatId, str, str]:
        spec = REGISTRY.get(self.profile_id)
        receipt = spec.measured_receipt
        if receipt is None:
            raise ContractError("Registry route lacks measured evidence")
        return (
            receipt.processor,
            spec.bitness,
            spec.data_endian,
            receipt.format_id,
            self.ida_build,
            self.hexrays_build,
        )

    def extraction_profile(self) -> tuple[dict, ProfileRegistry]:
        return REGISTRY.measured_extraction_profile(self.profile_id), REGISTRY


@dataclass(frozen=True)
class AnalystProfileEvidence:
    """Explicit analyst selection bound to the currently observed binary.

    ``source`` remains the reviewed extraction-configuration evidence. The open
    binary digest is recorded separately so arbitrary matching user binaries do
    not masquerade as the measured semantic fixture.
    """

    source: FrozenProfileEvidence
    binary_digest: str
    evidence_path: Literal["analyst_selected"] = "analyst_selected"

    def __post_init__(self) -> None:
        check_digest(self.binary_digest)
        require(
            self.source.evidence_path in ("normal", "format"),
            "analyst_selection_requires_normal_evidence",
        )

    @property
    def profile_id(self) -> str:
        return self.source.profile_id

    @property
    def abi_id(self) -> str:
        return self.source.abi_id

    @property
    def format_id(self) -> FormatId:
        return self.source.format_id

    @property
    def observed_identity(self) -> tuple[str, int, Endian, FormatId, str, str]:
        return self.source.observed_identity

    def extraction_profile(self) -> tuple[dict, ProfileRegistry]:
        profile, registry = self.source.extraction_profile()
        profile = dict(profile)
        profile["abi_provenance"] = {
            "kind": "analyst_selected_profile",
            "selected_profile_id": self.profile_id,
            "selected_abi_id": self.abi_id,
            "observed_binary_digest": self.binary_digest,
            "configuration_fixture_digest": self.source.binary_digest,
            "semantic_receipt_file": self.source.semantic_receipt_file,
            "semantic_receipt_digest": self.source.semantic_receipt_digest,
            "scope": (
                "analyst-selected profile/ABI for this exact open-binary digest; "
                "reviewed configuration evidence only, not fixture conformance or "
                "support promotion"
            ),
        }
        registry.validate_extraction_profile(profile)
        return profile, registry


REGISTRY_PROFILE_EVIDENCE = (
    RegistryProfileEvidence("X64-LE"),
    RegistryProfileEvidence("A64-LE"),
)


def _route(
    profile_id: str,
    abi_id: str,
    format_id: FormatId,
    platform_tag: str,
    processor: str,
    instruction_endian: Endian,
    binary_hex: str,
    build_row_hex: str,
    p0_receipt: str,
    p0_digest_hex: str,
    registry_hex: str,
    profile_hex: str,
    semantic_hex: str,
    semantic_receipt_file: str,
    evidence_path: Literal["normal", "format"],
) -> FrozenProfileEvidence:
    def prefixed(value: str) -> str:
        return "sha256-v1:" + value

    return FrozenProfileEvidence(
        profile_id,
        abi_id,
        format_id,
        platform_tag,
        processor,
        instruction_endian,
        prefixed(binary_hex),
        prefixed(build_row_hex),
        p0_receipt,
        prefixed(p0_digest_hex),
        prefixed(registry_hex),
        prefixed(profile_hex),
        prefixed(semantic_hex),
        semantic_receipt_file,
        evidence_path,
    )


FROZEN_PROFILE_EVIDENCE = (
    _route(
        "X86-LE",
        "sysv-i386",
        "FMT-ELF",
        "linux",
        "metapc",
        "little",
        "7aec7a326f78c7c45b93ed18d556e9c2d0a948aece7b514b9562373106ce1fd4",
        "714c6736da5d7df8ad4aff8fc30334bab01e3f4a0ab8e0d41bcfada3d5cdbaf7",
        "actual-p0/x86-le--elf--7aec7a326f78/receipt-final.json",
        "931e2aa5980d99b73911ea539f21787a42e006f8288d26136a96ac73cf602b6f",
        "e60afdd7a1fb332d86df30ad5e252c1d6b72b4e42791159d3192eeedb2c15f99",
        "3d13deddd5b703528f610e8b0d5c2c8669ccd755ab88a0554ecbb45bda5f93d6",
        "ac1418456c6fc013e5dce2225af54572f5673b4f271bf7547dedf67632bf152a",
        "tests/flow_fixtures/manifests/profile_semantics/normal/x86-le.json",
        "normal",
    ),
    _route(
        "X64-LE",
        "sysv-amd64",
        "FMT-ELF",
        "linux",
        "metapc",
        "little",
        "3f03305a9f75c223a27a657339bb3942bc72eb9d015c4d3a1760dfc3a2a1a217",
        "82176bc5f631dec4bf96e2dac594535523c4f190b7b89a526c221633e2d0994b",
        "actual-p0/x64-le--elf--3f03305a9f75/receipt-final.json",
        "d1cbb1a4da5b74ce71a36b5756a9499e24d47d7fc3dbd53b404d84433a72e5a1",
        "b5c0b2c59451064429c298244fb085c20c98ce8fe9d459a461d6ce84aa9246b0",
        "38c29a208ce6f7a315955cb2351af85171017efe123efca0501fa16b119c417e",
        "f9ef45fa374cc514e8308a43377cc96337952107e744450b4c8738c25d02c524",
        "tests/flow_fixtures/manifests/profile_semantics/normal/x64-le.json",
        "normal",
    ),
    _route(
        "ARM32-LE",
        "aapcs32",
        "FMT-ELF",
        "linux",
        "ARM",
        "little",
        "579cfc13cb9f2997bc0ba021b1fc5f60f3ed1f6c4ef9e419f9a80dfdf8fccd0e",
        "85852483821063e6936fafceb1c525bf481b61d85309fb5f7786dd9f9704d65a",
        "actual-p0/arm32-le--elf--579cfc13cb9f/receipt-final.json",
        "c3dd8a4bc35129fdd5740ba55813175b55ac5c6387b77bf7c3fcc6ab18d91c6a",
        "1c003bcd20bdb05e3662846f0e3d389bb3aebe8bb35cb4c23d9a2692773e08a0",
        "dedcd13ce59886bbbd787f2293339715e6304080706002b5b9f5ddfc04eb28af",
        "7ec30fc2df94064f4c5f573fff2dbbf7fc96cc7664774e7e3b184daeb4fb545d",
        "tests/flow_fixtures/manifests/profile_semantics/normal/arm32-le.json",
        "normal",
    ),
    _route(
        "ARM32-BE",
        "aapcs32",
        "FMT-ELF",
        "linux",
        "ARMB",
        "little",
        "30bd4b5028ac319ffa54df7cf24d48c3f4b94e7c09bea85a19fcba372f9ca1e2",
        "997f173d106e2136f0277871767f6b3e063e8c377c8e1b420adbb9f164d61a49",
        "actual-p0/arm32-be--elf--30bd4b5028ac/receipt-final.json",
        "06017beb866f2500537f06f073563f827cffce10e990a3522ddd52479c23d68e",
        "8972df3ebdde648c40b195e4d53d94ddb8d4cc1f144e444342ba4de7e911b370",
        "545f50d0fcf1cdeee7088293eacca0f33a3c357727948ff651b9caaf2eaaf9e3",
        "e934e019126253c8ab3efe1433760a0aae775186310f68c7dbba3567c69a0981",
        "tests/flow_fixtures/manifests/profile_semantics/normal/arm32-be.json",
        "normal",
    ),
    _route(
        "THUMB-LE",
        "aapcs32",
        "FMT-ELF",
        "linux",
        "ARM",
        "little",
        "0c05feec880d8fa13a7dfa8cde22a1e8773762767e490e9e8641f2650d281296",
        "6e02afe231c8c06a9ebd7204d070ba053810f7ac091bc24e6a8d39e481a02001",
        "actual-p0/thumb-le--elf--0c05feec880d/receipt-final.json",
        "971e5f9fe5caee10bfd5ab0f267cb3cacd160f123c76b3e86f4982f74e511574",
        "2502ee27d9ee14bc6d38c2175e6e81e611aa2cb89544d021fd9c813d9c0d59af",
        "b01e9d45e61103d203a3d1b4b151acde4971741381386b90d3d618e7ff8dc943",
        "faca12025758bfb80c97de1c9cb73571a867b7e46edd0e2decdde3d86f2b8312",
        "tests/flow_fixtures/manifests/profile_semantics/normal/thumb-le.json",
        "normal",
    ),
    _route(
        "THUMB-BE",
        "aapcs32",
        "FMT-ELF",
        "linux",
        "ARMB",
        "little",
        "b34e4c4a88f79d98caa726b11cd9a2d66579aa74dcf263fd1c49748bf6f86d6f",
        "0818f6476f8630c9cab358e492510b82df8a98e2802a72cad6e7c6bdb51591bc",
        "actual-p0/thumb-be--elf--b34e4c4a88f7/receipt-final.json",
        "30b3993869c5d09882094cca5a725e6df8c83f982f40d7f9b2da8a051559eb11",
        "b0040c7e5d59f8bf0a23ef3cde85155f0c33bff96d0c3ca421bed0f1a2748656",
        "0720ba4a23385b865fdc0318ad5cbcf929f0255f2a7f4a758044d7e0939b737f",
        "4e661ba79d9bb9a34030dfd075c21a39b9ff5cc38dd69e8d1f37e0334afd3b1d",
        "tests/flow_fixtures/manifests/profile_semantics/normal/thumb-be.json",
        "normal",
    ),
    _route(
        "A64-LE",
        "aapcs64",
        "FMT-ELF",
        "linux",
        "ARM",
        "little",
        "a540f9d5a4ae2fa945355e167dcb2a9ef941668697df680cc8d7a19f4282d16d",
        "ad04b3c26686f3f61a22900480eba73ad30eb835305b3b8c726ad0ad009f2d4d",
        "actual-p0/a64-le--elf--a540f9d5a4ae/receipt-final.json",
        "4a3da92031a8afa657eceeadee3950d82a33aafdf459ba315ce3307bc06de16c",
        "11899fa4f0117e78457796df4bf6a81301fa9fa3b1f2c7a9483807259004fabe",
        "c07dad395fd615a9567e9a8885103454bb24877fa95a434cdc9db5f61b90b603",
        "01a821b76c3d5e833eb795e27859bca25d373ae6740dad8ab7b975aeeb75bbc7",
        "tests/flow_fixtures/manifests/profile_semantics/normal/a64-le.json",
        "normal",
    ),
    _route(
        "MIPS32-LE",
        "mips-o32",
        "FMT-ELF",
        "linux",
        "mipsl",
        "little",
        "07455c1d91d89e8d0b4d5cb84de3a0bd9f77f93819578f3070fd04c8f4ddbb04",
        "707aa301fc48ba1e2ba0647214487f082469e6097b543aaa7615c3a63f0d9f1c",
        "actual-p0/mips32-le--elf--07455c1d91d8/receipt-final.json",
        "edcd8694ac9da51bdaf845e79d7e86149acbd6ab6cf57ee8877ed7517ef30ff6",
        "975790d20cbd1b97c9d3563215ac09483b3fe6250ad7309215feb9179f44f581",
        "0e0dcdc2ae3aabdaf4d49bf38d98bb8c610b5033123f5d4d6a016f904716aaf2",
        "0043318091ecc9eb946743330a038cbc15eadc5d3132f22333f1f761bd94f265",
        "tests/flow_fixtures/manifests/profile_semantics/normal/mips32-le.json",
        "normal",
    ),
    _route(
        "MIPS32-BE",
        "mips-o32",
        "FMT-ELF",
        "linux",
        "mipsb",
        "big",
        "257f5bdbc40d8d57051f9e374dd38415c89d9361e27213b1626f17aa88e61c1d",
        "faf587daa9b18cc7dfc9423c794d55a4684aeba76f87dc6b1ce8ac85e13a2faf",
        "actual-p0/mips32-be--elf--257f5bdbc40d/receipt-final.json",
        "b3da91b39b9e38418ac78ded6bb34dacab4fd35030669b80883412f267d6edf5",
        "fa27f70d60fd8b51897adeac15a5b7a47a84abeba50d031559be7eb4fbefa997",
        "d4ba37cef664fef92491fc13af0decd186d68132a3150fab0f3490381fc5b2e8",
        "aa5869201092fa2e63f7ae735c3a5648064bb11bc83ab82bfea59e98c0cbed51",
        "tests/flow_fixtures/manifests/profile_semantics/normal/mips32-be.json",
        "normal",
    ),
    _route(
        "MIPS64-LE",
        "mips-n64",
        "FMT-ELF",
        "linux",
        "mipsl",
        "little",
        "d2bdf5ab6f0db1f261c29634a36b4a96e597e6409041c7a30244837cbc7ff4db",
        "c2dd294fb0842b760f8f3541e73c3525fdb48b7785ab4aad2b33d3f554eb1fc0",
        "actual-p0/mips64-le--elf--d2bdf5ab6f0d/receipt-final.json",
        "b69a5a93c5fea7df450a250057183fc3ea73595b259ca2024d7b47597ee546f1",
        "fae2f2e694651d297d6e349f5e71aa745b561c5eab504355ffecf673a388f5f0",
        "531868cab980b8314c2339cc7ae810705ef419ec838149b4f4c32d95124c5c2a",
        "a34b5f6b55b96a6516d2813c79fb3893a8e9c2254f3e78cdf8214d2d6f3b53b6",
        "tests/flow_fixtures/manifests/profile_semantics/normal/mips64-le.json",
        "normal",
    ),
    _route(
        "MIPS64-BE",
        "mips-n64",
        "FMT-ELF",
        "linux",
        "mipsb",
        "big",
        "0e2751aafabf92a83158e29d67a494f961a787127c7f12ae13beecebc4276661",
        "242c276f13222a83f36ec86db446e6559f7380cda919ed650a8b33cde89773aa",
        "actual-p0/mips64-be--elf--0e2751aafabf/receipt-final.json",
        "85e8f4a59ca7b721fae42a270b246dd7b706ebf1abb91216f267a14fd2b66261",
        "8a53badf980eaf733854c2625e2b6ef10c539a1f995b2460f1b9dff7115e07d2",
        "119462be3741b873f47d7de426f35b8e3bb1e0701ce3dcba0591ec92960c937c",
        "d2fdcadcf3f256b0e9839184ba9238c8b5923363646a597bf2965bf14c78dbe5",
        "tests/flow_fixtures/manifests/profile_semantics/normal/mips64-be.json",
        "normal",
    ),
    _route(
        "PPC32-LE",
        "sysv-ppc32",
        "FMT-ELF",
        "linux",
        "PPCL",
        "little",
        "016efe8c142a8a9aa9c854f5113a66eeb8b87f39352b4defe343ae6c77423c1f",
        "30da3cf37d48af785c4273c5351648c84e57c8043a0ecc39da3004ffa2fffdfd",
        "actual-p0/ppc32-le--elf--016efe8c142a/receipt-final.json",
        "88b97db97eb41a0fb4004ecdb979be35789d8b54bb12b429615e3ace3351fe5b",
        "d7239bee2873f0cc2df0072fee1af3e70b1dac137e9b3747fde72f6b4e223580",
        "769792f2b93b84ef14dd87a04374c5c9362dad9659deb04e5e0ea4c3b629d957",
        "6fcab81bebc4083d188c16467fe7edc8676e1ad1e14b186495dcc7a7f0c66214",
        "tests/flow_fixtures/manifests/profile_semantics/normal/ppc32-le.json",
        "normal",
    ),
    _route(
        "PPC32-BE",
        "sysv-ppc32",
        "FMT-ELF",
        "linux",
        "PPC",
        "big",
        "5b2c0bddb982538eb73e708c0695e53807945f4b6caf3b54910016c37eb9889b",
        "6cc7672ef2274cc4a56aa6a85f5598025924758e252c371718c5aeb465d84d6c",
        "actual-p0/ppc32-be--elf--5b2c0bddb982/receipt-final.json",
        "9ade23c75f58c2e583ee9ab6a38714e5ffa14cf6ad11eda90728c27534949c38",
        "f9463d7b694f5c96c6b9c0ce0e3d8ce367f3b3f022c36311f32ec560bacdf86d",
        "6ec83facfbfec38fa4c4ad34c9e36d4eeecdcb67a98da4a9a07c6b97063e7a10",
        "6fb68fe9df67317ff3bde784302e06c56a635b65c1ef88a18db505b2d46ea1c7",
        "tests/flow_fixtures/manifests/profile_semantics/normal/ppc32-be.json",
        "normal",
    ),
    _route(
        "PPC64-LE",
        "elfv2-ppc64",
        "FMT-ELF",
        "linux",
        "PPCL",
        "little",
        "c4da59435feaba1a73ae4f7987c246aba819d56ed57a2f745833bf9146465c67",
        "f5e30d3ac05e6c55ef112ce728b8a284ede6fb953db68b5bcf9288250f35c82b",
        "actual-p0/ppc64-le--elf--c4da59435fea/receipt-final.json",
        "c642d8521a197f16f24e2e5cca2dd7f45494cf17038fb081b934b31e16e7ef51",
        "0aebe6e9911871aba0762215c4462868df1df813cc92f8c99c980b7a9a0749de",
        "014dd3f22e5a2b4c6e56d79c3692830349f42f8a0335f0c06736be23f08aa65c",
        "8895d1627afaa2760f25329dcf4c3f916a561b55ccef4cf1d8f9a0b639f32c94",
        "tests/flow_fixtures/manifests/profile_semantics/normal/ppc64-le.json",
        "normal",
    ),
    _route(
        "PPC64-BE",
        "elfv2-ppc64",
        "FMT-ELF",
        "linux",
        "PPC",
        "big",
        "7a35c6ae7a3f87fd32b389419d3da977fea05eeadacd39b45bede52550589af7",
        "f5aad98a2d4eb61e4bc6876058ded4809b91c6781bd1d7c2b0cd1b0b4e006c17",
        "actual-p0/ppc64-be--elf--7a35c6ae7a3f/receipt-final.json",
        "ece8a0225173a3354d8fd506d90ea0ad675dad1bb3324a112bee7f75e59a2349",
        "fb77abf6b7b324b139f3b6095b9efa0353cf8d6e6d8a130358c68b1d58647273",
        "51a1e53f0d830e6bb3fd1ca7133579c429a44ac28b1b482bf5aa66fbd7aac054",
        "625a20deafd03e95952937c88aca14f7bfc29080dd722c2d1d98051ca8c4a22d",
        "tests/flow_fixtures/manifests/profile_semantics/normal/ppc64-be.json",
        "normal",
    ),
    _route(
        "RV64-LE",
        "riscv-lp64",
        "FMT-ELF",
        "linux",
        "riscv",
        "little",
        "6a9a51949d884723d71b027b488354f2b7fadfb403a5bc2041615a6ccb50279f",
        "c493384da46b155f8556c3b3d491ec513eba174eda5ea9defd598e4d7f343150",
        "actual-p0/rv64-le--elf--6a9a51949d88/receipt-final.json",
        "5334d514b8a3fbca87f9468427ef17b968e3829d64696fd5cacfe3d91063298f",
        "7249792892e84f9e94a399ec699cd07f6829baef8686f5d17725941bd8127878",
        "e6667866fa9466912def4483f20a4a9fc198d95864b08ea5b3494b5005dc3288",
        "ceba2336924796327c0bedebd0a10b4afa1c7e0396767354f759fa26623e8b6e",
        "tests/flow_fixtures/manifests/profile_semantics/normal/rv64-le.json",
        "normal",
    ),
    _route(
        "X64-LE",
        "windows-x64",
        "FMT-PE",
        "windows",
        "metapc",
        "little",
        "5c5cbc1b4029053029df20896ac57dfda06619f8d0dbd0afa3c1e3b77819a171",
        "4f0dc2dcc314db5293b576ac8d2adb1f41bd54b040547f900eb62db62380265e",
        "actual-p0/x64-le--pe--5c5cbc1b4029/receipt-final.json",
        "203155ea88966537a16d6766b0cb4d4895a0be80504b42131fb4d52307cec8eb",
        "041b074a7db2d397bad0f565b59f9abfa0047e01f179c25ebea23973fca0ad72",
        "2cc0726e7a5900f8f7aff7d176078c591994efba622db4d2d621b8d098e80d15",
        "138a3b6e6de29530141c2633631ddfb7aa6faf6330205424bef1722ec97d9121",
        "tests/flow_fixtures/manifests/profile_semantics/formats/x64-le--pe.json",
        "format",
    ),
    _route(
        "ARM32-LE",
        "aapcs32",
        "FMT-RAW",
        "bare",
        "ARM",
        "little",
        "43b1047885a3772b1926c467317139c3fa91222c48f7c4539893b4af12d3b285",
        "2a854ba00f00a44102d8f25dd653156420803c5cbb08612b67805c8c0a40c94d",
        "actual-p0/arm32-le--raw--43b1047885a3/receipt-final.json",
        "87602026780677c06e2f84884bb442411c731cf4e32334404aa61819d623c5c3",
        "741e6588f08078f9ac842cac36152ff80c4d2c43ae54948bf335caa69dbed21c",
        "422ae92311c077b09e5b11aef423ad8a8b090794c9ec217e695e64920d861709",
        "d771194e47db87401e09489086bd5db687de51e98615ebb6787e6799cc2b8311",
        "tests/flow_fixtures/manifests/profile_semantics/formats/arm32-le--raw.json",
        "format",
    ),
    _route(
        "X64-LE",
        "darwin-x86_64-sysv-derived",
        "FMT-MACHO",
        "darwin",
        "metapc",
        "little",
        "25ae3f21eb437e6577ae4cbff3f639db50d8e621f795f82ec5978f8b896f6622",
        "ef067f3c3e5b0fc68599b684f62c5f09098825e2d8bcd948d54bb28c8eea78d5",
        "actual-p0/x64-le--macho--25ae3f21eb43/receipt-final.json",
        "10ca27013c8fab566c60fdfa10d7c7f27fc3e64c680c6701e053b36ac28f827a",
        "10890f124c39968d77c9e4b0d340a133cbd1f78dad1e7aee1cc9800865b0c745",
        "e6b18cc2697959ac37c53118836ec466d93bc5c7ac18dc06f45d173d5fadc9b4",
        "a1140b0e9a7c5248074d9ee21797ec81c161de4b06eb315728f336e69e623eb2",
        "tests/flow_fixtures/manifests/profile_semantics/formats/x64-le--macho.json",
        "format",
    ),
    _route(
        "A64-LE",
        "darwin-aarch64",
        "FMT-MACHO",
        "darwin",
        "ARM",
        "little",
        "ada0029630104cfd87c19b6534ac05615b802f1315302b2a53a1954942382d25",
        "09c63ddae832b5b4c2961359facd769d363404c53fbd3612b3de9352858f16c6",
        "actual-p0/a64-le--macho--ada002963010/receipt-final.json",
        "aafe7e77bbedad33e48fc3d292af77eb4a43f3c1919d81405707aa1af8078459",
        "479fceff56f72ec1fb07c8f7ea3cf94c855b272ad243458d0904847a27ecd713",
        "e370fced2092e9b29ece42ec15786c50b49f545c57808310c4d8ccc95173ea1d",
        "31e97769d345c596e35907aecef28b134715ddd6c21a2c0fed46c603f2a6775c",
        "tests/flow_fixtures/manifests/profile_semantics/formats/a64-le--macho.json",
        "format",
    ),
)


def resolve_open_database_profile(
    observed: OpenDatabaseEvidence,
    requested_profile: str | None = None,
    requested_abi: str | None = None,
    routing_mode: RoutingMode = "exact_fixture",
) -> ResolvedProfile:
    """Resolve one route or fail closed without guessing an ABI/profile."""

    require(
        routing_mode in ("exact_fixture", "analyst_selected"),
        "invalid_profile_routing_mode",
    )
    if routing_mode == "analyst_selected":
        require(
            type(requested_profile) is str and bool(requested_profile),
            "analyst_profile_required",
        )
        require(
            type(requested_abi) is str and bool(requested_abi),
            "analyst_abi_required",
        )
        candidates = tuple(
            item
            for item in FROZEN_PROFILE_EVIDENCE
            if item.profile_id == requested_profile
            and item.abi_id == requested_abi
            and item.observed_identity
            == (
                observed.processor,
                observed.bits,
                observed.data_endian,
                observed.format_id,
                observed.ida_build,
                observed.hexrays_build,
            )
        )
        require(bool(candidates), "analyst_profile_evidence_mismatch")
        require(len(candidates) == 1, "ambiguous_profile_evidence")
        selected = AnalystProfileEvidence(candidates[0], observed.binary_digest)
        profile, registry = selected.extraction_profile()
        return ResolvedProfile(selected, profile, registry)

    matches = tuple(
        item
        for item in (*FROZEN_PROFILE_EVIDENCE, *REVIEWED_FIXTURES)
        if item.binary_digest == observed.binary_digest
    )
    if matches:
        require(len(matches) == 1, "ambiguous_profile_evidence")
        evidence: FrozenProfileEvidence | RegistryProfileEvidence | ReviewedFixture = (
            matches[0]
        )
        require(
            (
                observed.processor,
                observed.bits,
                observed.data_endian,
                observed.format_id,
                observed.ida_build,
                observed.hexrays_build,
            )
            == evidence.observed_identity,
            "profile_evidence_mismatch",
        )
    else:
        raise ContractError("experimental_profile_unavailable")
    require(
        requested_profile in (None, evidence.profile_id),
        "profile_mismatch",
    )
    require(requested_abi in (None, evidence.abi_id), "abi_mismatch")
    profile, registry = evidence.extraction_profile()
    return ResolvedProfile(evidence, profile, registry)


__all__ = [
    "FROZEN_PROFILE_EVIDENCE",
    "MANIFEST_DIGEST",
    "REGISTRY_PROFILE_EVIDENCE",
    "AnalystProfileEvidence",
    "FrozenProfileEvidence",
    "OpenDatabaseEvidence",
    "RegistryProfileEvidence",
    "ResolvedProfile",
    "RoutingMode",
    "resolve_open_database_profile",
]
