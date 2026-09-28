"""Device ACL audit over IoCreateDevice(Secure) call sites (read-only).

Mirrors the reference device-create audit: ``IoCreateDevice`` creates devices
with a default (typically weak) ACL, while ``IoCreateDeviceSecure`` takes an
SDDL descriptor that may still grant broad access. Findings are review leads:
the actual runtime ACL depends on the OS version and call arguments.
"""

from __future__ import annotations

import idaapi
import idc

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    expired,
    func_name,
    import_call_sites,
    read_best_string,
)

#: Back-walk budget when resolving an SDDL argument.
_SDDL_LOOKBACK = 32


def _looks_like_sddl(text: str) -> bool:
    head = text.strip()[:2]
    return head in core.SDDL_PREFIXES


def _resolve_sddl(site: int) -> tuple[str | None, str | None]:
    """Best-effort SDDL string resolution near a call site."""
    try:
        func = idaapi.get_func(site)
        func_start = func.start_ea if func else 0
    except Exception:
        func_start = 0
    cursor = site
    for _ in range(_SDDL_LOOKBACK):
        try:
            cursor = idc.prev_head(cursor, func_start)
        except Exception:
            break
        if cursor == idaapi.BADADDR or cursor <= func_start:
            break
        try:
            mnem = idc.print_insn_mnem(cursor)
        except Exception:
            continue
        if mnem not in ("lea", "mov", "push"):
            continue
        for operand in (0, 1):
            try:
                target = int(idc.get_operand_value(cursor, operand))
            except Exception:
                continue
            if target in (0, idaapi.BADADDR):
                continue
            text = read_best_string(target)
            if text and _looks_like_sddl(text):
                return text, hex(target)
    return None, None


def audit(ctx: DriverContext) -> tuple[list[dict], dict]:
    """Audit device-creation call sites for ACL review leads."""
    leads: list[dict] = []
    stats = {"create_device": 0, "create_device_secure": 0, "world_sddl": 0}
    for import_ea in ctx.imports_map.get("IoCreateDevice", []):
        sites = import_call_sites(import_ea)
        for site in sites:
            if expired():
                ctx.limitations.append("ACL audit hit the tool deadline (partial)")
                return leads, stats
            stats["create_device"] += 1
            leads.append(
                core.ReviewLead(
                    check="device_acl",
                    severity=core.SEV_MEDIUM,
                    title="IoCreateDevice without explicit security descriptor",
                    detail=(
                        "Device created with the default ACL; verify no "
                        "IoCreateDeviceSecure/SDDL hardening applies."
                    ),
                    function=func_name(site),
                    addr=hex(site),
                    evidence={"api": "IoCreateDevice"},
                    method="import xref enumeration",
                ).as_dict()
            )
    for import_ea in ctx.imports_map.get("IoCreateDeviceSecure", []):
        sites = import_call_sites(import_ea)
        for site in sites:
            if expired():
                ctx.limitations.append("ACL audit hit the tool deadline (partial)")
                return leads, stats
            stats["create_device_secure"] += 1
            sddl, sddl_addr = _resolve_sddl(site)
            if sddl is None:
                leads.append(
                    core.ReviewLead(
                        check="device_acl",
                        severity=core.SEV_MEDIUM,
                        title="IoCreateDeviceSecure with unresolved SDDL",
                        detail="SDDL argument could not be resolved statically; review manually.",
                        function=func_name(site),
                        addr=hex(site),
                        evidence={"api": "IoCreateDeviceSecure"},
                        method=f"back-walk up to {_SDDL_LOOKBACK} instructions",
                    ).as_dict()
                )
                continue
            world = sorted(s for s in core.WORLD_SIDS if s in sddl)
            if world:
                stats["world_sddl"] += 1
                leads.append(
                    core.ReviewLead(
                        check="device_acl",
                        severity=core.SEV_HIGH,
                        title="IoCreateDeviceSecure with broadly accessible SDDL",
                        detail=f"SDDL grants access to {', '.join(world)}: {sddl}",
                        function=func_name(site),
                        addr=hex(site),
                        evidence={"api": "IoCreateDeviceSecure", "sddl": sddl},
                        method="SDDL string match for world SIDs",
                    ).as_dict()
                )
            else:
                leads.append(
                    core.ReviewLead(
                        check="device_acl",
                        severity=core.SEV_INFO,
                        title="IoCreateDeviceSecure with explicit SDDL",
                        detail=f"SDDL present; confirm it matches intent: {sddl}",
                        function=func_name(site),
                        addr=hex(site),
                        evidence={"api": "IoCreateDeviceSecure", "sddl": sddl},
                        method="SDDL string resolution",
                    ).as_dict()
                )
    if stats["create_device"] or stats["create_device_secure"]:
        ctx.limitations.append(
            "ACL leads are static approximations; the effective runtime ACL is unknown"
        )
    return leads, stats
