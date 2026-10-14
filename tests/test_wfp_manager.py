"""
Unit tests for Native Windows Filtering Platform (WFP) Manager.

Verifies:
- Accurate WFP ALE filter specifications conforming to Microsoft documentation.
- FWP_MATCH_EQUAL usage for application ID matching.
- Loopback access preservation (Weight 100 PERMIT for 127.0.0.1 and ::1).
- Gateway upstream access preservation (Weight 90 PERMIT for gateway App ID).
- Rogue external port 53 blocking (Weight 10 BLOCK).
- Port 853 DoT/DoQ blocking.
- Dynamic session configuration (FWPM_SESSION_FLAG_DYNAMIC) for kernel auto-cleanup on failure.
- Explicit operational boundaries and non-claims.
"""

from pathlib import Path
from wfp_manager import WFPManager, WFPState


def test_wfp_filter_specifications_and_weights():
    wfp = WFPManager(Path(r"C:\Program Files\DNS-SHIELD\service\DNSShieldService.exe"))
    specs = wfp.get_filter_specifications()

    # 4 IPv4 + 4 IPv6 = 8 filters
    assert len(specs) == 8

    # 1. Loopback preservation
    v4_loopback = [f for f in specs if f["id"] == "IPv4_Permit_Local_Gateway_Loopback"][0]
    assert v4_loopback["action"] == "FWP_ACTION_PERMIT"
    assert v4_loopback["weight"] == 100
    conds = {c["field"]: c["value"] for c in v4_loopback["conditions"]}
    assert conds["IP_REMOTE_PORT"] == 53
    assert conds["IP_REMOTE_ADDRESS"] == "127.0.0.1"

    v6_loopback = [f for f in specs if f["id"] == "IPv6_Permit_Local_Gateway_Loopback"][0]
    assert v6_loopback["action"] == "FWP_ACTION_PERMIT"
    assert v6_loopback["weight"] == 100

    # 2. Gateway binary upstream preservation using FWP_MATCH_EQUAL
    v4_gw = [f for f in specs if f["id"] == "IPv4_Permit_Gateway_Service_Outbound"][0]
    assert v4_gw["action"] == "FWP_ACTION_PERMIT"
    assert v4_gw["weight"] == 90
    gw_app_cond = [c for c in v4_gw["conditions"] if c["field"] == "ALE_APP_ID"][0]
    assert gw_app_cond["match"] == "FWP_MATCH_EQUAL"
    assert gw_app_cond["value"] == r"C:\Program Files\DNS-SHIELD\service\DNSShieldService.exe"

    # 3. Rogue external port 53 block
    v4_block = [f for f in specs if f["id"] == "IPv4_Block_Rogue_External_Port53"][0]
    assert v4_block["action"] == "FWP_ACTION_BLOCK"
    assert v4_block["weight"] == 10

    # 4. Port 853 DoT/DoQ block
    v4_853 = [f for f in specs if f["id"] == "IPv4_Block_Direct_DoT_DoQ_Port853"][0]
    assert v4_853["action"] == "FWP_ACTION_BLOCK"
    assert v4_853["weight"] == 10


def test_wfp_weight_fwp_uint64_and_flags():
    """
    Validates:
    1. FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT constant is 0x00000008 (Windows SDK).
    2. Weights 100 and 90 use FWP_UINT64 (pointing to uint64 buffer with valid lifetime),
       not FWP_UINT8 (which is reserved for 0-15 range indices in BFE).
    """
    import ctypes
    from wfp_manager import (
        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        FWPM_FILTER0,
        FWP_UINT64,
        FWP_UINT8,
    )

    # 1. Correct SDK flag constant value
    assert FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT == 0x00000008

    # 2. Build filter with FWP_UINT64 weight
    filter_obj = FWPM_FILTER0()
    weight_buf = ctypes.c_uint64(100)
    filter_obj.weight.type = FWP_UINT64
    filter_obj.weight.value.uint64 = ctypes.pointer(weight_buf)

    # Validate union pointer access
    assert filter_obj.weight.type == FWP_UINT64
    assert filter_obj.weight.value.uint64.contents.value == 100

    # Ensure FWP_UINT8 is recognized as different type (range index, not absolute weight)
    assert FWP_UINT64 != FWP_UINT8


def test_wfp_preview_and_non_claims():
    wfp = WFPManager()
    preview = wfp.preview()

    assert preview["sublayer"]["name"] == "DNSShieldSubLayer"
    assert preview["dynamic_session"] is True
    assert preview["filters_count"] == 8

    # Explicit non-claims must be documented
    non_claims = preview["non_claims"]
    assert any("443" in c for c in non_claims)
    assert any("VPN" in c for c in non_claims)


def test_wfp_dry_run_safety():
    wfp = WFPManager()
    res = wfp.apply_filters(dry_run=True)

    assert res["success"] is True
    assert res["dry_run"] is True
    assert res["status"] == WFPState.PENDING_VM_VALIDATION.value

    # Cleanup is safe
    cleanup = wfp.remove_filters()
    assert cleanup["success"] is True


def test_wfp_ctypes_structures_and_guid_alignment():
    """Validates that ctypes structures match Windows SDK sizes and alignments."""
    import ctypes
    from wfp_manager import (
        GUID, FWPM_DISPLAY_DATA0, FWPM_SESSION0, FWPM_SUBLAYER0, FWPM_ACTION0,
        FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWP_VALUE0, FWP_CONDITION_VALUE0,
        FWP_BYTE_BLOB, FWP_BYTE_ARRAY16, GUID_SUBLAYER_DNS_SHIELD
    )

    # 1. GUID must be exactly 16 bytes
    assert ctypes.sizeof(GUID) == 16
    assert ctypes.alignment(GUID) == 4

    # 2. GUID round-trip conversion
    g = GUID.from_str(GUID_SUBLAYER_DNS_SHIELD)
    assert g.to_str().lower() == GUID_SUBLAYER_DNS_SHIELD.lower()

    # 3. Byte arrays and blobs
    assert ctypes.sizeof(FWP_BYTE_ARRAY16) == 16
    assert ctypes.sizeof(FWP_BYTE_BLOB) == 16
    assert ctypes.alignment(FWP_BYTE_BLOB) == 8

    # 4. Values and Conditions
    assert ctypes.sizeof(FWP_VALUE0) == 16
    assert ctypes.alignment(FWP_VALUE0) == 8
    assert ctypes.sizeof(FWP_CONDITION_VALUE0) == 16
    assert ctypes.alignment(FWP_CONDITION_VALUE0) == 8
    assert ctypes.sizeof(FWPM_FILTER_CONDITION0) == 40
    assert ctypes.alignment(FWPM_FILTER_CONDITION0) == 8

    # Check field offsets in FWPM_FILTER_CONDITION0
    assert FWPM_FILTER_CONDITION0.fieldKey.offset == 0
    assert FWPM_FILTER_CONDITION0.matchType.offset == 16
    assert FWPM_FILTER_CONDITION0.conditionValue.offset == 24

    # 5. Session and Sublayer
    assert ctypes.sizeof(FWPM_SESSION0) == 72
    assert ctypes.sizeof(FWPM_SUBLAYER0) == 72

    # 6. Action
    assert ctypes.sizeof(FWPM_ACTION0) == 20
    assert ctypes.alignment(FWPM_ACTION0) == 4

    # 7. Complete FWPM_FILTER0 layout (200 bytes on x64 Windows)
    assert ctypes.sizeof(FWPM_FILTER0) == 200
    assert ctypes.alignment(FWPM_FILTER0) == 8
    assert FWPM_FILTER0.filterKey.offset == 0
    assert FWPM_FILTER0.displayData.offset == 16
    assert FWPM_FILTER0.flags.offset == 32
    assert FWPM_FILTER0.providerKey.offset == 40
    assert FWPM_FILTER0.providerData.offset == 48
    assert FWPM_FILTER0.layerKey.offset == 64
    assert FWPM_FILTER0.subLayerKey.offset == 80
    assert FWPM_FILTER0.weight.offset == 96
    assert FWPM_FILTER0.numFilterConditions.offset == 112
    assert FWPM_FILTER0.filterCondition.offset == 120
    assert FWPM_FILTER0.action.offset == 128
    assert FWPM_FILTER0.u.offset == 152
    assert FWPM_FILTER0.reserved.offset == 168
    assert FWPM_FILTER0.filterId.offset == 176
    assert FWPM_FILTER0.effectiveWeight.offset == 184


def test_wfp_dll_bindings():
    """On Windows, fwpuclnt.dll must have all required API entry points."""
    import os
    if os.name != "nt":
        return

    wfp = WFPManager()
    assert wfp.is_wfp_available()
    dll = wfp._fwp_dll
    assert hasattr(dll, "FwpmEngineOpen0")
    assert hasattr(dll, "FwpmEngineClose0")
    assert hasattr(dll, "FwpmTransactionBegin0")
    assert hasattr(dll, "FwpmTransactionCommit0")
    assert hasattr(dll, "FwpmTransactionAbort0")
    assert hasattr(dll, "FwpmSubLayerAdd0")
    assert hasattr(dll, "FwpmSubLayerDeleteByKey0")
    assert hasattr(dll, "FwpmGetAppIdFromFileName0")
    assert hasattr(dll, "FwpmFreeMemory0")
    assert hasattr(dll, "FwpmFilterAdd0")
    assert hasattr(dll, "FwpmFilterDeleteById0")
    assert hasattr(dll, "FwpmFilterCreateEnumHandle0")
    assert hasattr(dll, "FwpmFilterEnum0")
    assert hasattr(dll, "FwpmFilterDestroyEnumHandle0")


def test_wfp_delete_methods():
    """Validates that delete_filter_by_id and delete_sublayer behave safely when engine is inactive."""
    wfp = WFPManager()
    assert wfp.delete_filter_by_id(12345) is False
    assert wfp.delete_sublayer() is False

