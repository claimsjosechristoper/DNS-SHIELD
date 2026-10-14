"""
Windows Filtering Platform (WFP) Native Bypass Prevention Manager.

Provides executable user-mode WFP filter management via fwpuclnt.dll
to prevent rogue processes from bypassing the local DNS resolver while
guaranteeing that:
1. Local applications can reach the local listener (127.0.0.1 / ::1 on port 53).
2. The DNS-SHIELD service binary can reach configured external upstreams.
3. Rogue direct port 53 queries (IPv4/IPv6, UDP/TCP) to public resolvers are blocked.
4. Direct port 853 queries (DoT / DoQ) are blocked.

Windows SDK Architecture & Conformant ctypes Definitions:
- Sublayer creation via FwpmSubLayerAdd0.
- Application ID normalization via FwpmGetAppIdFromFileName0 with proper FwpmFreeMemory0 cleanup.
- Strict sublayer weight arbitration using FWP_MATCH_EQUAL (Loopback: 100, Gateway: 90, Block: 10).
- Atomic transaction boundaries (FwpmTransactionBegin0 / Commit0 / Abort0).
- Filter enumeration via FwpmFilterCreateEnumHandle0 / FwpmFilterEnum0 / FwpmFilterDestroyEnumHandle0.
- Dynamic session registration (FWPM_SESSION_FLAG_DYNAMIC) for automatic kernel cleanup on service termination.

Safety Policy:
By default, operations run in dry-run mode. Live filter installation requires
explicit dry_run=False inside an authorized disposable VM environment.
"""

import ctypes
from ctypes import wintypes
import enum
import ipaddress
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("DNSShield.WFPManager")

# --- WFP Constants (fwpmu.h / fwptypes.h) ---
FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 0x00000008

FWP_ACTION_PERMIT = 0x00000001
FWP_ACTION_BLOCK = 0x00000002

FWP_MATCH_EQUAL = 0
FWP_MATCH_GREATER = 1
FWP_MATCH_LESS = 2
FWP_MATCH_GREATER_OR_EQUAL = 3
FWP_MATCH_LESS_OR_EQUAL = 4
FWP_MATCH_RANGE = 5
FWP_MATCH_NOT_EQUAL = 6

# Data Types
FWP_EMPTY = 0
FWP_UINT8 = 1
FWP_UINT16 = 2
FWP_UINT32 = 3
FWP_UINT64 = 4
FWP_INT8 = 5
FWP_INT16 = 6
FWP_INT32 = 7
FWP_INT64 = 8
FWP_FLOAT = 9
FWP_DOUBLE = 10
FWP_BYTE_ARRAY16_TYPE = 11
FWP_BYTE_BLOB_TYPE = 12

# Standard WFP Layer GUIDs
GUID_ALE_AUTH_CONNECT_V4 = "{c38d57d1-05a7-4c33-904f-7fb4e73d6567}"
GUID_ALE_AUTH_CONNECT_V6 = "{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}"

# Standard WFP Condition Field GUIDs
GUID_COND_IP_REMOTE_PORT = "{c35a604d-d22b-4e1a-91b4-ea82bce21560}"
GUID_COND_IP_REMOTE_ADDRESS = "{b23a284e-28b6-497a-9fa1-8408a73507d6}"
GUID_COND_ALE_APP_ID = "{d78de288-7608-406c-82ab-b198c6d1d268}"

# DNS-SHIELD Custom Sublayer GUID
GUID_SUBLAYER_DNS_SHIELD = "{8b5c5e78-2b72-4b69-9d64-325a84f81713}"


# --- Windows SDK ctypes Structures ---

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, guid_str: str) -> "GUID":
        u = uuid.UUID(guid_str.strip("{}"))
        return cls.from_buffer_copy(u.bytes_le)

    def to_str(self) -> str:
        u = uuid.UUID(bytes_le=bytes(self))
        return f"{{{str(u)}}}"


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [
        ("name", wintypes.LPWSTR),
        ("description", wintypes.LPWSTR),
    ]


class FWPM_SESSION0(ctypes.Structure):
    _fields_ = [
        ("sessionKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", wintypes.DWORD),
        ("txnWaitTimeoutInMSec", wintypes.DWORD),
        ("processId", wintypes.DWORD),
        ("sid", ctypes.c_void_p),
        ("username", wintypes.LPWSTR),
        ("kernelMode", wintypes.BOOL),
    ]


class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
    ]


class FWP_BYTE_ARRAY16(ctypes.Structure):
    _fields_ = [
        ("byteArray16", ctypes.c_uint8 * 16),
    ]


class FWP_VALUE0_UNION(ctypes.Union):
    _fields_ = [
        ("uint8", wintypes.BYTE),
        ("uint16", wintypes.WORD),
        ("uint32", wintypes.DWORD),
        ("uint64", ctypes.POINTER(ctypes.c_uint64)),
        ("int8", ctypes.c_int8),
        ("int16", ctypes.c_int16),
        ("int32", ctypes.c_int32),
        ("int64", ctypes.POINTER(ctypes.c_int64)),
        ("float32", ctypes.c_float),
        ("double64", ctypes.POINTER(ctypes.c_double)),
        ("byteArray16", ctypes.POINTER(FWP_BYTE_ARRAY16)),
        ("byteBlob", ctypes.POINTER(FWP_BYTE_BLOB)),
        ("sid", ctypes.c_void_p),
        ("sd", ctypes.POINTER(FWP_BYTE_BLOB)),
        ("tokenInformation", ctypes.c_void_p),
        ("tokenAccessInformation", ctypes.c_void_p),
        ("unicodeString", wintypes.LPWSTR),
        ("byteArray6", ctypes.POINTER(ctypes.c_uint8 * 6)),
    ]


class FWP_VALUE0(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("value", FWP_VALUE0_UNION),
    ]


class FWP_CONDITION_VALUE0(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("value", FWP_VALUE0_UNION),
    ]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    _fields_ = [
        ("fieldKey", GUID),
        ("matchType", ctypes.c_int),
        ("conditionValue", FWP_CONDITION_VALUE0),
    ]


class FWPM_SUBLAYER0(ctypes.Structure):
    _fields_ = [
        ("subLayerKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", wintypes.DWORD),
        ("providerKey", ctypes.POINTER(GUID)),
        ("providerData", FWP_BYTE_BLOB),
        ("weight", wintypes.WORD),
    ]


class FWPM_ACTION0_UNION(ctypes.Union):
    _fields_ = [
        ("calloutKey", GUID),
        ("filterType", GUID),
    ]


class FWPM_ACTION0(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("u", FWPM_ACTION0_UNION),
    ]


class FWPM_FILTER0_UNION(ctypes.Union):
    _fields_ = [
        ("rawContext", ctypes.c_uint64),
        ("providerContextKey", GUID),
    ]


class FWPM_FILTER0(ctypes.Structure):
    _fields_ = [
        ("filterKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", wintypes.DWORD),
        ("providerKey", ctypes.POINTER(GUID)),
        ("providerData", FWP_BYTE_BLOB),
        ("layerKey", GUID),
        ("subLayerKey", GUID),
        ("weight", FWP_VALUE0),
        ("numFilterConditions", wintypes.DWORD),
        ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
        ("action", FWPM_ACTION0),
        ("u", FWPM_FILTER0_UNION),
        ("reserved", ctypes.POINTER(GUID)),
        ("filterId", ctypes.c_uint64),
        ("effectiveWeight", FWP_VALUE0),
    ]


class WFPState(str, enum.Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    ACTIVE = "ACTIVE"
    PENDING_VM_VALIDATION = "PENDING_VM_VALIDATION"


class WFPManager:
    """Manages genuine Windows Filtering Platform (WFP) ALE sublayers and filters."""

    SUBLAYER_NAME = "DNSShieldSubLayer"
    SUBLAYER_WEIGHT = 0x8000  # Priority weight for DNS-SHIELD sublayer

    def __init__(self, service_binary_path: Optional[Path] = None):
        self.service_binary = service_binary_path or Path(sys.executable)
        self.engine_handle = None
        self._fwp_dll = None
        self.installed_filter_ids: List[int] = []
        self._init_dll()

    def _init_dll(self) -> bool:
        """Loads and binds Win32 fwpuclnt.dll API function signatures."""
        if os.name != "nt":
            return False
        try:
            dll = ctypes.WinDLL("fwpuclnt.dll")

            # 1. Engine
            dll.FwpmEngineOpen0.restype = wintypes.DWORD
            dll.FwpmEngineOpen0.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                ctypes.POINTER(FWPM_SESSION0), ctypes.POINTER(wintypes.HANDLE)
            ]

            dll.FwpmEngineClose0.restype = wintypes.DWORD
            dll.FwpmEngineClose0.argtypes = [wintypes.HANDLE]

            # 2. Transactions
            dll.FwpmTransactionBegin0.restype = wintypes.DWORD
            dll.FwpmTransactionBegin0.argtypes = [wintypes.HANDLE, wintypes.DWORD]

            dll.FwpmTransactionCommit0.restype = wintypes.DWORD
            dll.FwpmTransactionCommit0.argtypes = [wintypes.HANDLE]

            dll.FwpmTransactionAbort0.restype = wintypes.DWORD
            dll.FwpmTransactionAbort0.argtypes = [wintypes.HANDLE]

            # 3. SubLayer
            dll.FwpmSubLayerAdd0.restype = wintypes.DWORD
            dll.FwpmSubLayerAdd0.argtypes = [wintypes.HANDLE, ctypes.POINTER(FWPM_SUBLAYER0), ctypes.c_void_p]

            dll.FwpmSubLayerDeleteByKey0.restype = wintypes.DWORD
            dll.FwpmSubLayerDeleteByKey0.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID)]

            # 4. App ID & Memory
            dll.FwpmGetAppIdFromFileName0.restype = wintypes.DWORD
            dll.FwpmGetAppIdFromFileName0.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(FWP_BYTE_BLOB))]

            dll.FwpmFreeMemory0.restype = None
            dll.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]

            # 5. Filters
            dll.FwpmFilterAdd0.restype = wintypes.DWORD
            dll.FwpmFilterAdd0.argtypes = [
                wintypes.HANDLE, ctypes.POINTER(FWPM_FILTER0), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)
            ]

            dll.FwpmFilterDeleteById0.restype = wintypes.DWORD
            dll.FwpmFilterDeleteById0.argtypes = [wintypes.HANDLE, ctypes.c_uint64]

            # 6. Enumeration
            dll.FwpmFilterCreateEnumHandle0.restype = wintypes.DWORD
            dll.FwpmFilterCreateEnumHandle0.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]

            dll.FwpmFilterEnum0.restype = wintypes.DWORD
            dll.FwpmFilterEnum0.argtypes = [
                wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD,
                ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0))),
                ctypes.POINTER(wintypes.DWORD)
            ]

            dll.FwpmFilterDestroyEnumHandle0.restype = wintypes.DWORD
            dll.FwpmFilterDestroyEnumHandle0.argtypes = [wintypes.HANDLE, wintypes.HANDLE]

            self._fwp_dll = dll
            return True
        except Exception as e:
            logger.debug(f"fwpuclnt.dll not initialized: {e}")
            self._fwp_dll = None
            return False

    def is_wfp_available(self) -> bool:
        return self._fwp_dll is not None

    def get_filter_specifications(self) -> List[Dict[str, Any]]:
        """
        Defines the complete, supported WFP rule manifest.
        Uses FWP_MATCH_EQUAL and filter weights to cleanly permit
        local loopback and gateway traffic while blocking external bypasses.
        """
        bin_path = str(self.service_binary)
        return [
            # --- IPv4 Layer (FWPM_LAYER_ALE_AUTH_CONNECT_V4) ---
            {
                "id": "IPv4_Permit_Local_Gateway_Loopback",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V4,
                "weight": 100,
                "action": "FWP_ACTION_PERMIT",
                "description": "Preserve application access to local DNS listener on 127.0.0.1:53",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 53},
                    {"field": "IP_REMOTE_ADDRESS", "guid": GUID_COND_IP_REMOTE_ADDRESS, "match": "FWP_MATCH_EQUAL", "value": "127.0.0.1"},
                ],
            },
            {
                "id": "IPv4_Permit_Gateway_Service_Outbound",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V4,
                "weight": 90,
                "action": "FWP_ACTION_PERMIT",
                "description": "Preserve gateway upstream access: allow DNS-SHIELD service binary on port 53",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 53},
                    {"field": "ALE_APP_ID", "guid": GUID_COND_ALE_APP_ID, "match": "FWP_MATCH_EQUAL", "value": bin_path},
                ],
            },
            {
                "id": "IPv4_Block_Rogue_External_Port53",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V4,
                "weight": 10,
                "action": "FWP_ACTION_BLOCK",
                "description": "Block all unauthorized external outbound UDP/TCP port 53 queries",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 53},
                ],
            },
            {
                "id": "IPv4_Block_Direct_DoT_DoQ_Port853",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V4,
                "weight": 10,
                "action": "FWP_ACTION_BLOCK",
                "description": "Block direct outbound port 853 (DoT/DoQ) encrypted DNS bypass",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 853},
                ],
            },

            # --- IPv6 Layer (FWPM_LAYER_ALE_AUTH_CONNECT_V6) ---
            {
                "id": "IPv6_Permit_Local_Gateway_Loopback",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V6,
                "weight": 100,
                "action": "FWP_ACTION_PERMIT",
                "description": "Preserve application access to local DNS listener on [::1]:53",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 53},
                    {"field": "IP_REMOTE_ADDRESS", "guid": GUID_COND_IP_REMOTE_ADDRESS, "match": "FWP_MATCH_EQUAL", "value": "::1"},
                ],
            },
            {
                "id": "IPv6_Permit_Gateway_Service_Outbound",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V6,
                "weight": 90,
                "action": "FWP_ACTION_PERMIT",
                "description": "Preserve gateway upstream access: allow DNS-SHIELD service binary on IPv6 port 53",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 53},
                    {"field": "ALE_APP_ID", "guid": GUID_COND_ALE_APP_ID, "match": "FWP_MATCH_EQUAL", "value": bin_path},
                ],
            },
            {
                "id": "IPv6_Block_Rogue_External_Port53",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V6,
                "weight": 10,
                "action": "FWP_ACTION_BLOCK",
                "description": "Block all unauthorized external outbound IPv6 port 53 queries",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 53},
                ],
            },
            {
                "id": "IPv6_Block_Direct_DoT_DoQ_Port853",
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
                "layer_guid": GUID_ALE_AUTH_CONNECT_V6,
                "weight": 10,
                "action": "FWP_ACTION_BLOCK",
                "description": "Block direct outbound IPv6 port 853 (DoT/DoQ) encrypted DNS bypass",
                "conditions": [
                    {"field": "IP_REMOTE_PORT", "guid": GUID_COND_IP_REMOTE_PORT, "match": "FWP_MATCH_EQUAL", "value": 853},
                ],
            },
        ]

    def preview(self) -> Dict[str, Any]:
        """Returns structured preview of planned WFP sublayer and filters."""
        specs = self.get_filter_specifications()
        return {
            "wfp_dll_available": self.is_wfp_available(),
            "sublayer": {
                "name": self.SUBLAYER_NAME,
                "guid": GUID_SUBLAYER_DNS_SHIELD,
                "weight": self.SUBLAYER_WEIGHT,
            },
            "dynamic_session": True,
            "filters_count": len(specs),
            "filters": specs,
            "lifecycle_note": "Filters will use FWPM_SESSION_FLAG_DYNAMIC for automatic kernel cleanup on crash.",
            "non_claims": [
                "Does not intercept arbitrary DoH over port 443 without enterprise browser policies.",
                "Does not filter direct IP-to-IP malware traffic without domain resolution.",
                "Does not intercept traffic routed through separate virtual VPN tunnel interfaces.",
            ],
        }

    def apply_filters(self, dry_run: bool = True) -> Dict[str, Any]:
        """
        Installs WFP sublayer and filters using fwpuclnt.dll.
        Guarded: dry_run=True by default to prevent mutating user laptop.
        """
        preview_data = self.preview()
        if dry_run or os.name != "nt":
            return {
                "success": True,
                "dry_run": True,
                "status": WFPState.PENDING_VM_VALIDATION.value,
                **preview_data,
            }

        if not self._fwp_dll:
            return {"success": False, "error": "fwpuclnt.dll not available"}

        engine_handle = wintypes.HANDLE()
        session = FWPM_SESSION0()
        session.flags = FWPM_SESSION_FLAG_DYNAMIC
        display = FWPM_DISPLAY_DATA0(
            name="DNS-SHIELD Dynamic Session",
            description="Dynamic bypass prevention session"
        )
        session.displayData = display

        app_id_blob_ptr = ctypes.POINTER(FWP_BYTE_BLOB)()
        in_transaction = False

        try:
            # 1. Open Dynamic Engine Session
            ret = self._fwp_dll.FwpmEngineOpen0(None, 10, None, ctypes.byref(session), ctypes.byref(engine_handle))
            if ret != 0:
                return {"success": False, "error": f"FwpmEngineOpen0 failed (0x{ret:08x})"}
            self.engine_handle = engine_handle

            # 2. Begin Atomic Transaction
            ret = self._fwp_dll.FwpmTransactionBegin0(self.engine_handle, 0)
            if ret != 0:
                raise RuntimeError(f"FwpmTransactionBegin0 failed (0x{ret:08x})")
            in_transaction = True

            # 3. Create SubLayer
            sublayer = FWPM_SUBLAYER0()
            sublayer.subLayerKey = GUID.from_str(GUID_SUBLAYER_DNS_SHIELD)
            sublayer.displayData = FWPM_DISPLAY_DATA0(
                name=self.SUBLAYER_NAME,
                description="DNS-SHIELD Outbound Arbitration Sublayer"
            )
            sublayer.flags = 0
            sublayer.weight = self.SUBLAYER_WEIGHT

            ret = self._fwp_dll.FwpmSubLayerAdd0(self.engine_handle, ctypes.byref(sublayer), None)
            if ret != 0:
                # FWP_E_ALREADY_EXISTS (0x8032000c) is acceptable if previously present
                if ret != 0x8032000c:
                    raise RuntimeError(f"FwpmSubLayerAdd0 failed (0x{ret:08x})")

            # 4. Resolve Service App ID
            bin_str = str(self.service_binary)
            ret = self._fwp_dll.FwpmGetAppIdFromFileName0(bin_str, ctypes.byref(app_id_blob_ptr))
            if ret != 0:
                raise RuntimeError(f"FwpmGetAppIdFromFileName0 failed for {bin_str} (0x{ret:08x})")

            # Keep pointer buffers alive during installation
            active_buffers: List[Any] = [app_id_blob_ptr]

            # 5. Add Filters
            specs = self.get_filter_specifications()
            installed_ids: List[int] = []

            for spec in specs:
                filter_obj = FWPM_FILTER0()
                filter_obj.filterKey = GUID.from_str(str(uuid.uuid4()))
                filter_obj.displayData = FWPM_DISPLAY_DATA0(
                    name=spec["id"],
                    description=spec["description"]
                )
                filter_obj.layerKey = GUID.from_str(spec["layer_guid"])
                filter_obj.subLayerKey = GUID.from_str(GUID_SUBLAYER_DNS_SHIELD)
                filter_obj.flags = 0  # Does not set FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT; preserves unrelated firewall rules

                # Weight: FWP_UINT64 absolute priority weight (not FWP_UINT8 range index)
                weight_val = ctypes.c_uint64(int(spec["weight"]))
                active_buffers.append(weight_val)
                filter_obj.weight.type = FWP_UINT64
                filter_obj.weight.value.uint64 = ctypes.pointer(weight_val)

                # Action
                filter_obj.action.type = FWP_ACTION_PERMIT if spec["action"] == "FWP_ACTION_PERMIT" else FWP_ACTION_BLOCK

                # Build Conditions
                cond_specs = spec.get("conditions", [])
                if cond_specs:
                    num_conds = len(cond_specs)
                    cond_array = (FWPM_FILTER_CONDITION0 * num_conds)()
                    active_buffers.append(cond_array)

                    for idx, c in enumerate(cond_specs):
                        cond = cond_array[idx]
                        cond.fieldKey = GUID.from_str(c["guid"])
                        cond.matchType = FWP_MATCH_EQUAL

                        field = c["field"]
                        val = c["value"]

                        if field == "IP_REMOTE_PORT":
                            cond.conditionValue.type = FWP_UINT16
                            cond.conditionValue.value.uint16 = int(val)
                        elif field == "IP_REMOTE_ADDRESS":
                            if "." in str(val):
                                # IPv4: UINT32 in host byte order
                                cond.conditionValue.type = FWP_UINT32
                                cond.conditionValue.value.uint32 = int(ipaddress.IPv4Address(val))
                            else:
                                # IPv6: FWP_BYTE_ARRAY16
                                cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE
                                arr16 = FWP_BYTE_ARRAY16()
                                packed = ipaddress.IPv6Address(val).packed
                                arr16.byteArray16 = (ctypes.c_uint8 * 16)(*packed)
                                active_buffers.append(arr16)
                                cond.conditionValue.value.byteArray16 = ctypes.pointer(arr16)
                        elif field == "ALE_APP_ID":
                            cond.conditionValue.type = FWP_BYTE_BLOB_TYPE
                            cond.conditionValue.value.byteBlob = app_id_blob_ptr

                    filter_obj.numFilterConditions = num_conds
                    filter_obj.filterCondition = cond_array
                else:
                    filter_obj.numFilterConditions = 0
                    filter_obj.filterCondition = None

                filter_id = ctypes.c_uint64(0)
                ret = self._fwp_dll.FwpmFilterAdd0(self.engine_handle, ctypes.byref(filter_obj), None, ctypes.byref(filter_id))
                if ret != 0:
                    raise RuntimeError(f"FwpmFilterAdd0 failed for {spec['id']} (0x{ret:08x})")

                installed_ids.append(filter_id.value)

            # 6. Commit Transaction
            ret = self._fwp_dll.FwpmTransactionCommit0(self.engine_handle)
            if ret != 0:
                raise RuntimeError(f"FwpmTransactionCommit0 failed (0x{ret:08x})")
            in_transaction = False

            self.installed_filter_ids = installed_ids
            logger.info(f"Successfully installed {len(installed_ids)} WFP filters in sublayer {self.SUBLAYER_NAME}")

            return {
                "success": True,
                "dry_run": False,
                "status": WFPState.ACTIVE.value,
                "filters_installed": len(installed_ids),
                "filter_ids": installed_ids,
                **preview_data,
            }

        except Exception as exc:
            logger.error(f"Error applying native WFP filters: {exc}")
            if in_transaction and self.engine_handle:
                try:
                    self._fwp_dll.FwpmTransactionAbort0(self.engine_handle)
                except Exception:
                    pass
            self.remove_filters()
            return {"success": False, "error": str(exc)}
        finally:
            # Free RPC App ID memory
            if app_id_blob_ptr:
                try:
                    ptr_to_free = ctypes.cast(app_id_blob_ptr, ctypes.c_void_p)
                    self._fwp_dll.FwpmFreeMemory0(ctypes.byref(ptr_to_free))
                except Exception as e:
                    logger.debug(f"Error in FwpmFreeMemory0: {e}")

    def enumerate_filters(self) -> Dict[str, Any]:
        """Enumerates active filters in the DNS-SHIELD sublayer."""
        if not self.engine_handle or not self._fwp_dll:
            return {"count": 0, "filters": []}

        enum_handle = wintypes.HANDLE()
        ret = self._fwp_dll.FwpmFilterCreateEnumHandle0(self.engine_handle, None, ctypes.byref(enum_handle))
        if ret != 0:
            return {"error": f"FwpmFilterCreateEnumHandle0 failed (0x{ret:08x})"}

        entries_ptr = ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0))()
        num_returned = wintypes.DWORD(0)
        filters_meta = []

        try:
            ret = self._fwp_dll.FwpmFilterEnum0(self.engine_handle, enum_handle, 100, ctypes.byref(entries_ptr), ctypes.byref(num_returned))
            if ret == 0 and num_returned.value > 0:
                target_sublayer = GUID_SUBLAYER_DNS_SHIELD.lower().strip("{}")
                for i in range(num_returned.value):
                    filt = entries_ptr[i].contents
                    sub_str = filt.subLayerKey.to_str().lower().strip("{}")
                    if sub_str == target_sublayer:
                        name = filt.displayData.name or "Unnamed"
                        filters_meta.append({
                            "filterId": filt.filterId,
                            "name": name,
                            "action": "PERMIT" if filt.action.type == FWP_ACTION_PERMIT else "BLOCK",
                        })
            return {"count": len(filters_meta), "filters": filters_meta}
        finally:
            if entries_ptr:
                try:
                    p = ctypes.cast(entries_ptr, ctypes.c_void_p)
                    self._fwp_dll.FwpmFreeMemory0(ctypes.byref(p))
                except Exception:
                    pass
            self._fwp_dll.FwpmFilterDestroyEnumHandle0(self.engine_handle, enum_handle)

    def delete_filter_by_id(self, filter_id: int) -> bool:
        """Deletes an installed WFP filter by its 64-bit filterId."""
        if not self.engine_handle or not self._fwp_dll:
            return False
        ret = self._fwp_dll.FwpmFilterDeleteById0(self.engine_handle, ctypes.c_uint64(filter_id))
        if ret == 0:
            if filter_id in self.installed_filter_ids:
                self.installed_filter_ids.remove(filter_id)
            return True
        logger.warning(f"FwpmFilterDeleteById0 failed for {filter_id} (0x{ret:08x})")
        return False

    def delete_sublayer(self, sublayer_guid: Optional[str] = None) -> bool:
        """Deletes the DNS-SHIELD sublayer by GUID."""
        if not self.engine_handle or not self._fwp_dll:
            return False
        guid_str = sublayer_guid or GUID_SUBLAYER_DNS_SHIELD
        g = GUID.from_str(guid_str)
        ret = self._fwp_dll.FwpmSubLayerDeleteByKey0(self.engine_handle, ctypes.byref(g))
        return ret == 0

    def remove_filters(self) -> Dict[str, Any]:
        """Tears down WFP engine session and filters."""
        if self.engine_handle and self._fwp_dll:
            try:
                self._fwp_dll.FwpmEngineClose0(self.engine_handle)
                self.engine_handle = None
                self.installed_filter_ids = []
                return {"success": True, "message": "WFP engine closed and dynamic filters released."}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": True, "message": "No active WFP engine session."}
