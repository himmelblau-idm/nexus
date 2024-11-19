/*
   Unix SMB3 implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

/*
 * Descriptions for errors generated from
 * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx
 */

use std::fmt;

#[derive(PartialEq, Eq)]
pub struct NtStatus(u32);

#[allow(dead_code)]
pub const NT_STATUS_OK: NtStatus = NtStatus(0x0);
pub const NT_STATUS_SUCCESS: NtStatus = NtStatus(0x0);
#[allow(dead_code)]
pub const NT_STATUS_WAIT_0: NtStatus = NtStatus(0x0);
pub const NT_STATUS_WAIT_1: NtStatus = NtStatus(0x1);
pub const NT_STATUS_WAIT_2: NtStatus = NtStatus(0x2);
pub const NT_STATUS_WAIT_3: NtStatus = NtStatus(0x3);
pub const NT_STATUS_WAIT_63: NtStatus = NtStatus(0x3f);
pub const NT_STATUS_ABANDONED: NtStatus = NtStatus(0x80);
#[allow(dead_code)]
pub const NT_STATUS_ABANDONED_WAIT_0: NtStatus = NtStatus(0x80);
pub const NT_STATUS_ABANDONED_WAIT_63: NtStatus = NtStatus(0xbf);
pub const NT_STATUS_USER_APC: NtStatus = NtStatus(0xc0);
pub const NT_STATUS_ALERTED: NtStatus = NtStatus(0x101);
pub const NT_STATUS_TIMEOUT: NtStatus = NtStatus(0x102);
pub const NT_STATUS_PENDING: NtStatus = NtStatus(0x103);
pub const NT_STATUS_REPARSE: NtStatus = NtStatus(0x104);
pub const NT_STATUS_MORE_ENTRIES: NtStatus = NtStatus(0x105);
pub const NT_STATUS_NOT_ALL_ASSIGNED: NtStatus = NtStatus(0x106);
pub const NT_STATUS_SOME_NOT_MAPPED: NtStatus = NtStatus(0x107);
pub const NT_STATUS_OPLOCK_BREAK_IN_PROGRESS: NtStatus = NtStatus(0x108);
pub const NT_STATUS_VOLUME_MOUNTED: NtStatus = NtStatus(0x109);
pub const NT_STATUS_RXACT_COMMITTED: NtStatus = NtStatus(0x10a);
pub const NT_STATUS_NOTIFY_CLEANUP: NtStatus = NtStatus(0x10b);
pub const NT_STATUS_NOTIFY_ENUM_DIR: NtStatus = NtStatus(0x10c);
pub const NT_STATUS_NO_QUOTAS_FOR_ACCOUNT: NtStatus = NtStatus(0x10d);
pub const NT_STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED: NtStatus =
    NtStatus(0x10e);
pub const NT_STATUS_PAGE_FAULT_TRANSITION: NtStatus = NtStatus(0x110);
pub const NT_STATUS_PAGE_FAULT_DEMAND_ZERO: NtStatus = NtStatus(0x111);
pub const NT_STATUS_PAGE_FAULT_COPY_ON_WRITE: NtStatus = NtStatus(0x112);
pub const NT_STATUS_PAGE_FAULT_GUARD_PAGE: NtStatus = NtStatus(0x113);
pub const NT_STATUS_PAGE_FAULT_PAGING_FILE: NtStatus = NtStatus(0x114);
pub const NT_STATUS_CACHE_PAGE_LOCKED: NtStatus = NtStatus(0x115);
pub const NT_STATUS_CRASH_DUMP: NtStatus = NtStatus(0x116);
pub const NT_STATUS_BUFFER_ALL_ZEROS: NtStatus = NtStatus(0x117);
pub const NT_STATUS_REPARSE_OBJECT: NtStatus = NtStatus(0x118);
pub const NT_STATUS_RESOURCE_REQUIREMENTS_CHANGED: NtStatus = NtStatus(0x119);
pub const NT_STATUS_TRANSLATION_COMPLETE: NtStatus = NtStatus(0x120);
pub const NT_STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY: NtStatus = NtStatus(0x121);
pub const NT_STATUS_NOTHING_TO_TERMINATE: NtStatus = NtStatus(0x122);
pub const NT_STATUS_PROCESS_NOT_IN_JOB: NtStatus = NtStatus(0x123);
pub const NT_STATUS_PROCESS_IN_JOB: NtStatus = NtStatus(0x124);
pub const NT_STATUS_VOLSNAP_HIBERNATE_READY: NtStatus = NtStatus(0x125);
pub const NT_STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY: NtStatus =
    NtStatus(0x126);
pub const NT_STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED: NtStatus =
    NtStatus(0x127);
pub const NT_STATUS_INTERRUPT_STILL_CONNECTED: NtStatus = NtStatus(0x128);
pub const NT_STATUS_PROCESS_CLONED: NtStatus = NtStatus(0x129);
pub const NT_STATUS_FILE_LOCKED_WITH_ONLY_READERS: NtStatus = NtStatus(0x12a);
pub const NT_STATUS_FILE_LOCKED_WITH_WRITERS: NtStatus = NtStatus(0x12b);
pub const NT_STATUS_RESOURCEMANAGER_READ_ONLY: NtStatus = NtStatus(0x202);
pub const NT_STATUS_WAIT_FOR_OPLOCK: NtStatus = NtStatus(0x367);
pub const NT_STATUS_DBG_EXCEPTION_HANDLED: NtStatus = NtStatus(0x10001);
pub const NT_STATUS_DBG_CONTINUE: NtStatus = NtStatus(0x10002);
pub const NT_STATUS_FLT_IO_COMPLETE: NtStatus = NtStatus(0x1c0001);
pub const NT_STATUS_FILE_NOT_AVAILABLE: NtStatus = NtStatus(0xc0000467);
pub const NT_STATUS_SHARE_UNAVAILABLE: NtStatus = NtStatus(0xc0000480);
pub const NT_STATUS_CALLBACK_RETURNED_THREAD_AFFINITY: NtStatus =
    NtStatus(0xc0000721);
pub const NT_STATUS_OBJECT_NAME_EXISTS: NtStatus = NtStatus(0x40000000);
pub const NT_STATUS_THREAD_WAS_SUSPENDED: NtStatus = NtStatus(0x40000001);
pub const NT_STATUS_WORKING_SET_LIMIT_RANGE: NtStatus = NtStatus(0x40000002);
pub const NT_STATUS_IMAGE_NOT_AT_BASE: NtStatus = NtStatus(0x40000003);
pub const NT_STATUS_RXACT_STATE_CREATED: NtStatus = NtStatus(0x40000004);
pub const NT_STATUS_SEGMENT_NOTIFICATION: NtStatus = NtStatus(0x40000005);
pub const NT_STATUS_LOCAL_USER_SESSION_KEY: NtStatus = NtStatus(0x40000006);
pub const NT_STATUS_BAD_CURRENT_DIRECTORY: NtStatus = NtStatus(0x40000007);
pub const NT_STATUS_SERIAL_MORE_WRITES: NtStatus = NtStatus(0x40000008);
pub const NT_STATUS_REGISTRY_RECOVERED: NtStatus = NtStatus(0x40000009);
pub const NT_STATUS_FT_READ_RECOVERY_FROM_BACKUP: NtStatus =
    NtStatus(0x4000000a);
pub const NT_STATUS_FT_WRITE_RECOVERY: NtStatus = NtStatus(0x4000000b);
pub const NT_STATUS_SERIAL_COUNTER_TIMEOUT: NtStatus = NtStatus(0x4000000c);
pub const NT_STATUS_NULL_LM_PASSWORD: NtStatus = NtStatus(0x4000000d);
pub const NT_STATUS_IMAGE_MACHINE_TYPE_MISMATCH: NtStatus =
    NtStatus(0x4000000e);
pub const NT_STATUS_RECEIVE_PARTIAL: NtStatus = NtStatus(0x4000000f);
pub const NT_STATUS_RECEIVE_EXPEDITED: NtStatus = NtStatus(0x40000010);
pub const NT_STATUS_RECEIVE_PARTIAL_EXPEDITED: NtStatus = NtStatus(0x40000011);
pub const NT_STATUS_EVENT_DONE: NtStatus = NtStatus(0x40000012);
pub const NT_STATUS_EVENT_PENDING: NtStatus = NtStatus(0x40000013);
pub const NT_STATUS_CHECKING_FILE_SYSTEM: NtStatus = NtStatus(0x40000014);
pub const NT_STATUS_FATAL_APP_EXIT: NtStatus = NtStatus(0x40000015);
pub const NT_STATUS_PREDEFINED_HANDLE: NtStatus = NtStatus(0x40000016);
pub const NT_STATUS_WAS_UNLOCKED: NtStatus = NtStatus(0x40000017);
pub const NT_STATUS_SERVICE_NOTIFICATION: NtStatus = NtStatus(0x40000018);
pub const NT_STATUS_WAS_LOCKED: NtStatus = NtStatus(0x40000019);
pub const NT_STATUS_LOG_HARD_ERROR: NtStatus = NtStatus(0x4000001a);
pub const NT_STATUS_ALREADY_WIN32: NtStatus = NtStatus(0x4000001b);
pub const NT_STATUS_WX86_UNSIMULATE: NtStatus = NtStatus(0x4000001c);
pub const NT_STATUS_WX86_CONTINUE: NtStatus = NtStatus(0x4000001d);
pub const NT_STATUS_WX86_SINGLE_STEP: NtStatus = NtStatus(0x4000001e);
pub const NT_STATUS_WX86_BREAKPOINT: NtStatus = NtStatus(0x4000001f);
pub const NT_STATUS_WX86_EXCEPTION_CONTINUE: NtStatus = NtStatus(0x40000020);
pub const NT_STATUS_WX86_EXCEPTION_LASTCHANCE: NtStatus = NtStatus(0x40000021);
pub const NT_STATUS_WX86_EXCEPTION_CHAIN: NtStatus = NtStatus(0x40000022);
pub const NT_STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE: NtStatus =
    NtStatus(0x40000023);
pub const NT_STATUS_NO_YIELD_PERFORMED: NtStatus = NtStatus(0x40000024);
pub const NT_STATUS_TIMER_RESUME_IGNORED: NtStatus = NtStatus(0x40000025);
pub const NT_STATUS_ARBITRATION_UNHANDLED: NtStatus = NtStatus(0x40000026);
pub const NT_STATUS_CARDBUS_NOT_SUPPORTED: NtStatus = NtStatus(0x40000027);
pub const NT_STATUS_WX86_CREATEWX86TIB: NtStatus = NtStatus(0x40000028);
pub const NT_STATUS_MP_PROCESSOR_MISMATCH: NtStatus = NtStatus(0x40000029);
pub const NT_STATUS_HIBERNATED: NtStatus = NtStatus(0x4000002a);
pub const NT_STATUS_RESUME_HIBERNATION: NtStatus = NtStatus(0x4000002b);
pub const NT_STATUS_FIRMWARE_UPDATED: NtStatus = NtStatus(0x4000002c);
pub const NT_STATUS_DRIVERS_LEAKING_LOCKED_PAGES: NtStatus =
    NtStatus(0x4000002d);
pub const NT_STATUS_MESSAGE_RETRIEVED: NtStatus = NtStatus(0x4000002e);
pub const NT_STATUS_SYSTEM_POWERSTATE_TRANSITION: NtStatus =
    NtStatus(0x4000002f);
pub const NT_STATUS_ALPC_CHECK_COMPLETION_LIST: NtStatus = NtStatus(0x40000030);
pub const NT_STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION: NtStatus =
    NtStatus(0x40000031);
pub const NT_STATUS_ACCESS_AUDIT_BY_POLICY: NtStatus = NtStatus(0x40000032);
pub const NT_STATUS_ABANDON_HIBERFILE: NtStatus = NtStatus(0x40000033);
pub const NT_STATUS_BIZRULES_NOT_ENABLED: NtStatus = NtStatus(0x40000034);
pub const NT_STATUS_WAKE_SYSTEM: NtStatus = NtStatus(0x40000294);
pub const NT_STATUS_DS_SHUTTING_DOWN: NtStatus = NtStatus(0x40000370);
pub const NT_STATUS_DBG_REPLY_LATER: NtStatus = NtStatus(0x40010001);
pub const NT_STATUS_DBG_UNABLE_TO_PROVIDE_HANDLE: NtStatus =
    NtStatus(0x40010002);
pub const NT_STATUS_DBG_TERMINATE_THREAD: NtStatus = NtStatus(0x40010003);
pub const NT_STATUS_DBG_TERMINATE_PROCESS: NtStatus = NtStatus(0x40010004);
pub const NT_STATUS_DBG_CONTROL_C: NtStatus = NtStatus(0x40010005);
pub const NT_STATUS_DBG_PRINTEXCEPTION_C: NtStatus = NtStatus(0x40010006);
pub const NT_STATUS_DBG_RIPEXCEPTION: NtStatus = NtStatus(0x40010007);
pub const NT_STATUS_DBG_CONTROL_BREAK: NtStatus = NtStatus(0x40010008);
pub const NT_STATUS_DBG_COMMAND_EXCEPTION: NtStatus = NtStatus(0x40010009);
pub const NT_STATUS_RPC_UUID_LOCAL_ONLY: NtStatus = NtStatus(0x40020056);
pub const NT_STATUS_RPC_SEND_INCOMPLETE: NtStatus = NtStatus(0x400200af);
pub const NT_STATUS_CTX_CDM_CONNECT: NtStatus = NtStatus(0x400a0004);
pub const NT_STATUS_CTX_CDM_DISCONNECT: NtStatus = NtStatus(0x400a0005);
pub const NT_STATUS_SXS_RELEASE_ACTIVATION_CONTEXT: NtStatus =
    NtStatus(0x4015000d);
pub const NT_STATUS_RECOVERY_NOT_NEEDED: NtStatus = NtStatus(0x40190034);
pub const NT_STATUS_RM_ALREADY_STARTED: NtStatus = NtStatus(0x40190035);
pub const NT_STATUS_LOG_NO_RESTART: NtStatus = NtStatus(0x401a000c);
pub const NT_STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST: NtStatus =
    NtStatus(0x401b00ec);
pub const NT_STATUS_GRAPHICS_PARTIAL_DATA_POPULATED: NtStatus =
    NtStatus(0x401e000a);
pub const NT_STATUS_GRAPHICS_DRIVER_MISMATCH: NtStatus = NtStatus(0x401e0117);
pub const NT_STATUS_GRAPHICS_MODE_NOT_PINNED: NtStatus = NtStatus(0x401e0307);
pub const NT_STATUS_GRAPHICS_NO_PREFERRED_MODE: NtStatus = NtStatus(0x401e031e);
pub const NT_STATUS_GRAPHICS_DATASET_IS_EMPTY: NtStatus = NtStatus(0x401e034b);
pub const NT_STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET: NtStatus =
    NtStatus(0x401e034c);
pub const NT_STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED:
    NtStatus = NtStatus(0x401e0351);
pub const NT_STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS: NtStatus =
    NtStatus(0x401e042f);
pub const NT_STATUS_GRAPHICS_LEADLINK_START_DEFERRED: NtStatus =
    NtStatus(0x401e0437);
pub const NT_STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY: NtStatus =
    NtStatus(0x401e0439);
pub const NT_STATUS_GRAPHICS_START_DEFERRED: NtStatus = NtStatus(0x401e043a);
pub const NT_STATUS_NDIS_INDICATION_REQUIRED: NtStatus = NtStatus(0x40230001);
pub const NT_STATUS_GUARD_PAGE_VIOLATION: NtStatus = NtStatus(0x80000001);
pub const NT_STATUS_DATATYPE_MISALIGNMENT: NtStatus = NtStatus(0x80000002);
pub const NT_STATUS_BREAKPOINT: NtStatus = NtStatus(0x80000003);
pub const NT_STATUS_SINGLE_STEP: NtStatus = NtStatus(0x80000004);
pub const NT_STATUS_BUFFER_OVERFLOW: NtStatus = NtStatus(0x80000005);
pub const NT_STATUS_NO_MORE_FILES: NtStatus = NtStatus(0x80000006);
pub const NT_STATUS_WAKE_SYSTEM_DEBUGGER: NtStatus = NtStatus(0x80000007);
pub const NT_STATUS_HANDLES_CLOSED: NtStatus = NtStatus(0x8000000a);
pub const NT_STATUS_NO_INHERITANCE: NtStatus = NtStatus(0x8000000b);
pub const NT_STATUS_GUID_SUBSTITUTION_MADE: NtStatus = NtStatus(0x8000000c);
pub const NT_STATUS_PARTIAL_COPY: NtStatus = NtStatus(0x8000000d);
pub const NT_STATUS_DEVICE_PAPER_EMPTY: NtStatus = NtStatus(0x8000000e);
pub const NT_STATUS_DEVICE_POWERED_OFF: NtStatus = NtStatus(0x8000000f);
pub const NT_STATUS_DEVICE_OFF_LINE: NtStatus = NtStatus(0x80000010);
pub const NT_STATUS_DEVICE_BUSY: NtStatus = NtStatus(0x80000011);
pub const NT_STATUS_NO_MORE_EAS: NtStatus = NtStatus(0x80000012);
pub const NT_STATUS_INVALID_EA_NAME: NtStatus = NtStatus(0x80000013);
pub const NT_STATUS_EA_LIST_INCONSISTENT: NtStatus = NtStatus(0x80000014);
pub const NT_STATUS_INVALID_EA_FLAG: NtStatus = NtStatus(0x80000015);
pub const NT_STATUS_VERIFY_REQUIRED: NtStatus = NtStatus(0x80000016);
pub const NT_STATUS_EXTRANEOUS_INFORMATION: NtStatus = NtStatus(0x80000017);
pub const NT_STATUS_RXACT_COMMIT_NECESSARY: NtStatus = NtStatus(0x80000018);
pub const NT_STATUS_NO_MORE_ENTRIES: NtStatus = NtStatus(0x8000001a);
pub const NT_STATUS_FILEMARK_DETECTED: NtStatus = NtStatus(0x8000001b);
pub const NT_STATUS_MEDIA_CHANGED: NtStatus = NtStatus(0x8000001c);
pub const NT_STATUS_BUS_RESET: NtStatus = NtStatus(0x8000001d);
pub const NT_STATUS_END_OF_MEDIA: NtStatus = NtStatus(0x8000001e);
pub const NT_STATUS_BEGINNING_OF_MEDIA: NtStatus = NtStatus(0x8000001f);
pub const NT_STATUS_MEDIA_CHECK: NtStatus = NtStatus(0x80000020);
pub const NT_STATUS_SETMARK_DETECTED: NtStatus = NtStatus(0x80000021);
pub const NT_STATUS_NO_DATA_DETECTED: NtStatus = NtStatus(0x80000022);
pub const NT_STATUS_REDIRECTOR_HAS_OPEN_HANDLES: NtStatus =
    NtStatus(0x80000023);
pub const NT_STATUS_SERVER_HAS_OPEN_HANDLES: NtStatus = NtStatus(0x80000024);
pub const NT_STATUS_ALREADY_DISCONNECTED: NtStatus = NtStatus(0x80000025);
pub const NT_STATUS_LONGJUMP: NtStatus = NtStatus(0x80000026);
pub const NT_STATUS_CLEANER_CARTRIDGE_INSTALLED: NtStatus =
    NtStatus(0x80000027);
pub const NT_STATUS_PLUGPLAY_QUERY_VETOED: NtStatus = NtStatus(0x80000028);
pub const NT_STATUS_UNWIND_CONSOLIDATE: NtStatus = NtStatus(0x80000029);
pub const NT_STATUS_REGISTRY_HIVE_RECOVERED: NtStatus = NtStatus(0x8000002a);
pub const NT_STATUS_DLL_MIGHT_BE_INSECURE: NtStatus = NtStatus(0x8000002b);
pub const NT_STATUS_DLL_MIGHT_BE_INCOMPATIBLE: NtStatus = NtStatus(0x8000002c);
pub const NT_STATUS_STOPPED_ON_SYMLINK: NtStatus = NtStatus(0x8000002d);
pub const NT_STATUS_DEVICE_REQUIRES_CLEANING: NtStatus = NtStatus(0x80000288);
pub const NT_STATUS_DEVICE_DOOR_OPEN: NtStatus = NtStatus(0x80000289);
pub const NT_STATUS_DATA_LOST_REPAIR: NtStatus = NtStatus(0x80000803);
pub const NT_STATUS_DBG_EXCEPTION_NOT_HANDLED: NtStatus = NtStatus(0x80010001);
pub const NT_STATUS_CLUSTER_NODE_ALREADY_UP: NtStatus = NtStatus(0x80130001);
pub const NT_STATUS_CLUSTER_NODE_ALREADY_DOWN: NtStatus = NtStatus(0x80130002);
pub const NT_STATUS_CLUSTER_NETWORK_ALREADY_ONLINE: NtStatus =
    NtStatus(0x80130003);
pub const NT_STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE: NtStatus =
    NtStatus(0x80130004);
pub const NT_STATUS_CLUSTER_NODE_ALREADY_MEMBER: NtStatus =
    NtStatus(0x80130005);
pub const NT_STATUS_COULD_NOT_RESIZE_LOG: NtStatus = NtStatus(0x80190009);
pub const NT_STATUS_NO_TXF_METADATA: NtStatus = NtStatus(0x80190029);
pub const NT_STATUS_CANT_RECOVER_WITH_HANDLE_OPEN: NtStatus =
    NtStatus(0x80190031);
pub const NT_STATUS_TXF_METADATA_ALREADY_PRESENT: NtStatus =
    NtStatus(0x80190041);
pub const NT_STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET: NtStatus =
    NtStatus(0x80190042);
pub const NT_STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED: NtStatus =
    NtStatus(0x801b00eb);
pub const NT_STATUS_FLT_BUFFER_TOO_SMALL: NtStatus = NtStatus(0x801c0001);
pub const NT_STATUS_FVE_PARTIAL_METADATA: NtStatus = NtStatus(0x80210001);
pub const NT_STATUS_FVE_TRANSIENT_STATE: NtStatus = NtStatus(0x80210002);
pub const NT_STATUS_UNSUCCESSFUL: NtStatus = NtStatus(0xc0000001);
pub const NT_STATUS_NOT_IMPLEMENTED: NtStatus = NtStatus(0xc0000002);
pub const NT_STATUS_INVALID_INFO_CLASS: NtStatus = NtStatus(0xc0000003);
pub const NT_STATUS_INFO_LENGTH_MISMATCH: NtStatus = NtStatus(0xc0000004);
pub const NT_STATUS_ACCESS_VIOLATION: NtStatus = NtStatus(0xc0000005);
pub const NT_STATUS_IN_PAGE_ERROR: NtStatus = NtStatus(0xc0000006);
pub const NT_STATUS_PAGEFILE_QUOTA: NtStatus = NtStatus(0xc0000007);
pub const NT_STATUS_INVALID_HANDLE: NtStatus = NtStatus(0xc0000008);
pub const NT_STATUS_BAD_INITIAL_STACK: NtStatus = NtStatus(0xc0000009);
pub const NT_STATUS_BAD_INITIAL_PC: NtStatus = NtStatus(0xc000000a);
pub const NT_STATUS_INVALID_CID: NtStatus = NtStatus(0xc000000b);
pub const NT_STATUS_TIMER_NOT_CANCELED: NtStatus = NtStatus(0xc000000c);
pub const NT_STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xc000000d);
pub const NT_STATUS_NO_SUCH_DEVICE: NtStatus = NtStatus(0xc000000e);
pub const NT_STATUS_NO_SUCH_FILE: NtStatus = NtStatus(0xc000000f);
pub const NT_STATUS_INVALID_DEVICE_REQUEST: NtStatus = NtStatus(0xc0000010);
pub const NT_STATUS_END_OF_FILE: NtStatus = NtStatus(0xc0000011);
pub const NT_STATUS_WRONG_VOLUME: NtStatus = NtStatus(0xc0000012);
pub const NT_STATUS_NO_MEDIA_IN_DEVICE: NtStatus = NtStatus(0xc0000013);
pub const NT_STATUS_UNRECOGNIZED_MEDIA: NtStatus = NtStatus(0xc0000014);
pub const NT_STATUS_NONEXISTENT_SECTOR: NtStatus = NtStatus(0xc0000015);
pub const NT_STATUS_MORE_PROCESSING_REQUIRED: NtStatus = NtStatus(0xc0000016);
pub const NT_STATUS_NO_MEMORY: NtStatus = NtStatus(0xc0000017);
pub const NT_STATUS_CONFLICTING_ADDRESSES: NtStatus = NtStatus(0xc0000018);
pub const NT_STATUS_NOT_MAPPED_VIEW: NtStatus = NtStatus(0xc0000019);
pub const NT_STATUS_UNABLE_TO_FREE_VM: NtStatus = NtStatus(0xc000001a);
pub const NT_STATUS_UNABLE_TO_DELETE_SECTION: NtStatus = NtStatus(0xc000001b);
pub const NT_STATUS_INVALID_SYSTEM_SERVICE: NtStatus = NtStatus(0xc000001c);
pub const NT_STATUS_ILLEGAL_INSTRUCTION: NtStatus = NtStatus(0xc000001d);
pub const NT_STATUS_INVALID_LOCK_SEQUENCE: NtStatus = NtStatus(0xc000001e);
pub const NT_STATUS_INVALID_VIEW_SIZE: NtStatus = NtStatus(0xc000001f);
pub const NT_STATUS_INVALID_FILE_FOR_SECTION: NtStatus = NtStatus(0xc0000020);
pub const NT_STATUS_ALREADY_COMMITTED: NtStatus = NtStatus(0xc0000021);
pub const NT_STATUS_ACCESS_DENIED: NtStatus = NtStatus(0xc0000022);
pub const NT_STATUS_BUFFER_TOO_SMALL: NtStatus = NtStatus(0xc0000023);
pub const NT_STATUS_OBJECT_TYPE_MISMATCH: NtStatus = NtStatus(0xc0000024);
pub const NT_STATUS_NONCONTINUABLE_EXCEPTION: NtStatus = NtStatus(0xc0000025);
pub const NT_STATUS_INVALID_DISPOSITION: NtStatus = NtStatus(0xc0000026);
pub const NT_STATUS_UNWIND: NtStatus = NtStatus(0xc0000027);
pub const NT_STATUS_BAD_STACK: NtStatus = NtStatus(0xc0000028);
pub const NT_STATUS_INVALID_UNWIND_TARGET: NtStatus = NtStatus(0xc0000029);
pub const NT_STATUS_NOT_LOCKED: NtStatus = NtStatus(0xc000002a);
pub const NT_STATUS_PARITY_ERROR: NtStatus = NtStatus(0xc000002b);
pub const NT_STATUS_UNABLE_TO_DECOMMIT_VM: NtStatus = NtStatus(0xc000002c);
pub const NT_STATUS_NOT_COMMITTED: NtStatus = NtStatus(0xc000002d);
pub const NT_STATUS_INVALID_PORT_ATTRIBUTES: NtStatus = NtStatus(0xc000002e);
pub const NT_STATUS_PORT_MESSAGE_TOO_LONG: NtStatus = NtStatus(0xc000002f);
pub const NT_STATUS_INVALID_PARAMETER_MIX: NtStatus = NtStatus(0xc0000030);
pub const NT_STATUS_INVALID_QUOTA_LOWER: NtStatus = NtStatus(0xc0000031);
pub const NT_STATUS_DISK_CORRUPT_ERROR: NtStatus = NtStatus(0xc0000032);
pub const NT_STATUS_OBJECT_NAME_INVALID: NtStatus = NtStatus(0xc0000033);
pub const NT_STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xc0000034);
pub const NT_STATUS_OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xc0000035);
pub const NT_STATUS_PORT_DISCONNECTED: NtStatus = NtStatus(0xc0000037);
pub const NT_STATUS_DEVICE_ALREADY_ATTACHED: NtStatus = NtStatus(0xc0000038);
pub const NT_STATUS_OBJECT_PATH_INVALID: NtStatus = NtStatus(0xc0000039);
pub const NT_STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xc000003a);
pub const NT_STATUS_OBJECT_PATH_SYNTAX_BAD: NtStatus = NtStatus(0xc000003b);
pub const NT_STATUS_DATA_OVERRUN: NtStatus = NtStatus(0xc000003c);
pub const NT_STATUS_DATA_LATE_ERROR: NtStatus = NtStatus(0xc000003d);
pub const NT_STATUS_DATA_ERROR: NtStatus = NtStatus(0xc000003e);
pub const NT_STATUS_CRC_ERROR: NtStatus = NtStatus(0xc000003f);
pub const NT_STATUS_SECTION_TOO_BIG: NtStatus = NtStatus(0xc0000040);
pub const NT_STATUS_PORT_CONNECTION_REFUSED: NtStatus = NtStatus(0xc0000041);
pub const NT_STATUS_INVALID_PORT_HANDLE: NtStatus = NtStatus(0xc0000042);
pub const NT_STATUS_SHARING_VIOLATION: NtStatus = NtStatus(0xc0000043);
pub const NT_STATUS_QUOTA_EXCEEDED: NtStatus = NtStatus(0xc0000044);
pub const NT_STATUS_INVALID_PAGE_PROTECTION: NtStatus = NtStatus(0xc0000045);
pub const NT_STATUS_MUTANT_NOT_OWNED: NtStatus = NtStatus(0xc0000046);
pub const NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED: NtStatus = NtStatus(0xc0000047);
pub const NT_STATUS_PORT_ALREADY_SET: NtStatus = NtStatus(0xc0000048);
pub const NT_STATUS_SECTION_NOT_IMAGE: NtStatus = NtStatus(0xc0000049);
pub const NT_STATUS_SUSPEND_COUNT_EXCEEDED: NtStatus = NtStatus(0xc000004a);
pub const NT_STATUS_THREAD_IS_TERMINATING: NtStatus = NtStatus(0xc000004b);
pub const NT_STATUS_BAD_WORKING_SET_LIMIT: NtStatus = NtStatus(0xc000004c);
pub const NT_STATUS_INCOMPATIBLE_FILE_MAP: NtStatus = NtStatus(0xc000004d);
pub const NT_STATUS_SECTION_PROTECTION: NtStatus = NtStatus(0xc000004e);
pub const NT_STATUS_EAS_NOT_SUPPORTED: NtStatus = NtStatus(0xc000004f);
pub const NT_STATUS_EA_TOO_LARGE: NtStatus = NtStatus(0xc0000050);
pub const NT_STATUS_NONEXISTENT_EA_ENTRY: NtStatus = NtStatus(0xc0000051);
pub const NT_STATUS_NO_EAS_ON_FILE: NtStatus = NtStatus(0xc0000052);
pub const NT_STATUS_EA_CORRUPT_ERROR: NtStatus = NtStatus(0xc0000053);
pub const NT_STATUS_FILE_LOCK_CONFLICT: NtStatus = NtStatus(0xc0000054);
pub const NT_STATUS_LOCK_NOT_GRANTED: NtStatus = NtStatus(0xc0000055);
pub const NT_STATUS_DELETE_PENDING: NtStatus = NtStatus(0xc0000056);
pub const NT_STATUS_CTL_FILE_NOT_SUPPORTED: NtStatus = NtStatus(0xc0000057);
pub const NT_STATUS_UNKNOWN_REVISION: NtStatus = NtStatus(0xc0000058);
pub const NT_STATUS_REVISION_MISMATCH: NtStatus = NtStatus(0xc0000059);
pub const NT_STATUS_INVALID_OWNER: NtStatus = NtStatus(0xc000005a);
pub const NT_STATUS_INVALID_PRIMARY_GROUP: NtStatus = NtStatus(0xc000005b);
pub const NT_STATUS_NO_IMPERSONATION_TOKEN: NtStatus = NtStatus(0xc000005c);
pub const NT_STATUS_CANT_DISABLE_MANDATORY: NtStatus = NtStatus(0xc000005d);
pub const NT_STATUS_NO_LOGON_SERVERS: NtStatus = NtStatus(0xc000005e);
pub const NT_STATUS_NO_SUCH_LOGON_SESSION: NtStatus = NtStatus(0xc000005f);
pub const NT_STATUS_NO_SUCH_PRIVILEGE: NtStatus = NtStatus(0xc0000060);
pub const NT_STATUS_PRIVILEGE_NOT_HELD: NtStatus = NtStatus(0xc0000061);
pub const NT_STATUS_INVALID_ACCOUNT_NAME: NtStatus = NtStatus(0xc0000062);
pub const NT_STATUS_USER_EXISTS: NtStatus = NtStatus(0xc0000063);
pub const NT_STATUS_NO_SUCH_USER: NtStatus = NtStatus(0xc0000064);
pub const NT_STATUS_GROUP_EXISTS: NtStatus = NtStatus(0xc0000065);
pub const NT_STATUS_NO_SUCH_GROUP: NtStatus = NtStatus(0xc0000066);
pub const NT_STATUS_MEMBER_IN_GROUP: NtStatus = NtStatus(0xc0000067);
pub const NT_STATUS_MEMBER_NOT_IN_GROUP: NtStatus = NtStatus(0xc0000068);
pub const NT_STATUS_LAST_ADMIN: NtStatus = NtStatus(0xc0000069);
pub const NT_STATUS_WRONG_PASSWORD: NtStatus = NtStatus(0xc000006a);
pub const NT_STATUS_ILL_FORMED_PASSWORD: NtStatus = NtStatus(0xc000006b);
pub const NT_STATUS_PASSWORD_RESTRICTION: NtStatus = NtStatus(0xc000006c);
pub const NT_STATUS_LOGON_FAILURE: NtStatus = NtStatus(0xc000006d);
pub const NT_STATUS_ACCOUNT_RESTRICTION: NtStatus = NtStatus(0xc000006e);
pub const NT_STATUS_INVALID_LOGON_HOURS: NtStatus = NtStatus(0xc000006f);
pub const NT_STATUS_INVALID_WORKSTATION: NtStatus = NtStatus(0xc0000070);
pub const NT_STATUS_PASSWORD_EXPIRED: NtStatus = NtStatus(0xc0000071);
pub const NT_STATUS_ACCOUNT_DISABLED: NtStatus = NtStatus(0xc0000072);
pub const NT_STATUS_NONE_MAPPED: NtStatus = NtStatus(0xc0000073);
pub const NT_STATUS_TOO_MANY_LUIDS_REQUESTED: NtStatus = NtStatus(0xc0000074);
pub const NT_STATUS_LUIDS_EXHAUSTED: NtStatus = NtStatus(0xc0000075);
pub const NT_STATUS_INVALID_SUB_AUTHORITY: NtStatus = NtStatus(0xc0000076);
pub const NT_STATUS_INVALID_ACL: NtStatus = NtStatus(0xc0000077);
pub const NT_STATUS_INVALID_SID: NtStatus = NtStatus(0xc0000078);
pub const NT_STATUS_INVALID_SECURITY_DESCR: NtStatus = NtStatus(0xc0000079);
pub const NT_STATUS_PROCEDURE_NOT_FOUND: NtStatus = NtStatus(0xc000007a);
pub const NT_STATUS_INVALID_IMAGE_FORMAT: NtStatus = NtStatus(0xc000007b);
pub const NT_STATUS_NO_TOKEN: NtStatus = NtStatus(0xc000007c);
pub const NT_STATUS_BAD_INHERITANCE_ACL: NtStatus = NtStatus(0xc000007d);
pub const NT_STATUS_RANGE_NOT_LOCKED: NtStatus = NtStatus(0xc000007e);
pub const NT_STATUS_DISK_FULL: NtStatus = NtStatus(0xc000007f);
pub const NT_STATUS_SERVER_DISABLED: NtStatus = NtStatus(0xc0000080);
pub const NT_STATUS_SERVER_NOT_DISABLED: NtStatus = NtStatus(0xc0000081);
pub const NT_STATUS_TOO_MANY_GUIDS_REQUESTED: NtStatus = NtStatus(0xc0000082);
pub const NT_STATUS_GUIDS_EXHAUSTED: NtStatus = NtStatus(0xc0000083);
pub const NT_STATUS_INVALID_ID_AUTHORITY: NtStatus = NtStatus(0xc0000084);
pub const NT_STATUS_AGENTS_EXHAUSTED: NtStatus = NtStatus(0xc0000085);
pub const NT_STATUS_INVALID_VOLUME_LABEL: NtStatus = NtStatus(0xc0000086);
pub const NT_STATUS_SECTION_NOT_EXTENDED: NtStatus = NtStatus(0xc0000087);
pub const NT_STATUS_NOT_MAPPED_DATA: NtStatus = NtStatus(0xc0000088);
pub const NT_STATUS_RESOURCE_DATA_NOT_FOUND: NtStatus = NtStatus(0xc0000089);
pub const NT_STATUS_RESOURCE_TYPE_NOT_FOUND: NtStatus = NtStatus(0xc000008a);
pub const NT_STATUS_RESOURCE_NAME_NOT_FOUND: NtStatus = NtStatus(0xc000008b);
pub const NT_STATUS_ARRAY_BOUNDS_EXCEEDED: NtStatus = NtStatus(0xc000008c);
pub const NT_STATUS_FLOAT_DENORMAL_OPERAND: NtStatus = NtStatus(0xc000008d);
pub const NT_STATUS_FLOAT_DIVIDE_BY_ZERO: NtStatus = NtStatus(0xc000008e);
pub const NT_STATUS_FLOAT_INEXACT_RESULT: NtStatus = NtStatus(0xc000008f);
pub const NT_STATUS_FLOAT_INVALID_OPERATION: NtStatus = NtStatus(0xc0000090);
pub const NT_STATUS_FLOAT_OVERFLOW: NtStatus = NtStatus(0xc0000091);
pub const NT_STATUS_FLOAT_STACK_CHECK: NtStatus = NtStatus(0xc0000092);
pub const NT_STATUS_FLOAT_UNDERFLOW: NtStatus = NtStatus(0xc0000093);
pub const NT_STATUS_INTEGER_DIVIDE_BY_ZERO: NtStatus = NtStatus(0xc0000094);
pub const NT_STATUS_INTEGER_OVERFLOW: NtStatus = NtStatus(0xc0000095);
pub const NT_STATUS_PRIVILEGED_INSTRUCTION: NtStatus = NtStatus(0xc0000096);
pub const NT_STATUS_TOO_MANY_PAGING_FILES: NtStatus = NtStatus(0xc0000097);
pub const NT_STATUS_FILE_INVALID: NtStatus = NtStatus(0xc0000098);
pub const NT_STATUS_ALLOTTED_SPACE_EXCEEDED: NtStatus = NtStatus(0xc0000099);
pub const NT_STATUS_INSUFFICIENT_RESOURCES: NtStatus = NtStatus(0xc000009a);
pub const NT_STATUS_DFS_EXIT_PATH_FOUND: NtStatus = NtStatus(0xc000009b);
pub const NT_STATUS_DEVICE_DATA_ERROR: NtStatus = NtStatus(0xc000009c);
pub const NT_STATUS_DEVICE_NOT_CONNECTED: NtStatus = NtStatus(0xc000009d);
pub const NT_STATUS_FREE_VM_NOT_AT_BASE: NtStatus = NtStatus(0xc000009f);
pub const NT_STATUS_MEMORY_NOT_ALLOCATED: NtStatus = NtStatus(0xc00000a0);
pub const NT_STATUS_WORKING_SET_QUOTA: NtStatus = NtStatus(0xc00000a1);
pub const NT_STATUS_MEDIA_WRITE_PROTECTED: NtStatus = NtStatus(0xc00000a2);
pub const NT_STATUS_DEVICE_NOT_READY: NtStatus = NtStatus(0xc00000a3);
pub const NT_STATUS_INVALID_GROUP_ATTRIBUTES: NtStatus = NtStatus(0xc00000a4);
pub const NT_STATUS_BAD_IMPERSONATION_LEVEL: NtStatus = NtStatus(0xc00000a5);
pub const NT_STATUS_CANT_OPEN_ANONYMOUS: NtStatus = NtStatus(0xc00000a6);
pub const NT_STATUS_BAD_VALIDATION_CLASS: NtStatus = NtStatus(0xc00000a7);
pub const NT_STATUS_BAD_TOKEN_TYPE: NtStatus = NtStatus(0xc00000a8);
pub const NT_STATUS_BAD_MASTER_BOOT_RECORD: NtStatus = NtStatus(0xc00000a9);
pub const NT_STATUS_INSTRUCTION_MISALIGNMENT: NtStatus = NtStatus(0xc00000aa);
pub const NT_STATUS_INSTANCE_NOT_AVAILABLE: NtStatus = NtStatus(0xc00000ab);
pub const NT_STATUS_PIPE_NOT_AVAILABLE: NtStatus = NtStatus(0xc00000ac);
pub const NT_STATUS_INVALID_PIPE_STATE: NtStatus = NtStatus(0xc00000ad);
pub const NT_STATUS_PIPE_BUSY: NtStatus = NtStatus(0xc00000ae);
pub const NT_STATUS_ILLEGAL_FUNCTION: NtStatus = NtStatus(0xc00000af);
pub const NT_STATUS_PIPE_DISCONNECTED: NtStatus = NtStatus(0xc00000b0);
pub const NT_STATUS_PIPE_CLOSING: NtStatus = NtStatus(0xc00000b1);
pub const NT_STATUS_PIPE_CONNECTED: NtStatus = NtStatus(0xc00000b2);
pub const NT_STATUS_PIPE_LISTENING: NtStatus = NtStatus(0xc00000b3);
pub const NT_STATUS_INVALID_READ_MODE: NtStatus = NtStatus(0xc00000b4);
pub const NT_STATUS_IO_TIMEOUT: NtStatus = NtStatus(0xc00000b5);
pub const NT_STATUS_FILE_FORCED_CLOSED: NtStatus = NtStatus(0xc00000b6);
pub const NT_STATUS_PROFILING_NOT_STARTED: NtStatus = NtStatus(0xc00000b7);
pub const NT_STATUS_PROFILING_NOT_STOPPED: NtStatus = NtStatus(0xc00000b8);
pub const NT_STATUS_COULD_NOT_INTERPRET: NtStatus = NtStatus(0xc00000b9);
pub const NT_STATUS_FILE_IS_A_DIRECTORY: NtStatus = NtStatus(0xc00000ba);
pub const NT_STATUS_NOT_SUPPORTED: NtStatus = NtStatus(0xc00000bb);
pub const NT_STATUS_REMOTE_NOT_LISTENING: NtStatus = NtStatus(0xc00000bc);
pub const NT_STATUS_DUPLICATE_NAME: NtStatus = NtStatus(0xc00000bd);
pub const NT_STATUS_BAD_NETWORK_PATH: NtStatus = NtStatus(0xc00000be);
pub const NT_STATUS_NETWORK_BUSY: NtStatus = NtStatus(0xc00000bf);
pub const NT_STATUS_DEVICE_DOES_NOT_EXIST: NtStatus = NtStatus(0xc00000c0);
pub const NT_STATUS_TOO_MANY_COMMANDS: NtStatus = NtStatus(0xc00000c1);
pub const NT_STATUS_ADAPTER_HARDWARE_ERROR: NtStatus = NtStatus(0xc00000c2);
pub const NT_STATUS_INVALID_NETWORK_RESPONSE: NtStatus = NtStatus(0xc00000c3);
pub const NT_STATUS_UNEXPECTED_NETWORK_ERROR: NtStatus = NtStatus(0xc00000c4);
pub const NT_STATUS_BAD_REMOTE_ADAPTER: NtStatus = NtStatus(0xc00000c5);
pub const NT_STATUS_PRINT_QUEUE_FULL: NtStatus = NtStatus(0xc00000c6);
pub const NT_STATUS_NO_SPOOL_SPACE: NtStatus = NtStatus(0xc00000c7);
pub const NT_STATUS_PRINT_CANCELLED: NtStatus = NtStatus(0xc00000c8);
pub const NT_STATUS_NETWORK_NAME_DELETED: NtStatus = NtStatus(0xc00000c9);
pub const NT_STATUS_NETWORK_ACCESS_DENIED: NtStatus = NtStatus(0xc00000ca);
pub const NT_STATUS_BAD_DEVICE_TYPE: NtStatus = NtStatus(0xc00000cb);
pub const NT_STATUS_BAD_NETWORK_NAME: NtStatus = NtStatus(0xc00000cc);
pub const NT_STATUS_TOO_MANY_NAMES: NtStatus = NtStatus(0xc00000cd);
pub const NT_STATUS_TOO_MANY_SESSIONS: NtStatus = NtStatus(0xc00000ce);
pub const NT_STATUS_SHARING_PAUSED: NtStatus = NtStatus(0xc00000cf);
pub const NT_STATUS_REQUEST_NOT_ACCEPTED: NtStatus = NtStatus(0xc00000d0);
pub const NT_STATUS_REDIRECTOR_PAUSED: NtStatus = NtStatus(0xc00000d1);
pub const NT_STATUS_NET_WRITE_FAULT: NtStatus = NtStatus(0xc00000d2);
pub const NT_STATUS_PROFILING_AT_LIMIT: NtStatus = NtStatus(0xc00000d3);
pub const NT_STATUS_NOT_SAME_DEVICE: NtStatus = NtStatus(0xc00000d4);
pub const NT_STATUS_FILE_RENAMED: NtStatus = NtStatus(0xc00000d5);
pub const NT_STATUS_VIRTUAL_CIRCUIT_CLOSED: NtStatus = NtStatus(0xc00000d6);
pub const NT_STATUS_NO_SECURITY_ON_OBJECT: NtStatus = NtStatus(0xc00000d7);
pub const NT_STATUS_CANT_WAIT: NtStatus = NtStatus(0xc00000d8);
pub const NT_STATUS_PIPE_EMPTY: NtStatus = NtStatus(0xc00000d9);
pub const NT_STATUS_CANT_ACCESS_DOMAIN_INFO: NtStatus = NtStatus(0xc00000da);
pub const NT_STATUS_CANT_TERMINATE_SELF: NtStatus = NtStatus(0xc00000db);
pub const NT_STATUS_INVALID_SERVER_STATE: NtStatus = NtStatus(0xc00000dc);
pub const NT_STATUS_INVALID_DOMAIN_STATE: NtStatus = NtStatus(0xc00000dd);
pub const NT_STATUS_INVALID_DOMAIN_ROLE: NtStatus = NtStatus(0xc00000de);
pub const NT_STATUS_NO_SUCH_DOMAIN: NtStatus = NtStatus(0xc00000df);
pub const NT_STATUS_DOMAIN_EXISTS: NtStatus = NtStatus(0xc00000e0);
pub const NT_STATUS_DOMAIN_LIMIT_EXCEEDED: NtStatus = NtStatus(0xc00000e1);
pub const NT_STATUS_OPLOCK_NOT_GRANTED: NtStatus = NtStatus(0xc00000e2);
pub const NT_STATUS_INVALID_OPLOCK_PROTOCOL: NtStatus = NtStatus(0xc00000e3);
pub const NT_STATUS_INTERNAL_DB_CORRUPTION: NtStatus = NtStatus(0xc00000e4);
pub const NT_STATUS_INTERNAL_ERROR: NtStatus = NtStatus(0xc00000e5);
pub const NT_STATUS_GENERIC_NOT_MAPPED: NtStatus = NtStatus(0xc00000e6);
pub const NT_STATUS_BAD_DESCRIPTOR_FORMAT: NtStatus = NtStatus(0xc00000e7);
pub const NT_STATUS_INVALID_USER_BUFFER: NtStatus = NtStatus(0xc00000e8);
pub const NT_STATUS_UNEXPECTED_IO_ERROR: NtStatus = NtStatus(0xc00000e9);
pub const NT_STATUS_UNEXPECTED_MM_CREATE_ERR: NtStatus = NtStatus(0xc00000ea);
pub const NT_STATUS_UNEXPECTED_MM_MAP_ERROR: NtStatus = NtStatus(0xc00000eb);
pub const NT_STATUS_UNEXPECTED_MM_EXTEND_ERR: NtStatus = NtStatus(0xc00000ec);
pub const NT_STATUS_NOT_LOGON_PROCESS: NtStatus = NtStatus(0xc00000ed);
pub const NT_STATUS_LOGON_SESSION_EXISTS: NtStatus = NtStatus(0xc00000ee);
pub const NT_STATUS_INVALID_PARAMETER_1: NtStatus = NtStatus(0xc00000ef);
pub const NT_STATUS_INVALID_PARAMETER_2: NtStatus = NtStatus(0xc00000f0);
pub const NT_STATUS_INVALID_PARAMETER_3: NtStatus = NtStatus(0xc00000f1);
pub const NT_STATUS_INVALID_PARAMETER_4: NtStatus = NtStatus(0xc00000f2);
pub const NT_STATUS_INVALID_PARAMETER_5: NtStatus = NtStatus(0xc00000f3);
pub const NT_STATUS_INVALID_PARAMETER_6: NtStatus = NtStatus(0xc00000f4);
pub const NT_STATUS_INVALID_PARAMETER_7: NtStatus = NtStatus(0xc00000f5);
pub const NT_STATUS_INVALID_PARAMETER_8: NtStatus = NtStatus(0xc00000f6);
pub const NT_STATUS_INVALID_PARAMETER_9: NtStatus = NtStatus(0xc00000f7);
pub const NT_STATUS_INVALID_PARAMETER_10: NtStatus = NtStatus(0xc00000f8);
pub const NT_STATUS_INVALID_PARAMETER_11: NtStatus = NtStatus(0xc00000f9);
pub const NT_STATUS_INVALID_PARAMETER_12: NtStatus = NtStatus(0xc00000fa);
pub const NT_STATUS_REDIRECTOR_NOT_STARTED: NtStatus = NtStatus(0xc00000fb);
pub const NT_STATUS_REDIRECTOR_STARTED: NtStatus = NtStatus(0xc00000fc);
pub const NT_STATUS_STACK_OVERFLOW: NtStatus = NtStatus(0xc00000fd);
pub const NT_STATUS_NO_SUCH_PACKAGE: NtStatus = NtStatus(0xc00000fe);
pub const NT_STATUS_BAD_FUNCTION_TABLE: NtStatus = NtStatus(0xc00000ff);
pub const NT_STATUS_VARIABLE_NOT_FOUND: NtStatus = NtStatus(0xc0000100);
pub const NT_STATUS_DIRECTORY_NOT_EMPTY: NtStatus = NtStatus(0xc0000101);
pub const NT_STATUS_FILE_CORRUPT_ERROR: NtStatus = NtStatus(0xc0000102);
pub const NT_STATUS_NOT_A_DIRECTORY: NtStatus = NtStatus(0xc0000103);
pub const NT_STATUS_BAD_LOGON_SESSION_STATE: NtStatus = NtStatus(0xc0000104);
pub const NT_STATUS_LOGON_SESSION_COLLISION: NtStatus = NtStatus(0xc0000105);
pub const NT_STATUS_NAME_TOO_LONG: NtStatus = NtStatus(0xc0000106);
pub const NT_STATUS_FILES_OPEN: NtStatus = NtStatus(0xc0000107);
pub const NT_STATUS_CONNECTION_IN_USE: NtStatus = NtStatus(0xc0000108);
pub const NT_STATUS_MESSAGE_NOT_FOUND: NtStatus = NtStatus(0xc0000109);
pub const NT_STATUS_PROCESS_IS_TERMINATING: NtStatus = NtStatus(0xc000010a);
pub const NT_STATUS_INVALID_LOGON_TYPE: NtStatus = NtStatus(0xc000010b);
pub const NT_STATUS_NO_GUID_TRANSLATION: NtStatus = NtStatus(0xc000010c);
pub const NT_STATUS_CANNOT_IMPERSONATE: NtStatus = NtStatus(0xc000010d);
pub const NT_STATUS_IMAGE_ALREADY_LOADED: NtStatus = NtStatus(0xc000010e);
pub const NT_STATUS_NO_LDT: NtStatus = NtStatus(0xc0000117);
pub const NT_STATUS_INVALID_LDT_SIZE: NtStatus = NtStatus(0xc0000118);
pub const NT_STATUS_INVALID_LDT_OFFSET: NtStatus = NtStatus(0xc0000119);
pub const NT_STATUS_INVALID_LDT_DESCRIPTOR: NtStatus = NtStatus(0xc000011a);
pub const NT_STATUS_INVALID_IMAGE_NE_FORMAT: NtStatus = NtStatus(0xc000011b);
pub const NT_STATUS_RXACT_INVALID_STATE: NtStatus = NtStatus(0xc000011c);
pub const NT_STATUS_RXACT_COMMIT_FAILURE: NtStatus = NtStatus(0xc000011d);
pub const NT_STATUS_MAPPED_FILE_SIZE_ZERO: NtStatus = NtStatus(0xc000011e);
pub const NT_STATUS_TOO_MANY_OPENED_FILES: NtStatus = NtStatus(0xc000011f);
pub const NT_STATUS_CANCELLED: NtStatus = NtStatus(0xc0000120);
pub const NT_STATUS_CANNOT_DELETE: NtStatus = NtStatus(0xc0000121);
pub const NT_STATUS_INVALID_COMPUTER_NAME: NtStatus = NtStatus(0xc0000122);
pub const NT_STATUS_FILE_DELETED: NtStatus = NtStatus(0xc0000123);
pub const NT_STATUS_SPECIAL_ACCOUNT: NtStatus = NtStatus(0xc0000124);
pub const NT_STATUS_SPECIAL_GROUP: NtStatus = NtStatus(0xc0000125);
pub const NT_STATUS_SPECIAL_USER: NtStatus = NtStatus(0xc0000126);
pub const NT_STATUS_MEMBERS_PRIMARY_GROUP: NtStatus = NtStatus(0xc0000127);
pub const NT_STATUS_FILE_CLOSED: NtStatus = NtStatus(0xc0000128);
pub const NT_STATUS_TOO_MANY_THREADS: NtStatus = NtStatus(0xc0000129);
pub const NT_STATUS_THREAD_NOT_IN_PROCESS: NtStatus = NtStatus(0xc000012a);
pub const NT_STATUS_TOKEN_ALREADY_IN_USE: NtStatus = NtStatus(0xc000012b);
pub const NT_STATUS_PAGEFILE_QUOTA_EXCEEDED: NtStatus = NtStatus(0xc000012c);
pub const NT_STATUS_COMMITMENT_LIMIT: NtStatus = NtStatus(0xc000012d);
pub const NT_STATUS_INVALID_IMAGE_LE_FORMAT: NtStatus = NtStatus(0xc000012e);
pub const NT_STATUS_INVALID_IMAGE_NOT_MZ: NtStatus = NtStatus(0xc000012f);
pub const NT_STATUS_INVALID_IMAGE_PROTECT: NtStatus = NtStatus(0xc0000130);
pub const NT_STATUS_INVALID_IMAGE_WIN_16: NtStatus = NtStatus(0xc0000131);
pub const NT_STATUS_LOGON_SERVER_CONFLICT: NtStatus = NtStatus(0xc0000132);
pub const NT_STATUS_TIME_DIFFERENCE_AT_DC: NtStatus = NtStatus(0xc0000133);
pub const NT_STATUS_SYNCHRONIZATION_REQUIRED: NtStatus = NtStatus(0xc0000134);
pub const NT_STATUS_DLL_NOT_FOUND: NtStatus = NtStatus(0xc0000135);
pub const NT_STATUS_OPEN_FAILED: NtStatus = NtStatus(0xc0000136);
pub const NT_STATUS_IO_PRIVILEGE_FAILED: NtStatus = NtStatus(0xc0000137);
pub const NT_STATUS_ORDINAL_NOT_FOUND: NtStatus = NtStatus(0xc0000138);
pub const NT_STATUS_ENTRYPOINT_NOT_FOUND: NtStatus = NtStatus(0xc0000139);
pub const NT_STATUS_CONTROL_C_EXIT: NtStatus = NtStatus(0xc000013a);
pub const NT_STATUS_LOCAL_DISCONNECT: NtStatus = NtStatus(0xc000013b);
pub const NT_STATUS_REMOTE_DISCONNECT: NtStatus = NtStatus(0xc000013c);
pub const NT_STATUS_REMOTE_RESOURCES: NtStatus = NtStatus(0xc000013d);
pub const NT_STATUS_LINK_FAILED: NtStatus = NtStatus(0xc000013e);
pub const NT_STATUS_LINK_TIMEOUT: NtStatus = NtStatus(0xc000013f);
pub const NT_STATUS_INVALID_CONNECTION: NtStatus = NtStatus(0xc0000140);
pub const NT_STATUS_INVALID_ADDRESS: NtStatus = NtStatus(0xc0000141);
pub const NT_STATUS_DLL_INIT_FAILED: NtStatus = NtStatus(0xc0000142);
pub const NT_STATUS_MISSING_SYSTEMFILE: NtStatus = NtStatus(0xc0000143);
pub const NT_STATUS_UNHANDLED_EXCEPTION: NtStatus = NtStatus(0xc0000144);
pub const NT_STATUS_APP_INIT_FAILURE: NtStatus = NtStatus(0xc0000145);
pub const NT_STATUS_PAGEFILE_CREATE_FAILED: NtStatus = NtStatus(0xc0000146);
pub const NT_STATUS_NO_PAGEFILE: NtStatus = NtStatus(0xc0000147);
pub const NT_STATUS_INVALID_LEVEL: NtStatus = NtStatus(0xc0000148);
pub const NT_STATUS_WRONG_PASSWORD_CORE: NtStatus = NtStatus(0xc0000149);
pub const NT_STATUS_ILLEGAL_FLOAT_CONTEXT: NtStatus = NtStatus(0xc000014a);
pub const NT_STATUS_PIPE_BROKEN: NtStatus = NtStatus(0xc000014b);
pub const NT_STATUS_REGISTRY_CORRUPT: NtStatus = NtStatus(0xc000014c);
pub const NT_STATUS_REGISTRY_IO_FAILED: NtStatus = NtStatus(0xc000014d);
pub const NT_STATUS_NO_EVENT_PAIR: NtStatus = NtStatus(0xc000014e);
pub const NT_STATUS_UNRECOGNIZED_VOLUME: NtStatus = NtStatus(0xc000014f);
pub const NT_STATUS_SERIAL_NO_DEVICE_INITED: NtStatus = NtStatus(0xc0000150);
pub const NT_STATUS_NO_SUCH_ALIAS: NtStatus = NtStatus(0xc0000151);
pub const NT_STATUS_MEMBER_NOT_IN_ALIAS: NtStatus = NtStatus(0xc0000152);
pub const NT_STATUS_MEMBER_IN_ALIAS: NtStatus = NtStatus(0xc0000153);
pub const NT_STATUS_ALIAS_EXISTS: NtStatus = NtStatus(0xc0000154);
pub const NT_STATUS_LOGON_NOT_GRANTED: NtStatus = NtStatus(0xc0000155);
pub const NT_STATUS_TOO_MANY_SECRETS: NtStatus = NtStatus(0xc0000156);
pub const NT_STATUS_SECRET_TOO_LONG: NtStatus = NtStatus(0xc0000157);
pub const NT_STATUS_INTERNAL_DB_ERROR: NtStatus = NtStatus(0xc0000158);
pub const NT_STATUS_FULLSCREEN_MODE: NtStatus = NtStatus(0xc0000159);
pub const NT_STATUS_TOO_MANY_CONTEXT_IDS: NtStatus = NtStatus(0xc000015a);
pub const NT_STATUS_LOGON_TYPE_NOT_GRANTED: NtStatus = NtStatus(0xc000015b);
pub const NT_STATUS_NOT_REGISTRY_FILE: NtStatus = NtStatus(0xc000015c);
pub const NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED: NtStatus =
    NtStatus(0xc000015d);
pub const NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR: NtStatus = NtStatus(0xc000015e);
pub const NT_STATUS_FT_MISSING_MEMBER: NtStatus = NtStatus(0xc000015f);
pub const NT_STATUS_ILL_FORMED_SERVICE_ENTRY: NtStatus = NtStatus(0xc0000160);
pub const NT_STATUS_ILLEGAL_CHARACTER: NtStatus = NtStatus(0xc0000161);
pub const NT_STATUS_UNMAPPABLE_CHARACTER: NtStatus = NtStatus(0xc0000162);
pub const NT_STATUS_UNDEFINED_CHARACTER: NtStatus = NtStatus(0xc0000163);
pub const NT_STATUS_FLOPPY_VOLUME: NtStatus = NtStatus(0xc0000164);
pub const NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND: NtStatus = NtStatus(0xc0000165);
pub const NT_STATUS_FLOPPY_WRONG_CYLINDER: NtStatus = NtStatus(0xc0000166);
pub const NT_STATUS_FLOPPY_UNKNOWN_ERROR: NtStatus = NtStatus(0xc0000167);
pub const NT_STATUS_FLOPPY_BAD_REGISTERS: NtStatus = NtStatus(0xc0000168);
pub const NT_STATUS_DISK_RECALIBRATE_FAILED: NtStatus = NtStatus(0xc0000169);
pub const NT_STATUS_DISK_OPERATION_FAILED: NtStatus = NtStatus(0xc000016a);
pub const NT_STATUS_DISK_RESET_FAILED: NtStatus = NtStatus(0xc000016b);
pub const NT_STATUS_SHARED_IRQ_BUSY: NtStatus = NtStatus(0xc000016c);
pub const NT_STATUS_FT_ORPHANING: NtStatus = NtStatus(0xc000016d);
pub const NT_STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT: NtStatus =
    NtStatus(0xc000016e);
pub const NT_STATUS_PARTITION_FAILURE: NtStatus = NtStatus(0xc0000172);
pub const NT_STATUS_INVALID_BLOCK_LENGTH: NtStatus = NtStatus(0xc0000173);
pub const NT_STATUS_DEVICE_NOT_PARTITIONED: NtStatus = NtStatus(0xc0000174);
pub const NT_STATUS_UNABLE_TO_LOCK_MEDIA: NtStatus = NtStatus(0xc0000175);
pub const NT_STATUS_UNABLE_TO_UNLOAD_MEDIA: NtStatus = NtStatus(0xc0000176);
pub const NT_STATUS_EOM_OVERFLOW: NtStatus = NtStatus(0xc0000177);
pub const NT_STATUS_NO_MEDIA: NtStatus = NtStatus(0xc0000178);
pub const NT_STATUS_NO_SUCH_MEMBER: NtStatus = NtStatus(0xc000017a);
pub const NT_STATUS_INVALID_MEMBER: NtStatus = NtStatus(0xc000017b);
pub const NT_STATUS_KEY_DELETED: NtStatus = NtStatus(0xc000017c);
pub const NT_STATUS_NO_LOG_SPACE: NtStatus = NtStatus(0xc000017d);
pub const NT_STATUS_TOO_MANY_SIDS: NtStatus = NtStatus(0xc000017e);
pub const NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED: NtStatus =
    NtStatus(0xc000017f);
pub const NT_STATUS_KEY_HAS_CHILDREN: NtStatus = NtStatus(0xc0000180);
pub const NT_STATUS_CHILD_MUST_BE_VOLATILE: NtStatus = NtStatus(0xc0000181);
pub const NT_STATUS_DEVICE_CONFIGURATION_ERROR: NtStatus = NtStatus(0xc0000182);
pub const NT_STATUS_DRIVER_INTERNAL_ERROR: NtStatus = NtStatus(0xc0000183);
pub const NT_STATUS_INVALID_DEVICE_STATE: NtStatus = NtStatus(0xc0000184);
pub const NT_STATUS_IO_DEVICE_ERROR: NtStatus = NtStatus(0xc0000185);
pub const NT_STATUS_DEVICE_PROTOCOL_ERROR: NtStatus = NtStatus(0xc0000186);
pub const NT_STATUS_BACKUP_CONTROLLER: NtStatus = NtStatus(0xc0000187);
pub const NT_STATUS_LOG_FILE_FULL: NtStatus = NtStatus(0xc0000188);
pub const NT_STATUS_TOO_LATE: NtStatus = NtStatus(0xc0000189);
pub const NT_STATUS_NO_TRUST_LSA_SECRET: NtStatus = NtStatus(0xc000018a);
pub const NT_STATUS_NO_TRUST_SAM_ACCOUNT: NtStatus = NtStatus(0xc000018b);
pub const NT_STATUS_TRUSTED_DOMAIN_FAILURE: NtStatus = NtStatus(0xc000018c);
pub const NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE: NtStatus =
    NtStatus(0xc000018d);
pub const NT_STATUS_EVENTLOG_FILE_CORRUPT: NtStatus = NtStatus(0xc000018e);
pub const NT_STATUS_EVENTLOG_CANT_START: NtStatus = NtStatus(0xc000018f);
pub const NT_STATUS_TRUST_FAILURE: NtStatus = NtStatus(0xc0000190);
pub const NT_STATUS_MUTANT_LIMIT_EXCEEDED: NtStatus = NtStatus(0xc0000191);
pub const NT_STATUS_NETLOGON_NOT_STARTED: NtStatus = NtStatus(0xc0000192);
pub const NT_STATUS_ACCOUNT_EXPIRED: NtStatus = NtStatus(0xc0000193);
pub const NT_STATUS_POSSIBLE_DEADLOCK: NtStatus = NtStatus(0xc0000194);
pub const NT_STATUS_NETWORK_CREDENTIAL_CONFLICT: NtStatus =
    NtStatus(0xc0000195);
pub const NT_STATUS_REMOTE_SESSION_LIMIT: NtStatus = NtStatus(0xc0000196);
pub const NT_STATUS_EVENTLOG_FILE_CHANGED: NtStatus = NtStatus(0xc0000197);
pub const NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT: NtStatus =
    NtStatus(0xc0000198);
pub const NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT: NtStatus =
    NtStatus(0xc0000199);
pub const NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT: NtStatus =
    NtStatus(0xc000019a);
pub const NT_STATUS_DOMAIN_TRUST_INCONSISTENT: NtStatus = NtStatus(0xc000019b);
pub const NT_STATUS_FS_DRIVER_REQUIRED: NtStatus = NtStatus(0xc000019c);
pub const NT_STATUS_IMAGE_ALREADY_LOADED_AS_DLL: NtStatus =
    NtStatus(0xc000019d);
pub const NT_STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING:
    NtStatus = NtStatus(0xc000019e);
pub const NT_STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME: NtStatus =
    NtStatus(0xc000019f);
pub const NT_STATUS_SECURITY_STREAM_IS_INCONSISTENT: NtStatus =
    NtStatus(0xc00001a0);
pub const NT_STATUS_INVALID_LOCK_RANGE: NtStatus = NtStatus(0xc00001a1);
pub const NT_STATUS_INVALID_ACE_CONDITION: NtStatus = NtStatus(0xc00001a2);
pub const NT_STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT: NtStatus =
    NtStatus(0xc00001a3);
pub const NT_STATUS_NOTIFICATION_GUID_ALREADY_DEFINED: NtStatus =
    NtStatus(0xc00001a4);
pub const NT_STATUS_NETWORK_OPEN_RESTRICTION: NtStatus = NtStatus(0xc0000201);
pub const NT_STATUS_NO_USER_SESSION_KEY: NtStatus = NtStatus(0xc0000202);
pub const NT_STATUS_USER_SESSION_DELETED: NtStatus = NtStatus(0xc0000203);
pub const NT_STATUS_RESOURCE_LANG_NOT_FOUND: NtStatus = NtStatus(0xc0000204);
pub const NT_STATUS_INSUFF_SERVER_RESOURCES: NtStatus = NtStatus(0xc0000205);
pub const NT_STATUS_INVALID_BUFFER_SIZE: NtStatus = NtStatus(0xc0000206);
pub const NT_STATUS_INVALID_ADDRESS_COMPONENT: NtStatus = NtStatus(0xc0000207);
pub const NT_STATUS_INVALID_ADDRESS_WILDCARD: NtStatus = NtStatus(0xc0000208);
pub const NT_STATUS_TOO_MANY_ADDRESSES: NtStatus = NtStatus(0xc0000209);
pub const NT_STATUS_ADDRESS_ALREADY_EXISTS: NtStatus = NtStatus(0xc000020a);
pub const NT_STATUS_ADDRESS_CLOSED: NtStatus = NtStatus(0xc000020b);
pub const NT_STATUS_CONNECTION_DISCONNECTED: NtStatus = NtStatus(0xc000020c);
pub const NT_STATUS_CONNECTION_RESET: NtStatus = NtStatus(0xc000020d);
pub const NT_STATUS_TOO_MANY_NODES: NtStatus = NtStatus(0xc000020e);
pub const NT_STATUS_TRANSACTION_ABORTED: NtStatus = NtStatus(0xc000020f);
pub const NT_STATUS_TRANSACTION_TIMED_OUT: NtStatus = NtStatus(0xc0000210);
pub const NT_STATUS_TRANSACTION_NO_RELEASE: NtStatus = NtStatus(0xc0000211);
pub const NT_STATUS_TRANSACTION_NO_MATCH: NtStatus = NtStatus(0xc0000212);
pub const NT_STATUS_TRANSACTION_RESPONDED: NtStatus = NtStatus(0xc0000213);
pub const NT_STATUS_TRANSACTION_INVALID_ID: NtStatus = NtStatus(0xc0000214);
pub const NT_STATUS_TRANSACTION_INVALID_TYPE: NtStatus = NtStatus(0xc0000215);
pub const NT_STATUS_NOT_SERVER_SESSION: NtStatus = NtStatus(0xc0000216);
pub const NT_STATUS_NOT_CLIENT_SESSION: NtStatus = NtStatus(0xc0000217);
pub const NT_STATUS_CANNOT_LOAD_REGISTRY_FILE: NtStatus = NtStatus(0xc0000218);
pub const NT_STATUS_DEBUG_ATTACH_FAILED: NtStatus = NtStatus(0xc0000219);
pub const NT_STATUS_SYSTEM_PROCESS_TERMINATED: NtStatus = NtStatus(0xc000021a);
pub const NT_STATUS_DATA_NOT_ACCEPTED: NtStatus = NtStatus(0xc000021b);
pub const NT_STATUS_NO_BROWSER_SERVERS_FOUND: NtStatus = NtStatus(0xc000021c);
pub const NT_STATUS_VDM_HARD_ERROR: NtStatus = NtStatus(0xc000021d);
pub const NT_STATUS_DRIVER_CANCEL_TIMEOUT: NtStatus = NtStatus(0xc000021e);
pub const NT_STATUS_REPLY_MESSAGE_MISMATCH: NtStatus = NtStatus(0xc000021f);
pub const NT_STATUS_MAPPED_ALIGNMENT: NtStatus = NtStatus(0xc0000220);
pub const NT_STATUS_IMAGE_CHECKSUM_MISMATCH: NtStatus = NtStatus(0xc0000221);
pub const NT_STATUS_LOST_WRITEBEHIND_DATA: NtStatus = NtStatus(0xc0000222);
pub const NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID: NtStatus =
    NtStatus(0xc0000223);
pub const NT_STATUS_PASSWORD_MUST_CHANGE: NtStatus = NtStatus(0xc0000224);
pub const NT_STATUS_NOT_FOUND: NtStatus = NtStatus(0xc0000225);
pub const NT_STATUS_NOT_TINY_STREAM: NtStatus = NtStatus(0xc0000226);
pub const NT_STATUS_RECOVERY_FAILURE: NtStatus = NtStatus(0xc0000227);
pub const NT_STATUS_STACK_OVERFLOW_READ: NtStatus = NtStatus(0xc0000228);
pub const NT_STATUS_FAIL_CHECK: NtStatus = NtStatus(0xc0000229);
pub const NT_STATUS_DUPLICATE_OBJECTID: NtStatus = NtStatus(0xc000022a);
pub const NT_STATUS_OBJECTID_EXISTS: NtStatus = NtStatus(0xc000022b);
pub const NT_STATUS_CONVERT_TO_LARGE: NtStatus = NtStatus(0xc000022c);
pub const NT_STATUS_RETRY: NtStatus = NtStatus(0xc000022d);
pub const NT_STATUS_FOUND_OUT_OF_SCOPE: NtStatus = NtStatus(0xc000022e);
pub const NT_STATUS_ALLOCATE_BUCKET: NtStatus = NtStatus(0xc000022f);
pub const NT_STATUS_PROPSET_NOT_FOUND: NtStatus = NtStatus(0xc0000230);
pub const NT_STATUS_MARSHALL_OVERFLOW: NtStatus = NtStatus(0xc0000231);
pub const NT_STATUS_INVALID_VARIANT: NtStatus = NtStatus(0xc0000232);
pub const NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND: NtStatus =
    NtStatus(0xc0000233);
pub const NT_STATUS_ACCOUNT_LOCKED_OUT: NtStatus = NtStatus(0xc0000234);
pub const NT_STATUS_HANDLE_NOT_CLOSABLE: NtStatus = NtStatus(0xc0000235);
pub const NT_STATUS_CONNECTION_REFUSED: NtStatus = NtStatus(0xc0000236);
pub const NT_STATUS_GRACEFUL_DISCONNECT: NtStatus = NtStatus(0xc0000237);
pub const NT_STATUS_ADDRESS_ALREADY_ASSOCIATED: NtStatus = NtStatus(0xc0000238);
pub const NT_STATUS_ADDRESS_NOT_ASSOCIATED: NtStatus = NtStatus(0xc0000239);
pub const NT_STATUS_CONNECTION_INVALID: NtStatus = NtStatus(0xc000023a);
pub const NT_STATUS_CONNECTION_ACTIVE: NtStatus = NtStatus(0xc000023b);
pub const NT_STATUS_NETWORK_UNREACHABLE: NtStatus = NtStatus(0xc000023c);
pub const NT_STATUS_HOST_UNREACHABLE: NtStatus = NtStatus(0xc000023d);
pub const NT_STATUS_PROTOCOL_UNREACHABLE: NtStatus = NtStatus(0xc000023e);
pub const NT_STATUS_PORT_UNREACHABLE: NtStatus = NtStatus(0xc000023f);
pub const NT_STATUS_REQUEST_ABORTED: NtStatus = NtStatus(0xc0000240);
pub const NT_STATUS_CONNECTION_ABORTED: NtStatus = NtStatus(0xc0000241);
pub const NT_STATUS_BAD_COMPRESSION_BUFFER: NtStatus = NtStatus(0xc0000242);
pub const NT_STATUS_USER_MAPPED_FILE: NtStatus = NtStatus(0xc0000243);
pub const NT_STATUS_AUDIT_FAILED: NtStatus = NtStatus(0xc0000244);
pub const NT_STATUS_TIMER_RESOLUTION_NOT_SET: NtStatus = NtStatus(0xc0000245);
pub const NT_STATUS_CONNECTION_COUNT_LIMIT: NtStatus = NtStatus(0xc0000246);
pub const NT_STATUS_LOGIN_TIME_RESTRICTION: NtStatus = NtStatus(0xc0000247);
pub const NT_STATUS_LOGIN_WKSTA_RESTRICTION: NtStatus = NtStatus(0xc0000248);
pub const NT_STATUS_IMAGE_MP_UP_MISMATCH: NtStatus = NtStatus(0xc0000249);
pub const NT_STATUS_INSUFFICIENT_LOGON_INFO: NtStatus = NtStatus(0xc0000250);
pub const NT_STATUS_BAD_DLL_ENTRYPOINT: NtStatus = NtStatus(0xc0000251);
pub const NT_STATUS_BAD_SERVICE_ENTRYPOINT: NtStatus = NtStatus(0xc0000252);
pub const NT_STATUS_LPC_REPLY_LOST: NtStatus = NtStatus(0xc0000253);
pub const NT_STATUS_IP_ADDRESS_CONFLICT1: NtStatus = NtStatus(0xc0000254);
pub const NT_STATUS_IP_ADDRESS_CONFLICT2: NtStatus = NtStatus(0xc0000255);
pub const NT_STATUS_REGISTRY_QUOTA_LIMIT: NtStatus = NtStatus(0xc0000256);
pub const NT_STATUS_PATH_NOT_COVERED: NtStatus = NtStatus(0xc0000257);
pub const NT_STATUS_NO_CALLBACK_ACTIVE: NtStatus = NtStatus(0xc0000258);
pub const NT_STATUS_LICENSE_QUOTA_EXCEEDED: NtStatus = NtStatus(0xc0000259);
pub const NT_STATUS_PWD_TOO_SHORT: NtStatus = NtStatus(0xc000025a);
pub const NT_STATUS_PWD_TOO_RECENT: NtStatus = NtStatus(0xc000025b);
pub const NT_STATUS_PWD_HISTORY_CONFLICT: NtStatus = NtStatus(0xc000025c);
pub const NT_STATUS_PLUGPLAY_NO_DEVICE: NtStatus = NtStatus(0xc000025e);
pub const NT_STATUS_UNSUPPORTED_COMPRESSION: NtStatus = NtStatus(0xc000025f);
pub const NT_STATUS_INVALID_HW_PROFILE: NtStatus = NtStatus(0xc0000260);
pub const NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH: NtStatus =
    NtStatus(0xc0000261);
pub const NT_STATUS_DRIVER_ORDINAL_NOT_FOUND: NtStatus = NtStatus(0xc0000262);
pub const NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND: NtStatus =
    NtStatus(0xc0000263);
pub const NT_STATUS_RESOURCE_NOT_OWNED: NtStatus = NtStatus(0xc0000264);
pub const NT_STATUS_TOO_MANY_LINKS: NtStatus = NtStatus(0xc0000265);
pub const NT_STATUS_QUOTA_LIST_INCONSISTENT: NtStatus = NtStatus(0xc0000266);
pub const NT_STATUS_FILE_IS_OFFLINE: NtStatus = NtStatus(0xc0000267);
pub const NT_STATUS_EVALUATION_EXPIRATION: NtStatus = NtStatus(0xc0000268);
pub const NT_STATUS_ILLEGAL_DLL_RELOCATION: NtStatus = NtStatus(0xc0000269);
pub const NT_STATUS_LICENSE_VIOLATION: NtStatus = NtStatus(0xc000026a);
pub const NT_STATUS_DLL_INIT_FAILED_LOGOFF: NtStatus = NtStatus(0xc000026b);
pub const NT_STATUS_DRIVER_UNABLE_TO_LOAD: NtStatus = NtStatus(0xc000026c);
pub const NT_STATUS_DFS_UNAVAILABLE: NtStatus = NtStatus(0xc000026d);
pub const NT_STATUS_VOLUME_DISMOUNTED: NtStatus = NtStatus(0xc000026e);
pub const NT_STATUS_WX86_INTERNAL_ERROR: NtStatus = NtStatus(0xc000026f);
pub const NT_STATUS_WX86_FLOAT_STACK_CHECK: NtStatus = NtStatus(0xc0000270);
pub const NT_STATUS_VALIDATE_CONTINUE: NtStatus = NtStatus(0xc0000271);
pub const NT_STATUS_NO_MATCH: NtStatus = NtStatus(0xc0000272);
pub const NT_STATUS_NO_MORE_MATCHES: NtStatus = NtStatus(0xc0000273);
pub const NT_STATUS_NOT_A_REPARSE_POINT: NtStatus = NtStatus(0xc0000275);
pub const NT_STATUS_IO_REPARSE_TAG_INVALID: NtStatus = NtStatus(0xc0000276);
pub const NT_STATUS_IO_REPARSE_TAG_MISMATCH: NtStatus = NtStatus(0xc0000277);
pub const NT_STATUS_IO_REPARSE_DATA_INVALID: NtStatus = NtStatus(0xc0000278);
pub const NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED: NtStatus = NtStatus(0xc0000279);
pub const NT_STATUS_REPARSE_POINT_NOT_RESOLVED: NtStatus = NtStatus(0xc0000280);
pub const NT_STATUS_DIRECTORY_IS_A_REPARSE_POINT: NtStatus =
    NtStatus(0xc0000281);
pub const NT_STATUS_RANGE_LIST_CONFLICT: NtStatus = NtStatus(0xc0000282);
pub const NT_STATUS_SOURCE_ELEMENT_EMPTY: NtStatus = NtStatus(0xc0000283);
pub const NT_STATUS_DESTINATION_ELEMENT_FULL: NtStatus = NtStatus(0xc0000284);
pub const NT_STATUS_ILLEGAL_ELEMENT_ADDRESS: NtStatus = NtStatus(0xc0000285);
pub const NT_STATUS_MAGAZINE_NOT_PRESENT: NtStatus = NtStatus(0xc0000286);
pub const NT_STATUS_REINITIALIZATION_NEEDED: NtStatus = NtStatus(0xc0000287);
pub const NT_STATUS_ENCRYPTION_FAILED: NtStatus = NtStatus(0xc000028a);
pub const NT_STATUS_DECRYPTION_FAILED: NtStatus = NtStatus(0xc000028b);
pub const NT_STATUS_RANGE_NOT_FOUND: NtStatus = NtStatus(0xc000028c);
pub const NT_STATUS_NO_RECOVERY_POLICY: NtStatus = NtStatus(0xc000028d);
pub const NT_STATUS_NO_EFS: NtStatus = NtStatus(0xc000028e);
pub const NT_STATUS_WRONG_EFS: NtStatus = NtStatus(0xc000028f);
pub const NT_STATUS_NO_USER_KEYS: NtStatus = NtStatus(0xc0000290);
pub const NT_STATUS_FILE_NOT_ENCRYPTED: NtStatus = NtStatus(0xc0000291);
pub const NT_STATUS_NOT_EXPORT_FORMAT: NtStatus = NtStatus(0xc0000292);
pub const NT_STATUS_FILE_ENCRYPTED: NtStatus = NtStatus(0xc0000293);
pub const NT_STATUS_WMI_GUID_NOT_FOUND: NtStatus = NtStatus(0xc0000295);
pub const NT_STATUS_WMI_INSTANCE_NOT_FOUND: NtStatus = NtStatus(0xc0000296);
pub const NT_STATUS_WMI_ITEMID_NOT_FOUND: NtStatus = NtStatus(0xc0000297);
pub const NT_STATUS_WMI_TRY_AGAIN: NtStatus = NtStatus(0xc0000298);
pub const NT_STATUS_SHARED_POLICY: NtStatus = NtStatus(0xc0000299);
pub const NT_STATUS_POLICY_OBJECT_NOT_FOUND: NtStatus = NtStatus(0xc000029a);
pub const NT_STATUS_POLICY_ONLY_IN_DS: NtStatus = NtStatus(0xc000029b);
pub const NT_STATUS_VOLUME_NOT_UPGRADED: NtStatus = NtStatus(0xc000029c);
pub const NT_STATUS_REMOTE_STORAGE_NOT_ACTIVE: NtStatus = NtStatus(0xc000029d);
pub const NT_STATUS_REMOTE_STORAGE_MEDIA_ERROR: NtStatus = NtStatus(0xc000029e);
pub const NT_STATUS_NO_TRACKING_SERVICE: NtStatus = NtStatus(0xc000029f);
pub const NT_STATUS_SERVER_SID_MISMATCH: NtStatus = NtStatus(0xc00002a0);
pub const NT_STATUS_DS_NO_ATTRIBUTE_OR_VALUE: NtStatus = NtStatus(0xc00002a1);
pub const NT_STATUS_DS_INVALID_ATTRIBUTE_SYNTAX: NtStatus =
    NtStatus(0xc00002a2);
pub const NT_STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED: NtStatus =
    NtStatus(0xc00002a3);
pub const NT_STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS: NtStatus =
    NtStatus(0xc00002a4);
pub const NT_STATUS_DS_BUSY: NtStatus = NtStatus(0xc00002a5);
pub const NT_STATUS_DS_UNAVAILABLE: NtStatus = NtStatus(0xc00002a6);
pub const NT_STATUS_DS_NO_RIDS_ALLOCATED: NtStatus = NtStatus(0xc00002a7);
pub const NT_STATUS_DS_NO_MORE_RIDS: NtStatus = NtStatus(0xc00002a8);
pub const NT_STATUS_DS_INCORRECT_ROLE_OWNER: NtStatus = NtStatus(0xc00002a9);
pub const NT_STATUS_DS_RIDMGR_INIT_ERROR: NtStatus = NtStatus(0xc00002aa);
pub const NT_STATUS_DS_OBJ_CLASS_VIOLATION: NtStatus = NtStatus(0xc00002ab);
pub const NT_STATUS_DS_CANT_ON_NON_LEAF: NtStatus = NtStatus(0xc00002ac);
pub const NT_STATUS_DS_CANT_ON_RDN: NtStatus = NtStatus(0xc00002ad);
pub const NT_STATUS_DS_CANT_MOD_OBJ_CLASS: NtStatus = NtStatus(0xc00002ae);
pub const NT_STATUS_DS_CROSS_DOM_MOVE_FAILED: NtStatus = NtStatus(0xc00002af);
pub const NT_STATUS_DS_GC_NOT_AVAILABLE: NtStatus = NtStatus(0xc00002b0);
pub const NT_STATUS_DIRECTORY_SERVICE_REQUIRED: NtStatus = NtStatus(0xc00002b1);
pub const NT_STATUS_REPARSE_ATTRIBUTE_CONFLICT: NtStatus = NtStatus(0xc00002b2);
pub const NT_STATUS_CANT_ENABLE_DENY_ONLY: NtStatus = NtStatus(0xc00002b3);
pub const NT_STATUS_FLOAT_MULTIPLE_FAULTS: NtStatus = NtStatus(0xc00002b4);
pub const NT_STATUS_FLOAT_MULTIPLE_TRAPS: NtStatus = NtStatus(0xc00002b5);
pub const NT_STATUS_DEVICE_REMOVED: NtStatus = NtStatus(0xc00002b6);
pub const NT_STATUS_JOURNAL_DELETE_IN_PROGRESS: NtStatus = NtStatus(0xc00002b7);
pub const NT_STATUS_JOURNAL_NOT_ACTIVE: NtStatus = NtStatus(0xc00002b8);
pub const NT_STATUS_NOINTERFACE: NtStatus = NtStatus(0xc00002b9);
pub const NT_STATUS_DS_ADMIN_LIMIT_EXCEEDED: NtStatus = NtStatus(0xc00002c1);
pub const NT_STATUS_DRIVER_FAILED_SLEEP: NtStatus = NtStatus(0xc00002c2);
pub const NT_STATUS_MUTUAL_AUTHENTICATION_FAILED: NtStatus =
    NtStatus(0xc00002c3);
pub const NT_STATUS_CORRUPT_SYSTEM_FILE: NtStatus = NtStatus(0xc00002c4);
pub const NT_STATUS_DATATYPE_MISALIGNMENT_ERROR: NtStatus =
    NtStatus(0xc00002c5);
pub const NT_STATUS_WMI_READ_ONLY: NtStatus = NtStatus(0xc00002c6);
pub const NT_STATUS_WMI_SET_FAILURE: NtStatus = NtStatus(0xc00002c7);
pub const NT_STATUS_COMMITMENT_MINIMUM: NtStatus = NtStatus(0xc00002c8);
pub const NT_STATUS_REG_NAT_CONSUMPTION: NtStatus = NtStatus(0xc00002c9);
pub const NT_STATUS_TRANSPORT_FULL: NtStatus = NtStatus(0xc00002ca);
pub const NT_STATUS_DS_SAM_INIT_FAILURE: NtStatus = NtStatus(0xc00002cb);
pub const NT_STATUS_ONLY_IF_CONNECTED: NtStatus = NtStatus(0xc00002cc);
pub const NT_STATUS_DS_SENSITIVE_GROUP_VIOLATION: NtStatus =
    NtStatus(0xc00002cd);
pub const NT_STATUS_PNP_RESTART_ENUMERATION: NtStatus = NtStatus(0xc00002ce);
pub const NT_STATUS_JOURNAL_ENTRY_DELETED: NtStatus = NtStatus(0xc00002cf);
pub const NT_STATUS_DS_CANT_MOD_PRIMARYGROUPID: NtStatus = NtStatus(0xc00002d0);
pub const NT_STATUS_SYSTEM_IMAGE_BAD_SIGNATURE: NtStatus = NtStatus(0xc00002d1);
pub const NT_STATUS_PNP_REBOOT_REQUIRED: NtStatus = NtStatus(0xc00002d2);
pub const NT_STATUS_POWER_STATE_INVALID: NtStatus = NtStatus(0xc00002d3);
pub const NT_STATUS_DS_INVALID_GROUP_TYPE: NtStatus = NtStatus(0xc00002d4);
pub const NT_STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN: NtStatus =
    NtStatus(0xc00002d5);
pub const NT_STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN: NtStatus =
    NtStatus(0xc00002d6);
pub const NT_STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER: NtStatus =
    NtStatus(0xc00002d7);
pub const NT_STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER: NtStatus =
    NtStatus(0xc00002d8);
pub const NT_STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER: NtStatus =
    NtStatus(0xc00002d9);
pub const NT_STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER: NtStatus =
    NtStatus(0xc00002da);
pub const NT_STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER: NtStatus =
    NtStatus(0xc00002db);
pub const NT_STATUS_DS_HAVE_PRIMARY_MEMBERS: NtStatus = NtStatus(0xc00002dc);
pub const NT_STATUS_WMI_NOT_SUPPORTED: NtStatus = NtStatus(0xc00002dd);
pub const NT_STATUS_INSUFFICIENT_POWER: NtStatus = NtStatus(0xc00002de);
pub const NT_STATUS_SAM_NEED_BOOTKEY_PASSWORD: NtStatus = NtStatus(0xc00002df);
pub const NT_STATUS_SAM_NEED_BOOTKEY_FLOPPY: NtStatus = NtStatus(0xc00002e0);
pub const NT_STATUS_DS_CANT_START: NtStatus = NtStatus(0xc00002e1);
pub const NT_STATUS_DS_INIT_FAILURE: NtStatus = NtStatus(0xc00002e2);
pub const NT_STATUS_SAM_INIT_FAILURE: NtStatus = NtStatus(0xc00002e3);
pub const NT_STATUS_DS_GC_REQUIRED: NtStatus = NtStatus(0xc00002e4);
pub const NT_STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY: NtStatus =
    NtStatus(0xc00002e5);
pub const NT_STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS: NtStatus =
    NtStatus(0xc00002e6);
pub const NT_STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED: NtStatus =
    NtStatus(0xc00002e7);
pub const NT_STATUS_CURRENT_DOMAIN_NOT_ALLOWED: NtStatus = NtStatus(0xc00002e9);
pub const NT_STATUS_CANNOT_MAKE: NtStatus = NtStatus(0xc00002ea);
pub const NT_STATUS_SYSTEM_SHUTDOWN: NtStatus = NtStatus(0xc00002eb);
pub const NT_STATUS_DS_INIT_FAILURE_CONSOLE: NtStatus = NtStatus(0xc00002ec);
pub const NT_STATUS_DS_SAM_INIT_FAILURE_CONSOLE: NtStatus =
    NtStatus(0xc00002ed);
pub const NT_STATUS_UNFINISHED_CONTEXT_DELETED: NtStatus = NtStatus(0xc00002ee);
pub const NT_STATUS_NO_TGT_REPLY: NtStatus = NtStatus(0xc00002ef);
pub const NT_STATUS_OBJECTID_NOT_FOUND: NtStatus = NtStatus(0xc00002f0);
pub const NT_STATUS_NO_IP_ADDRESSES: NtStatus = NtStatus(0xc00002f1);
pub const NT_STATUS_WRONG_CREDENTIAL_HANDLE: NtStatus = NtStatus(0xc00002f2);
pub const NT_STATUS_CRYPTO_SYSTEM_INVALID: NtStatus = NtStatus(0xc00002f3);
pub const NT_STATUS_MAX_REFERRALS_EXCEEDED: NtStatus = NtStatus(0xc00002f4);
pub const NT_STATUS_MUST_BE_KDC: NtStatus = NtStatus(0xc00002f5);
pub const NT_STATUS_STRONG_CRYPTO_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc00002f6);
pub const NT_STATUS_TOO_MANY_PRINCIPALS: NtStatus = NtStatus(0xc00002f7);
pub const NT_STATUS_NO_PA_DATA: NtStatus = NtStatus(0xc00002f8);
pub const NT_STATUS_PKINIT_NAME_MISMATCH: NtStatus = NtStatus(0xc00002f9);
pub const NT_STATUS_SMARTCARD_LOGON_REQUIRED: NtStatus = NtStatus(0xc00002fa);
pub const NT_STATUS_KDC_INVALID_REQUEST: NtStatus = NtStatus(0xc00002fb);
pub const NT_STATUS_KDC_UNABLE_TO_REFER: NtStatus = NtStatus(0xc00002fc);
pub const NT_STATUS_KDC_UNKNOWN_ETYPE: NtStatus = NtStatus(0xc00002fd);
pub const NT_STATUS_SHUTDOWN_IN_PROGRESS: NtStatus = NtStatus(0xc00002fe);
pub const NT_STATUS_SERVER_SHUTDOWN_IN_PROGRESS: NtStatus =
    NtStatus(0xc00002ff);
pub const NT_STATUS_NOT_SUPPORTED_ON_SBS: NtStatus = NtStatus(0xc0000300);
pub const NT_STATUS_WMI_GUID_DISCONNECTED: NtStatus = NtStatus(0xc0000301);
pub const NT_STATUS_WMI_ALREADY_DISABLED: NtStatus = NtStatus(0xc0000302);
pub const NT_STATUS_WMI_ALREADY_ENABLED: NtStatus = NtStatus(0xc0000303);
pub const NT_STATUS_MFT_TOO_FRAGMENTED: NtStatus = NtStatus(0xc0000304);
pub const NT_STATUS_COPY_PROTECTION_FAILURE: NtStatus = NtStatus(0xc0000305);
pub const NT_STATUS_CSS_AUTHENTICATION_FAILURE: NtStatus = NtStatus(0xc0000306);
pub const NT_STATUS_CSS_KEY_NOT_PRESENT: NtStatus = NtStatus(0xc0000307);
pub const NT_STATUS_CSS_KEY_NOT_ESTABLISHED: NtStatus = NtStatus(0xc0000308);
pub const NT_STATUS_CSS_SCRAMBLED_SECTOR: NtStatus = NtStatus(0xc0000309);
pub const NT_STATUS_CSS_REGION_MISMATCH: NtStatus = NtStatus(0xc000030a);
pub const NT_STATUS_CSS_RESETS_EXHAUSTED: NtStatus = NtStatus(0xc000030b);
pub const NT_STATUS_PKINIT_FAILURE: NtStatus = NtStatus(0xc0000320);
pub const NT_STATUS_SMARTCARD_SUBSYSTEM_FAILURE: NtStatus =
    NtStatus(0xc0000321);
pub const NT_STATUS_NO_KERB_KEY: NtStatus = NtStatus(0xc0000322);
pub const NT_STATUS_HOST_DOWN: NtStatus = NtStatus(0xc0000350);
pub const NT_STATUS_UNSUPPORTED_PREAUTH: NtStatus = NtStatus(0xc0000351);
pub const NT_STATUS_EFS_ALG_BLOB_TOO_BIG: NtStatus = NtStatus(0xc0000352);
pub const NT_STATUS_PORT_NOT_SET: NtStatus = NtStatus(0xc0000353);
pub const NT_STATUS_DEBUGGER_INACTIVE: NtStatus = NtStatus(0xc0000354);
pub const NT_STATUS_DS_VERSION_CHECK_FAILURE: NtStatus = NtStatus(0xc0000355);
pub const NT_STATUS_AUDITING_DISABLED: NtStatus = NtStatus(0xc0000356);
pub const NT_STATUS_PRENT4_MACHINE_ACCOUNT: NtStatus = NtStatus(0xc0000357);
pub const NT_STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER: NtStatus =
    NtStatus(0xc0000358);
pub const NT_STATUS_INVALID_IMAGE_WIN_32: NtStatus = NtStatus(0xc0000359);
pub const NT_STATUS_INVALID_IMAGE_WIN_64: NtStatus = NtStatus(0xc000035a);
pub const NT_STATUS_BAD_BINDINGS: NtStatus = NtStatus(0xc000035b);
pub const NT_STATUS_NETWORK_SESSION_EXPIRED: NtStatus = NtStatus(0xc000035c);
pub const NT_STATUS_APPHELP_BLOCK: NtStatus = NtStatus(0xc000035d);
pub const NT_STATUS_ALL_SIDS_FILTERED: NtStatus = NtStatus(0xc000035e);
pub const NT_STATUS_NOT_SAFE_MODE_DRIVER: NtStatus = NtStatus(0xc000035f);
pub const NT_STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT: NtStatus =
    NtStatus(0xc0000361);
pub const NT_STATUS_ACCESS_DISABLED_BY_POLICY_PATH: NtStatus =
    NtStatus(0xc0000362);
pub const NT_STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER: NtStatus =
    NtStatus(0xc0000363);
pub const NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER: NtStatus =
    NtStatus(0xc0000364);
pub const NT_STATUS_FAILED_DRIVER_ENTRY: NtStatus = NtStatus(0xc0000365);
pub const NT_STATUS_DEVICE_ENUMERATION_ERROR: NtStatus = NtStatus(0xc0000366);
pub const NT_STATUS_MOUNT_POINT_NOT_RESOLVED: NtStatus = NtStatus(0xc0000368);
pub const NT_STATUS_INVALID_DEVICE_OBJECT_PARAMETER: NtStatus =
    NtStatus(0xc0000369);
pub const NT_STATUS_MCA_OCCURED: NtStatus = NtStatus(0xc000036a);
pub const NT_STATUS_DRIVER_BLOCKED_CRITICAL: NtStatus = NtStatus(0xc000036b);
pub const NT_STATUS_DRIVER_BLOCKED: NtStatus = NtStatus(0xc000036c);
pub const NT_STATUS_DRIVER_DATABASE_ERROR: NtStatus = NtStatus(0xc000036d);
pub const NT_STATUS_SYSTEM_HIVE_TOO_LARGE: NtStatus = NtStatus(0xc000036e);
pub const NT_STATUS_INVALID_IMPORT_OF_NON_DLL: NtStatus = NtStatus(0xc000036f);
pub const NT_STATUS_NO_SECRETS: NtStatus = NtStatus(0xc0000371);
pub const NT_STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY: NtStatus =
    NtStatus(0xc0000372);
pub const NT_STATUS_FAILED_STACK_SWITCH: NtStatus = NtStatus(0xc0000373);
pub const NT_STATUS_HEAP_CORRUPTION: NtStatus = NtStatus(0xc0000374);
pub const NT_STATUS_SMARTCARD_WRONG_PIN: NtStatus = NtStatus(0xc0000380);
pub const NT_STATUS_SMARTCARD_CARD_BLOCKED: NtStatus = NtStatus(0xc0000381);
pub const NT_STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED: NtStatus =
    NtStatus(0xc0000382);
pub const NT_STATUS_SMARTCARD_NO_CARD: NtStatus = NtStatus(0xc0000383);
pub const NT_STATUS_SMARTCARD_NO_KEY_CONTAINER: NtStatus = NtStatus(0xc0000384);
pub const NT_STATUS_SMARTCARD_NO_CERTIFICATE: NtStatus = NtStatus(0xc0000385);
pub const NT_STATUS_SMARTCARD_NO_KEYSET: NtStatus = NtStatus(0xc0000386);
pub const NT_STATUS_SMARTCARD_IO_ERROR: NtStatus = NtStatus(0xc0000387);
pub const NT_STATUS_DOWNGRADE_DETECTED: NtStatus = NtStatus(0xc0000388);
pub const NT_STATUS_SMARTCARD_CERT_REVOKED: NtStatus = NtStatus(0xc0000389);
pub const NT_STATUS_ISSUING_CA_UNTRUSTED: NtStatus = NtStatus(0xc000038a);
pub const NT_STATUS_REVOCATION_OFFLINE_C: NtStatus = NtStatus(0xc000038b);
pub const NT_STATUS_PKINIT_CLIENT_FAILURE: NtStatus = NtStatus(0xc000038c);
pub const NT_STATUS_SMARTCARD_CERT_EXPIRED: NtStatus = NtStatus(0xc000038d);
pub const NT_STATUS_DRIVER_FAILED_PRIOR_UNLOAD: NtStatus = NtStatus(0xc000038e);
pub const NT_STATUS_SMARTCARD_SILENT_CONTEXT: NtStatus = NtStatus(0xc000038f);
pub const NT_STATUS_PER_USER_TRUST_QUOTA_EXCEEDED: NtStatus =
    NtStatus(0xc0000401);
pub const NT_STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED: NtStatus =
    NtStatus(0xc0000402);
pub const NT_STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED: NtStatus =
    NtStatus(0xc0000403);
pub const NT_STATUS_DS_NAME_NOT_UNIQUE: NtStatus = NtStatus(0xc0000404);
pub const NT_STATUS_DS_DUPLICATE_ID_FOUND: NtStatus = NtStatus(0xc0000405);
pub const NT_STATUS_DS_GROUP_CONVERSION_ERROR: NtStatus = NtStatus(0xc0000406);
pub const NT_STATUS_VOLSNAP_PREPARE_HIBERNATE: NtStatus = NtStatus(0xc0000407);
pub const NT_STATUS_USER2USER_REQUIRED: NtStatus = NtStatus(0xc0000408);
pub const NT_STATUS_STACK_BUFFER_OVERRUN: NtStatus = NtStatus(0xc0000409);
pub const NT_STATUS_NO_S4U_PROT_SUPPORT: NtStatus = NtStatus(0xc000040a);
pub const NT_STATUS_CROSSREALM_DELEGATION_FAILURE: NtStatus =
    NtStatus(0xc000040b);
pub const NT_STATUS_REVOCATION_OFFLINE_KDC: NtStatus = NtStatus(0xc000040c);
pub const NT_STATUS_ISSUING_CA_UNTRUSTED_KDC: NtStatus = NtStatus(0xc000040d);
pub const NT_STATUS_KDC_CERT_EXPIRED: NtStatus = NtStatus(0xc000040e);
pub const NT_STATUS_KDC_CERT_REVOKED: NtStatus = NtStatus(0xc000040f);
pub const NT_STATUS_PARAMETER_QUOTA_EXCEEDED: NtStatus = NtStatus(0xc0000410);
pub const NT_STATUS_HIBERNATION_FAILURE: NtStatus = NtStatus(0xc0000411);
pub const NT_STATUS_DELAY_LOAD_FAILED: NtStatus = NtStatus(0xc0000412);
pub const NT_STATUS_AUTHENTICATION_FIREWALL_FAILED: NtStatus =
    NtStatus(0xc0000413);
pub const NT_STATUS_VDM_DISALLOWED: NtStatus = NtStatus(0xc0000414);
pub const NT_STATUS_HUNG_DISPLAY_DRIVER_THREAD: NtStatus = NtStatus(0xc0000415);
pub const NT_STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE:
    NtStatus = NtStatus(0xc0000416);
pub const NT_STATUS_INVALID_CRUNTIME_PARAMETER: NtStatus = NtStatus(0xc0000417);
pub const NT_STATUS_NTLM_BLOCKED: NtStatus = NtStatus(0xc0000418);
pub const NT_STATUS_DS_SRC_SID_EXISTS_IN_FOREST: NtStatus =
    NtStatus(0xc0000419);
pub const NT_STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST: NtStatus =
    NtStatus(0xc000041a);
pub const NT_STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST: NtStatus =
    NtStatus(0xc000041b);
pub const NT_STATUS_INVALID_USER_PRINCIPAL_NAME: NtStatus =
    NtStatus(0xc000041c);
pub const NT_STATUS_ASSERTION_FAILURE: NtStatus = NtStatus(0xc0000420);
pub const NT_STATUS_VERIFIER_STOP: NtStatus = NtStatus(0xc0000421);
pub const NT_STATUS_CALLBACK_POP_STACK: NtStatus = NtStatus(0xc0000423);
pub const NT_STATUS_INCOMPATIBLE_DRIVER_BLOCKED: NtStatus =
    NtStatus(0xc0000424);
pub const NT_STATUS_HIVE_UNLOADED: NtStatus = NtStatus(0xc0000425);
pub const NT_STATUS_COMPRESSION_DISABLED: NtStatus = NtStatus(0xc0000426);
pub const NT_STATUS_FILE_SYSTEM_LIMITATION: NtStatus = NtStatus(0xc0000427);
pub const NT_STATUS_INVALID_IMAGE_HASH: NtStatus = NtStatus(0xc0000428);
pub const NT_STATUS_NOT_CAPABLE: NtStatus = NtStatus(0xc0000429);
pub const NT_STATUS_REQUEST_OUT_OF_SEQUENCE: NtStatus = NtStatus(0xc000042a);
pub const NT_STATUS_IMPLEMENTATION_LIMIT: NtStatus = NtStatus(0xc000042b);
pub const NT_STATUS_ELEVATION_REQUIRED: NtStatus = NtStatus(0xc000042c);
pub const NT_STATUS_NO_SECURITY_CONTEXT: NtStatus = NtStatus(0xc000042d);
pub const NT_STATUS_PKU2U_CERT_FAILURE: NtStatus = NtStatus(0xc000042e);
pub const NT_STATUS_BEYOND_VDL: NtStatus = NtStatus(0xc0000432);
pub const NT_STATUS_ENCOUNTERED_WRITE_IN_PROGRESS: NtStatus =
    NtStatus(0xc0000433);
pub const NT_STATUS_PTE_CHANGED: NtStatus = NtStatus(0xc0000434);
pub const NT_STATUS_PURGE_FAILED: NtStatus = NtStatus(0xc0000435);
pub const NT_STATUS_CRED_REQUIRES_CONFIRMATION: NtStatus = NtStatus(0xc0000440);
pub const NT_STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE: NtStatus =
    NtStatus(0xc0000441);
pub const NT_STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER: NtStatus =
    NtStatus(0xc0000442);
pub const NT_STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE: NtStatus =
    NtStatus(0xc0000443);
pub const NT_STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE: NtStatus =
    NtStatus(0xc0000444);
pub const NT_STATUS_CS_ENCRYPTION_FILE_NOT_CSE: NtStatus = NtStatus(0xc0000445);
pub const NT_STATUS_INVALID_LABEL: NtStatus = NtStatus(0xc0000446);
pub const NT_STATUS_DRIVER_PROCESS_TERMINATED: NtStatus = NtStatus(0xc0000450);
pub const NT_STATUS_AMBIGUOUS_SYSTEM_DEVICE: NtStatus = NtStatus(0xc0000451);
pub const NT_STATUS_SYSTEM_DEVICE_NOT_FOUND: NtStatus = NtStatus(0xc0000452);
pub const NT_STATUS_RESTART_BOOT_APPLICATION: NtStatus = NtStatus(0xc0000453);
pub const NT_STATUS_INSUFFICIENT_NVRAM_RESOURCES: NtStatus =
    NtStatus(0xc0000454);
pub const NT_STATUS_NO_RANGES_PROCESSED: NtStatus = NtStatus(0xc0000460);
pub const NT_STATUS_DEVICE_FEATURE_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc0000463);
pub const NT_STATUS_DEVICE_UNREACHABLE: NtStatus = NtStatus(0xc0000464);
pub const NT_STATUS_INVALID_TOKEN: NtStatus = NtStatus(0xc0000465);
pub const NT_STATUS_SERVER_UNAVAILABLE: NtStatus = NtStatus(0xc0000466);
pub const NT_STATUS_INVALID_TASK_NAME: NtStatus = NtStatus(0xc0000500);
pub const NT_STATUS_INVALID_TASK_INDEX: NtStatus = NtStatus(0xc0000501);
pub const NT_STATUS_THREAD_ALREADY_IN_TASK: NtStatus = NtStatus(0xc0000502);
pub const NT_STATUS_CALLBACK_BYPASS: NtStatus = NtStatus(0xc0000503);
pub const NT_STATUS_FAIL_FAST_EXCEPTION: NtStatus = NtStatus(0xc0000602);
pub const NT_STATUS_IMAGE_CERT_REVOKED: NtStatus = NtStatus(0xc0000603);
pub const NT_STATUS_PORT_CLOSED: NtStatus = NtStatus(0xc0000700);
pub const NT_STATUS_MESSAGE_LOST: NtStatus = NtStatus(0xc0000701);
pub const NT_STATUS_INVALID_MESSAGE: NtStatus = NtStatus(0xc0000702);
pub const NT_STATUS_REQUEST_CANCELED: NtStatus = NtStatus(0xc0000703);
pub const NT_STATUS_RECURSIVE_DISPATCH: NtStatus = NtStatus(0xc0000704);
pub const NT_STATUS_LPC_RECEIVE_BUFFER_EXPECTED: NtStatus =
    NtStatus(0xc0000705);
pub const NT_STATUS_LPC_INVALID_CONNECTION_USAGE: NtStatus =
    NtStatus(0xc0000706);
pub const NT_STATUS_LPC_REQUESTS_NOT_ALLOWED: NtStatus = NtStatus(0xc0000707);
pub const NT_STATUS_RESOURCE_IN_USE: NtStatus = NtStatus(0xc0000708);
pub const NT_STATUS_HARDWARE_MEMORY_ERROR: NtStatus = NtStatus(0xc0000709);
pub const NT_STATUS_THREADPOOL_HANDLE_EXCEPTION: NtStatus =
    NtStatus(0xc000070a);
pub const NT_STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED: NtStatus =
    NtStatus(0xc000070b);
pub const NT_STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED:
    NtStatus = NtStatus(0xc000070c);
pub const NT_STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED: NtStatus =
    NtStatus(0xc000070d);
pub const NT_STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED: NtStatus =
    NtStatus(0xc000070e);
pub const NT_STATUS_THREADPOOL_RELEASED_DURING_OPERATION: NtStatus =
    NtStatus(0xc000070f);
pub const NT_STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING: NtStatus =
    NtStatus(0xc0000710);
pub const NT_STATUS_APC_RETURNED_WHILE_IMPERSONATING: NtStatus =
    NtStatus(0xc0000711);
pub const NT_STATUS_PROCESS_IS_PROTECTED: NtStatus = NtStatus(0xc0000712);
pub const NT_STATUS_MCA_EXCEPTION: NtStatus = NtStatus(0xc0000713);
pub const NT_STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE: NtStatus =
    NtStatus(0xc0000714);
pub const NT_STATUS_SYMLINK_CLASS_DISABLED: NtStatus = NtStatus(0xc0000715);
pub const NT_STATUS_INVALID_IDN_NORMALIZATION: NtStatus = NtStatus(0xc0000716);
pub const NT_STATUS_NO_UNICODE_TRANSLATION: NtStatus = NtStatus(0xc0000717);
pub const NT_STATUS_ALREADY_REGISTERED: NtStatus = NtStatus(0xc0000718);
pub const NT_STATUS_CONTEXT_MISMATCH: NtStatus = NtStatus(0xc0000719);
pub const NT_STATUS_PORT_ALREADY_HAS_COMPLETION_LIST: NtStatus =
    NtStatus(0xc000071a);
pub const NT_STATUS_CALLBACK_RETURNED_THREAD_PRIORITY: NtStatus =
    NtStatus(0xc000071b);
pub const NT_STATUS_INVALID_THREAD: NtStatus = NtStatus(0xc000071c);
pub const NT_STATUS_CALLBACK_RETURNED_TRANSACTION: NtStatus =
    NtStatus(0xc000071d);
pub const NT_STATUS_CALLBACK_RETURNED_LDR_LOCK: NtStatus = NtStatus(0xc000071e);
pub const NT_STATUS_CALLBACK_RETURNED_LANG: NtStatus = NtStatus(0xc000071f);
pub const NT_STATUS_CALLBACK_RETURNED_PRI_BACK: NtStatus = NtStatus(0xc0000720);
pub const NT_STATUS_DISK_REPAIR_DISABLED: NtStatus = NtStatus(0xc0000800);
pub const NT_STATUS_DS_DOMAIN_RENAME_IN_PROGRESS: NtStatus =
    NtStatus(0xc0000801);
pub const NT_STATUS_DISK_QUOTA_EXCEEDED: NtStatus = NtStatus(0xc0000802);
pub const NT_STATUS_CONTENT_BLOCKED: NtStatus = NtStatus(0xc0000804);
pub const NT_STATUS_BAD_CLUSTERS: NtStatus = NtStatus(0xc0000805);
pub const NT_STATUS_VOLUME_DIRTY: NtStatus = NtStatus(0xc0000806);
pub const NT_STATUS_FILE_CHECKED_OUT: NtStatus = NtStatus(0xc0000901);
pub const NT_STATUS_CHECKOUT_REQUIRED: NtStatus = NtStatus(0xc0000902);
pub const NT_STATUS_BAD_FILE_TYPE: NtStatus = NtStatus(0xc0000903);
pub const NT_STATUS_FILE_TOO_LARGE: NtStatus = NtStatus(0xc0000904);
pub const NT_STATUS_FORMS_AUTH_REQUIRED: NtStatus = NtStatus(0xc0000905);
pub const NT_STATUS_VIRUS_INFECTED: NtStatus = NtStatus(0xc0000906);
pub const NT_STATUS_VIRUS_DELETED: NtStatus = NtStatus(0xc0000907);
pub const NT_STATUS_BAD_MCFG_TABLE: NtStatus = NtStatus(0xc0000908);
pub const NT_STATUS_CANNOT_BREAK_OPLOCK: NtStatus = NtStatus(0xc0000909);
pub const NT_STATUS_WOW_ASSERTION: NtStatus = NtStatus(0xc0009898);
pub const NT_STATUS_INVALID_SIGNATURE: NtStatus = NtStatus(0xc000a000);
pub const NT_STATUS_HMAC_NOT_SUPPORTED: NtStatus = NtStatus(0xc000a001);
pub const NT_STATUS_IPSEC_QUEUE_OVERFLOW: NtStatus = NtStatus(0xc000a010);
pub const NT_STATUS_ND_QUEUE_OVERFLOW: NtStatus = NtStatus(0xc000a011);
pub const NT_STATUS_HOPLIMIT_EXCEEDED: NtStatus = NtStatus(0xc000a012);
pub const NT_STATUS_PROTOCOL_NOT_SUPPORTED: NtStatus = NtStatus(0xc000a013);
pub const NT_STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED: NtStatus =
    NtStatus(0xc000a080);
pub const NT_STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR: NtStatus =
    NtStatus(0xc000a081);
pub const NT_STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR: NtStatus =
    NtStatus(0xc000a082);
pub const NT_STATUS_XML_PARSE_ERROR: NtStatus = NtStatus(0xc000a083);
pub const NT_STATUS_XMLDSIG_ERROR: NtStatus = NtStatus(0xc000a084);
pub const NT_STATUS_WRONG_COMPARTMENT: NtStatus = NtStatus(0xc000a085);
pub const NT_STATUS_AUTHIP_FAILURE: NtStatus = NtStatus(0xc000a086);
pub const NT_STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS: NtStatus =
    NtStatus(0xc000a087);
pub const NT_STATUS_DS_OID_NOT_FOUND: NtStatus = NtStatus(0xc000a088);
pub const NT_STATUS_HASH_NOT_SUPPORTED: NtStatus = NtStatus(0xc000a100);
pub const NT_STATUS_HASH_NOT_PRESENT: NtStatus = NtStatus(0xc000a101);
pub const NT_STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc000a2a1);
pub const NT_STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc000a2a2);
pub const NT_STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc000a2a3);
pub const NT_STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc000a2a4);
pub const NT_STATUS_DBG_NO_STATE_CHANGE: NtStatus = NtStatus(0xc0010001);
pub const NT_STATUS_DBG_APP_NOT_IDLE: NtStatus = NtStatus(0xc0010002);
pub const NT_STATUS_RPC_INVALID_STRING_BINDING: NtStatus = NtStatus(0xc0020001);
pub const NT_STATUS_RPC_WRONG_KIND_OF_BINDING: NtStatus = NtStatus(0xc0020002);
pub const NT_STATUS_RPC_INVALID_BINDING: NtStatus = NtStatus(0xc0020003);
pub const NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED: NtStatus = NtStatus(0xc0020004);
pub const NT_STATUS_RPC_INVALID_RPC_PROTSEQ: NtStatus = NtStatus(0xc0020005);
pub const NT_STATUS_RPC_INVALID_STRING_UUID: NtStatus = NtStatus(0xc0020006);
pub const NT_STATUS_RPC_INVALID_ENDPOINT_FORMAT: NtStatus =
    NtStatus(0xc0020007);
pub const NT_STATUS_RPC_INVALID_NET_ADDR: NtStatus = NtStatus(0xc0020008);
pub const NT_STATUS_RPC_NO_ENDPOINT_FOUND: NtStatus = NtStatus(0xc0020009);
pub const NT_STATUS_RPC_INVALID_TIMEOUT: NtStatus = NtStatus(0xc002000a);
pub const NT_STATUS_RPC_OBJECT_NOT_FOUND: NtStatus = NtStatus(0xc002000b);
pub const NT_STATUS_RPC_ALREADY_REGISTERED: NtStatus = NtStatus(0xc002000c);
pub const NT_STATUS_RPC_TYPE_ALREADY_REGISTERED: NtStatus =
    NtStatus(0xc002000d);
pub const NT_STATUS_RPC_ALREADY_LISTENING: NtStatus = NtStatus(0xc002000e);
pub const NT_STATUS_RPC_NO_PROTSEQS_REGISTERED: NtStatus = NtStatus(0xc002000f);
pub const NT_STATUS_RPC_NOT_LISTENING: NtStatus = NtStatus(0xc0020010);
pub const NT_STATUS_RPC_UNKNOWN_MGR_TYPE: NtStatus = NtStatus(0xc0020011);
pub const NT_STATUS_RPC_UNKNOWN_IF: NtStatus = NtStatus(0xc0020012);
pub const NT_STATUS_RPC_NO_BINDINGS: NtStatus = NtStatus(0xc0020013);
pub const NT_STATUS_RPC_NO_PROTSEQS: NtStatus = NtStatus(0xc0020014);
pub const NT_STATUS_RPC_CANT_CREATE_ENDPOINT: NtStatus = NtStatus(0xc0020015);
pub const NT_STATUS_RPC_OUT_OF_RESOURCES: NtStatus = NtStatus(0xc0020016);
pub const NT_STATUS_RPC_SERVER_UNAVAILABLE: NtStatus = NtStatus(0xc0020017);
pub const NT_STATUS_RPC_SERVER_TOO_BUSY: NtStatus = NtStatus(0xc0020018);
pub const NT_STATUS_RPC_INVALID_NETWORK_OPTIONS: NtStatus =
    NtStatus(0xc0020019);
pub const NT_STATUS_RPC_NO_CALL_ACTIVE: NtStatus = NtStatus(0xc002001a);
pub const NT_STATUS_RPC_CALL_FAILED: NtStatus = NtStatus(0xc002001b);
pub const NT_STATUS_RPC_CALL_FAILED_DNE: NtStatus = NtStatus(0xc002001c);
pub const NT_STATUS_RPC_PROTOCOL_ERROR: NtStatus = NtStatus(0xc002001d);
pub const NT_STATUS_RPC_UNSUPPORTED_TRANS_SYN: NtStatus = NtStatus(0xc002001f);
pub const NT_STATUS_RPC_UNSUPPORTED_TYPE: NtStatus = NtStatus(0xc0020021);
pub const NT_STATUS_RPC_INVALID_TAG: NtStatus = NtStatus(0xc0020022);
pub const NT_STATUS_RPC_INVALID_BOUND: NtStatus = NtStatus(0xc0020023);
pub const NT_STATUS_RPC_NO_ENTRY_NAME: NtStatus = NtStatus(0xc0020024);
pub const NT_STATUS_RPC_INVALID_NAME_SYNTAX: NtStatus = NtStatus(0xc0020025);
pub const NT_STATUS_RPC_UNSUPPORTED_NAME_SYNTAX: NtStatus =
    NtStatus(0xc0020026);
pub const NT_STATUS_RPC_UUID_NO_ADDRESS: NtStatus = NtStatus(0xc0020028);
pub const NT_STATUS_RPC_DUPLICATE_ENDPOINT: NtStatus = NtStatus(0xc0020029);
pub const NT_STATUS_RPC_UNKNOWN_AUTHN_TYPE: NtStatus = NtStatus(0xc002002a);
pub const NT_STATUS_RPC_MAX_CALLS_TOO_SMALL: NtStatus = NtStatus(0xc002002b);
pub const NT_STATUS_RPC_STRING_TOO_LONG: NtStatus = NtStatus(0xc002002c);
pub const NT_STATUS_RPC_PROTSEQ_NOT_FOUND: NtStatus = NtStatus(0xc002002d);
pub const NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE: NtStatus = NtStatus(0xc002002e);
pub const NT_STATUS_RPC_BINDING_HAS_NO_AUTH: NtStatus = NtStatus(0xc002002f);
pub const NT_STATUS_RPC_UNKNOWN_AUTHN_SERVICE: NtStatus = NtStatus(0xc0020030);
pub const NT_STATUS_RPC_UNKNOWN_AUTHN_LEVEL: NtStatus = NtStatus(0xc0020031);
pub const NT_STATUS_RPC_INVALID_AUTH_IDENTITY: NtStatus = NtStatus(0xc0020032);
pub const NT_STATUS_RPC_UNKNOWN_AUTHZ_SERVICE: NtStatus = NtStatus(0xc0020033);
pub const NT_STATUS_EPT_INVALID_ENTRY: NtStatus = NtStatus(0xc0020034);
pub const NT_STATUS_EPT_CANT_PERFORM_OP: NtStatus = NtStatus(0xc0020035);
pub const NT_STATUS_EPT_NOT_REGISTERED: NtStatus = NtStatus(0xc0020036);
pub const NT_STATUS_RPC_NOTHING_TO_EXPORT: NtStatus = NtStatus(0xc0020037);
pub const NT_STATUS_RPC_INCOMPLETE_NAME: NtStatus = NtStatus(0xc0020038);
pub const NT_STATUS_RPC_INVALID_VERS_OPTION: NtStatus = NtStatus(0xc0020039);
pub const NT_STATUS_RPC_NO_MORE_MEMBERS: NtStatus = NtStatus(0xc002003a);
pub const NT_STATUS_RPC_NOT_ALL_OBJS_UNEXPORTED: NtStatus =
    NtStatus(0xc002003b);
pub const NT_STATUS_RPC_INTERFACE_NOT_FOUND: NtStatus = NtStatus(0xc002003c);
pub const NT_STATUS_RPC_ENTRY_ALREADY_EXISTS: NtStatus = NtStatus(0xc002003d);
pub const NT_STATUS_RPC_ENTRY_NOT_FOUND: NtStatus = NtStatus(0xc002003e);
pub const NT_STATUS_RPC_NAME_SERVICE_UNAVAILABLE: NtStatus =
    NtStatus(0xc002003f);
pub const NT_STATUS_RPC_INVALID_NAF_ID: NtStatus = NtStatus(0xc0020040);
pub const NT_STATUS_RPC_CANNOT_SUPPORT: NtStatus = NtStatus(0xc0020041);
pub const NT_STATUS_RPC_NO_CONTEXT_AVAILABLE: NtStatus = NtStatus(0xc0020042);
pub const NT_STATUS_RPC_INTERNAL_ERROR: NtStatus = NtStatus(0xc0020043);
pub const NT_STATUS_RPC_ZERO_DIVIDE: NtStatus = NtStatus(0xc0020044);
pub const NT_STATUS_RPC_ADDRESS_ERROR: NtStatus = NtStatus(0xc0020045);
pub const NT_STATUS_RPC_FP_DIV_ZERO: NtStatus = NtStatus(0xc0020046);
pub const NT_STATUS_RPC_FP_UNDERFLOW: NtStatus = NtStatus(0xc0020047);
pub const NT_STATUS_RPC_FP_OVERFLOW: NtStatus = NtStatus(0xc0020048);
pub const NT_STATUS_RPC_CALL_IN_PROGRESS: NtStatus = NtStatus(0xc0020049);
pub const NT_STATUS_RPC_NO_MORE_BINDINGS: NtStatus = NtStatus(0xc002004a);
pub const NT_STATUS_RPC_GROUP_MEMBER_NOT_FOUND: NtStatus = NtStatus(0xc002004b);
pub const NT_STATUS_EPT_CANT_CREATE: NtStatus = NtStatus(0xc002004c);
pub const NT_STATUS_RPC_INVALID_OBJECT: NtStatus = NtStatus(0xc002004d);
pub const NT_STATUS_RPC_NO_INTERFACES: NtStatus = NtStatus(0xc002004f);
pub const NT_STATUS_RPC_CALL_CANCELLED: NtStatus = NtStatus(0xc0020050);
pub const NT_STATUS_RPC_BINDING_INCOMPLETE: NtStatus = NtStatus(0xc0020051);
pub const NT_STATUS_RPC_COMM_FAILURE: NtStatus = NtStatus(0xc0020052);
pub const NT_STATUS_RPC_UNSUPPORTED_AUTHN_LEVEL: NtStatus =
    NtStatus(0xc0020053);
pub const NT_STATUS_RPC_NO_PRINC_NAME: NtStatus = NtStatus(0xc0020054);
pub const NT_STATUS_RPC_NOT_RPC_ERROR: NtStatus = NtStatus(0xc0020055);
pub const NT_STATUS_RPC_SEC_PKG_ERROR: NtStatus = NtStatus(0xc0020057);
pub const NT_STATUS_RPC_NOT_CANCELLED: NtStatus = NtStatus(0xc0020058);
pub const NT_STATUS_RPC_INVALID_ASYNC_HANDLE: NtStatus = NtStatus(0xc0020062);
pub const NT_STATUS_RPC_INVALID_ASYNC_CALL: NtStatus = NtStatus(0xc0020063);
pub const NT_STATUS_RPC_PROXY_ACCESS_DENIED: NtStatus = NtStatus(0xc0020064);
pub const NT_STATUS_RPC_NO_MORE_ENTRIES: NtStatus = NtStatus(0xc0030001);
pub const NT_STATUS_RPC_SS_CHAR_TRANS_OPEN_FAIL: NtStatus =
    NtStatus(0xc0030002);
pub const NT_STATUS_RPC_SS_CHAR_TRANS_SHORT_FILE: NtStatus =
    NtStatus(0xc0030003);
pub const NT_STATUS_RPC_SS_IN_NULL_CONTEXT: NtStatus = NtStatus(0xc0030004);
pub const NT_STATUS_RPC_SS_CONTEXT_MISMATCH: NtStatus = NtStatus(0xc0030005);
pub const NT_STATUS_RPC_SS_CONTEXT_DAMAGED: NtStatus = NtStatus(0xc0030006);
pub const NT_STATUS_RPC_SS_HANDLES_MISMATCH: NtStatus = NtStatus(0xc0030007);
pub const NT_STATUS_RPC_SS_CANNOT_GET_CALL_HANDLE: NtStatus =
    NtStatus(0xc0030008);
pub const NT_STATUS_RPC_NULL_REF_POINTER: NtStatus = NtStatus(0xc0030009);
pub const NT_STATUS_RPC_ENUM_VALUE_OUT_OF_RANGE: NtStatus =
    NtStatus(0xc003000a);
pub const NT_STATUS_RPC_BYTE_COUNT_TOO_SMALL: NtStatus = NtStatus(0xc003000b);
pub const NT_STATUS_RPC_BAD_STUB_DATA: NtStatus = NtStatus(0xc003000c);
pub const NT_STATUS_RPC_INVALID_ES_ACTION: NtStatus = NtStatus(0xc0030059);
pub const NT_STATUS_RPC_WRONG_ES_VERSION: NtStatus = NtStatus(0xc003005a);
pub const NT_STATUS_RPC_WRONG_STUB_VERSION: NtStatus = NtStatus(0xc003005b);
pub const NT_STATUS_RPC_INVALID_PIPE_OBJECT: NtStatus = NtStatus(0xc003005c);
pub const NT_STATUS_RPC_INVALID_PIPE_OPERATION: NtStatus = NtStatus(0xc003005d);
pub const NT_STATUS_RPC_WRONG_PIPE_VERSION: NtStatus = NtStatus(0xc003005e);
pub const NT_STATUS_RPC_PIPE_CLOSED: NtStatus = NtStatus(0xc003005f);
pub const NT_STATUS_RPC_PIPE_DISCIPLINE_ERROR: NtStatus = NtStatus(0xc0030060);
pub const NT_STATUS_RPC_PIPE_EMPTY: NtStatus = NtStatus(0xc0030061);
pub const NT_STATUS_PNP_BAD_MPS_TABLE: NtStatus = NtStatus(0xc0040035);
pub const NT_STATUS_PNP_TRANSLATION_FAILED: NtStatus = NtStatus(0xc0040036);
pub const NT_STATUS_PNP_IRQ_TRANSLATION_FAILED: NtStatus = NtStatus(0xc0040037);
pub const NT_STATUS_PNP_INVALID_ID: NtStatus = NtStatus(0xc0040038);
pub const NT_STATUS_IO_REISSUE_AS_CACHED: NtStatus = NtStatus(0xc0040039);
pub const NT_STATUS_CTX_WINSTATION_NAME_INVALID: NtStatus =
    NtStatus(0xc00a0001);
pub const NT_STATUS_CTX_INVALID_PD: NtStatus = NtStatus(0xc00a0002);
pub const NT_STATUS_CTX_PD_NOT_FOUND: NtStatus = NtStatus(0xc00a0003);
pub const NT_STATUS_CTX_CLOSE_PENDING: NtStatus = NtStatus(0xc00a0006);
pub const NT_STATUS_CTX_NO_OUTBUF: NtStatus = NtStatus(0xc00a0007);
pub const NT_STATUS_CTX_MODEM_INF_NOT_FOUND: NtStatus = NtStatus(0xc00a0008);
pub const NT_STATUS_CTX_INVALID_MODEMNAME: NtStatus = NtStatus(0xc00a0009);
pub const NT_STATUS_CTX_RESPONSE_ERROR: NtStatus = NtStatus(0xc00a000a);
pub const NT_STATUS_CTX_MODEM_RESPONSE_TIMEOUT: NtStatus = NtStatus(0xc00a000b);
pub const NT_STATUS_CTX_MODEM_RESPONSE_NO_CARRIER: NtStatus =
    NtStatus(0xc00a000c);
pub const NT_STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE: NtStatus =
    NtStatus(0xc00a000d);
pub const NT_STATUS_CTX_MODEM_RESPONSE_BUSY: NtStatus = NtStatus(0xc00a000e);
pub const NT_STATUS_CTX_MODEM_RESPONSE_VOICE: NtStatus = NtStatus(0xc00a000f);
pub const NT_STATUS_CTX_TD_ERROR: NtStatus = NtStatus(0xc00a0010);
pub const NT_STATUS_CTX_LICENSE_CLIENT_INVALID: NtStatus = NtStatus(0xc00a0012);
pub const NT_STATUS_CTX_LICENSE_NOT_AVAILABLE: NtStatus = NtStatus(0xc00a0013);
pub const NT_STATUS_CTX_LICENSE_EXPIRED: NtStatus = NtStatus(0xc00a0014);
pub const NT_STATUS_CTX_WINSTATION_NOT_FOUND: NtStatus = NtStatus(0xc00a0015);
pub const NT_STATUS_CTX_WINSTATION_NAME_COLLISION: NtStatus =
    NtStatus(0xc00a0016);
pub const NT_STATUS_CTX_WINSTATION_BUSY: NtStatus = NtStatus(0xc00a0017);
pub const NT_STATUS_CTX_BAD_VIDEO_MODE: NtStatus = NtStatus(0xc00a0018);
pub const NT_STATUS_CTX_GRAPHICS_INVALID: NtStatus = NtStatus(0xc00a0022);
pub const NT_STATUS_CTX_NOT_CONSOLE: NtStatus = NtStatus(0xc00a0024);
pub const NT_STATUS_CTX_CLIENT_QUERY_TIMEOUT: NtStatus = NtStatus(0xc00a0026);
pub const NT_STATUS_CTX_CONSOLE_DISCONNECT: NtStatus = NtStatus(0xc00a0027);
pub const NT_STATUS_CTX_CONSOLE_CONNECT: NtStatus = NtStatus(0xc00a0028);
pub const NT_STATUS_CTX_SHADOW_DENIED: NtStatus = NtStatus(0xc00a002a);
pub const NT_STATUS_CTX_WINSTATION_ACCESS_DENIED: NtStatus =
    NtStatus(0xc00a002b);
pub const NT_STATUS_CTX_INVALID_WD: NtStatus = NtStatus(0xc00a002e);
pub const NT_STATUS_CTX_WD_NOT_FOUND: NtStatus = NtStatus(0xc00a002f);
pub const NT_STATUS_CTX_SHADOW_INVALID: NtStatus = NtStatus(0xc00a0030);
pub const NT_STATUS_CTX_SHADOW_DISABLED: NtStatus = NtStatus(0xc00a0031);
pub const NT_STATUS_RDP_PROTOCOL_ERROR: NtStatus = NtStatus(0xc00a0032);
pub const NT_STATUS_CTX_CLIENT_LICENSE_NOT_SET: NtStatus = NtStatus(0xc00a0033);
pub const NT_STATUS_CTX_CLIENT_LICENSE_IN_USE: NtStatus = NtStatus(0xc00a0034);
pub const NT_STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE: NtStatus =
    NtStatus(0xc00a0035);
pub const NT_STATUS_CTX_SHADOW_NOT_RUNNING: NtStatus = NtStatus(0xc00a0036);
pub const NT_STATUS_CTX_LOGON_DISABLED: NtStatus = NtStatus(0xc00a0037);
pub const NT_STATUS_CTX_SECURITY_LAYER_ERROR: NtStatus = NtStatus(0xc00a0038);
pub const NT_STATUS_TS_INCOMPATIBLE_SESSIONS: NtStatus = NtStatus(0xc00a0039);
pub const NT_STATUS_MUI_FILE_NOT_FOUND: NtStatus = NtStatus(0xc00b0001);
pub const NT_STATUS_MUI_INVALID_FILE: NtStatus = NtStatus(0xc00b0002);
pub const NT_STATUS_MUI_INVALID_RC_CONFIG: NtStatus = NtStatus(0xc00b0003);
pub const NT_STATUS_MUI_INVALID_LOCALE_NAME: NtStatus = NtStatus(0xc00b0004);
pub const NT_STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME: NtStatus =
    NtStatus(0xc00b0005);
pub const NT_STATUS_MUI_FILE_NOT_LOADED: NtStatus = NtStatus(0xc00b0006);
pub const NT_STATUS_RESOURCE_ENUM_USER_STOP: NtStatus = NtStatus(0xc00b0007);
pub const NT_STATUS_CLUSTER_INVALID_NODE: NtStatus = NtStatus(0xc0130001);
pub const NT_STATUS_CLUSTER_NODE_EXISTS: NtStatus = NtStatus(0xc0130002);
pub const NT_STATUS_CLUSTER_JOIN_IN_PROGRESS: NtStatus = NtStatus(0xc0130003);
pub const NT_STATUS_CLUSTER_NODE_NOT_FOUND: NtStatus = NtStatus(0xc0130004);
pub const NT_STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND: NtStatus =
    NtStatus(0xc0130005);
pub const NT_STATUS_CLUSTER_NETWORK_EXISTS: NtStatus = NtStatus(0xc0130006);
pub const NT_STATUS_CLUSTER_NETWORK_NOT_FOUND: NtStatus = NtStatus(0xc0130007);
pub const NT_STATUS_CLUSTER_NETINTERFACE_EXISTS: NtStatus =
    NtStatus(0xc0130008);
pub const NT_STATUS_CLUSTER_NETINTERFACE_NOT_FOUND: NtStatus =
    NtStatus(0xc0130009);
pub const NT_STATUS_CLUSTER_INVALID_REQUEST: NtStatus = NtStatus(0xc013000a);
pub const NT_STATUS_CLUSTER_INVALID_NETWORK_PROVIDER: NtStatus =
    NtStatus(0xc013000b);
pub const NT_STATUS_CLUSTER_NODE_DOWN: NtStatus = NtStatus(0xc013000c);
pub const NT_STATUS_CLUSTER_NODE_UNREACHABLE: NtStatus = NtStatus(0xc013000d);
pub const NT_STATUS_CLUSTER_NODE_NOT_MEMBER: NtStatus = NtStatus(0xc013000e);
pub const NT_STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS: NtStatus =
    NtStatus(0xc013000f);
pub const NT_STATUS_CLUSTER_INVALID_NETWORK: NtStatus = NtStatus(0xc0130010);
pub const NT_STATUS_CLUSTER_NO_NET_ADAPTERS: NtStatus = NtStatus(0xc0130011);
pub const NT_STATUS_CLUSTER_NODE_UP: NtStatus = NtStatus(0xc0130012);
pub const NT_STATUS_CLUSTER_NODE_PAUSED: NtStatus = NtStatus(0xc0130013);
pub const NT_STATUS_CLUSTER_NODE_NOT_PAUSED: NtStatus = NtStatus(0xc0130014);
pub const NT_STATUS_CLUSTER_NO_SECURITY_CONTEXT: NtStatus =
    NtStatus(0xc0130015);
pub const NT_STATUS_CLUSTER_NETWORK_NOT_INTERNAL: NtStatus =
    NtStatus(0xc0130016);
pub const NT_STATUS_CLUSTER_POISONED: NtStatus = NtStatus(0xc0130017);
pub const NT_STATUS_ACPI_INVALID_OPCODE: NtStatus = NtStatus(0xc0140001);
pub const NT_STATUS_ACPI_STACK_OVERFLOW: NtStatus = NtStatus(0xc0140002);
pub const NT_STATUS_ACPI_ASSERT_FAILED: NtStatus = NtStatus(0xc0140003);
pub const NT_STATUS_ACPI_INVALID_INDEX: NtStatus = NtStatus(0xc0140004);
pub const NT_STATUS_ACPI_INVALID_ARGUMENT: NtStatus = NtStatus(0xc0140005);
pub const NT_STATUS_ACPI_FATAL: NtStatus = NtStatus(0xc0140006);
pub const NT_STATUS_ACPI_INVALID_SUPERNAME: NtStatus = NtStatus(0xc0140007);
pub const NT_STATUS_ACPI_INVALID_ARGTYPE: NtStatus = NtStatus(0xc0140008);
pub const NT_STATUS_ACPI_INVALID_OBJTYPE: NtStatus = NtStatus(0xc0140009);
pub const NT_STATUS_ACPI_INVALID_TARGETTYPE: NtStatus = NtStatus(0xc014000a);
pub const NT_STATUS_ACPI_INCORRECT_ARGUMENT_COUNT: NtStatus =
    NtStatus(0xc014000b);
pub const NT_STATUS_ACPI_ADDRESS_NOT_MAPPED: NtStatus = NtStatus(0xc014000c);
pub const NT_STATUS_ACPI_INVALID_EVENTTYPE: NtStatus = NtStatus(0xc014000d);
pub const NT_STATUS_ACPI_HANDLER_COLLISION: NtStatus = NtStatus(0xc014000e);
pub const NT_STATUS_ACPI_INVALID_DATA: NtStatus = NtStatus(0xc014000f);
pub const NT_STATUS_ACPI_INVALID_REGION: NtStatus = NtStatus(0xc0140010);
pub const NT_STATUS_ACPI_INVALID_ACCESS_SIZE: NtStatus = NtStatus(0xc0140011);
pub const NT_STATUS_ACPI_ACQUIRE_GLOBAL_LOCK: NtStatus = NtStatus(0xc0140012);
pub const NT_STATUS_ACPI_ALREADY_INITIALIZED: NtStatus = NtStatus(0xc0140013);
pub const NT_STATUS_ACPI_NOT_INITIALIZED: NtStatus = NtStatus(0xc0140014);
pub const NT_STATUS_ACPI_INVALID_MUTEX_LEVEL: NtStatus = NtStatus(0xc0140015);
pub const NT_STATUS_ACPI_MUTEX_NOT_OWNED: NtStatus = NtStatus(0xc0140016);
pub const NT_STATUS_ACPI_MUTEX_NOT_OWNER: NtStatus = NtStatus(0xc0140017);
pub const NT_STATUS_ACPI_RS_ACCESS: NtStatus = NtStatus(0xc0140018);
pub const NT_STATUS_ACPI_INVALID_TABLE: NtStatus = NtStatus(0xc0140019);
pub const NT_STATUS_ACPI_REG_HANDLER_FAILED: NtStatus = NtStatus(0xc0140020);
pub const NT_STATUS_ACPI_POWER_REQUEST_FAILED: NtStatus = NtStatus(0xc0140021);
pub const NT_STATUS_SXS_SECTION_NOT_FOUND: NtStatus = NtStatus(0xc0150001);
pub const NT_STATUS_SXS_CANT_GEN_ACTCTX: NtStatus = NtStatus(0xc0150002);
pub const NT_STATUS_SXS_INVALID_ACTCTXDATA_FORMAT: NtStatus =
    NtStatus(0xc0150003);
pub const NT_STATUS_SXS_ASSEMBLY_NOT_FOUND: NtStatus = NtStatus(0xc0150004);
pub const NT_STATUS_SXS_MANIFEST_FORMAT_ERROR: NtStatus = NtStatus(0xc0150005);
pub const NT_STATUS_SXS_MANIFEST_PARSE_ERROR: NtStatus = NtStatus(0xc0150006);
pub const NT_STATUS_SXS_ACTIVATION_CONTEXT_DISABLED: NtStatus =
    NtStatus(0xc0150007);
pub const NT_STATUS_SXS_KEY_NOT_FOUND: NtStatus = NtStatus(0xc0150008);
pub const NT_STATUS_SXS_VERSION_CONFLICT: NtStatus = NtStatus(0xc0150009);
pub const NT_STATUS_SXS_WRONG_SECTION_TYPE: NtStatus = NtStatus(0xc015000a);
pub const NT_STATUS_SXS_THREAD_QUERIES_DISABLED: NtStatus =
    NtStatus(0xc015000b);
pub const NT_STATUS_SXS_ASSEMBLY_MISSING: NtStatus = NtStatus(0xc015000c);
pub const NT_STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET: NtStatus =
    NtStatus(0xc015000e);
pub const NT_STATUS_SXS_EARLY_DEACTIVATION: NtStatus = NtStatus(0xc015000f);
pub const NT_STATUS_SXS_INVALID_DEACTIVATION: NtStatus = NtStatus(0xc0150010);
pub const NT_STATUS_SXS_MULTIPLE_DEACTIVATION: NtStatus = NtStatus(0xc0150011);
pub const NT_STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY: NtStatus =
    NtStatus(0xc0150012);
pub const NT_STATUS_SXS_PROCESS_TERMINATION_REQUESTED: NtStatus =
    NtStatus(0xc0150013);
pub const NT_STATUS_SXS_CORRUPT_ACTIVATION_STACK: NtStatus =
    NtStatus(0xc0150014);
pub const NT_STATUS_SXS_CORRUPTION: NtStatus = NtStatus(0xc0150015);
pub const NT_STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE: NtStatus =
    NtStatus(0xc0150016);
pub const NT_STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME: NtStatus =
    NtStatus(0xc0150017);
pub const NT_STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE: NtStatus =
    NtStatus(0xc0150018);
pub const NT_STATUS_SXS_IDENTITY_PARSE_ERROR: NtStatus = NtStatus(0xc0150019);
pub const NT_STATUS_SXS_COMPONENT_STORE_CORRUPT: NtStatus =
    NtStatus(0xc015001a);
pub const NT_STATUS_SXS_FILE_HASH_MISMATCH: NtStatus = NtStatus(0xc015001b);
pub const NT_STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT:
    NtStatus = NtStatus(0xc015001c);
pub const NT_STATUS_SXS_IDENTITIES_DIFFERENT: NtStatus = NtStatus(0xc015001d);
pub const NT_STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT: NtStatus =
    NtStatus(0xc015001e);
pub const NT_STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY: NtStatus =
    NtStatus(0xc015001f);
pub const NT_STATUS_ADVANCED_INSTALLER_FAILED: NtStatus = NtStatus(0xc0150020);
pub const NT_STATUS_XML_ENCODING_MISMATCH: NtStatus = NtStatus(0xc0150021);
pub const NT_STATUS_SXS_MANIFEST_TOO_BIG: NtStatus = NtStatus(0xc0150022);
pub const NT_STATUS_SXS_SETTING_NOT_REGISTERED: NtStatus = NtStatus(0xc0150023);
pub const NT_STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE: NtStatus =
    NtStatus(0xc0150024);
pub const NT_STATUS_SMI_PRIMITIVE_INSTALLER_FAILED: NtStatus =
    NtStatus(0xc0150025);
pub const NT_STATUS_GENERIC_COMMAND_FAILED: NtStatus = NtStatus(0xc0150026);
pub const NT_STATUS_SXS_FILE_HASH_MISSING: NtStatus = NtStatus(0xc0150027);
pub const NT_STATUS_TRANSACTIONAL_CONFLICT: NtStatus = NtStatus(0xc0190001);
pub const NT_STATUS_INVALID_TRANSACTION: NtStatus = NtStatus(0xc0190002);
pub const NT_STATUS_TRANSACTION_NOT_ACTIVE: NtStatus = NtStatus(0xc0190003);
pub const NT_STATUS_TM_INITIALIZATION_FAILED: NtStatus = NtStatus(0xc0190004);
pub const NT_STATUS_RM_NOT_ACTIVE: NtStatus = NtStatus(0xc0190005);
pub const NT_STATUS_RM_METADATA_CORRUPT: NtStatus = NtStatus(0xc0190006);
pub const NT_STATUS_TRANSACTION_NOT_JOINED: NtStatus = NtStatus(0xc0190007);
pub const NT_STATUS_DIRECTORY_NOT_RM: NtStatus = NtStatus(0xc0190008);
pub const NT_STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE: NtStatus =
    NtStatus(0xc019000a);
pub const NT_STATUS_LOG_RESIZE_INVALID_SIZE: NtStatus = NtStatus(0xc019000b);
pub const NT_STATUS_REMOTE_FILE_VERSION_MISMATCH: NtStatus =
    NtStatus(0xc019000c);
pub const NT_STATUS_CRM_PROTOCOL_ALREADY_EXISTS: NtStatus =
    NtStatus(0xc019000f);
pub const NT_STATUS_TRANSACTION_PROPAGATION_FAILED: NtStatus =
    NtStatus(0xc0190010);
pub const NT_STATUS_CRM_PROTOCOL_NOT_FOUND: NtStatus = NtStatus(0xc0190011);
pub const NT_STATUS_TRANSACTION_SUPERIOR_EXISTS: NtStatus =
    NtStatus(0xc0190012);
pub const NT_STATUS_TRANSACTION_REQUEST_NOT_VALID: NtStatus =
    NtStatus(0xc0190013);
pub const NT_STATUS_TRANSACTION_NOT_REQUESTED: NtStatus = NtStatus(0xc0190014);
pub const NT_STATUS_TRANSACTION_ALREADY_ABORTED: NtStatus =
    NtStatus(0xc0190015);
pub const NT_STATUS_TRANSACTION_ALREADY_COMMITTED: NtStatus =
    NtStatus(0xc0190016);
pub const NT_STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER: NtStatus =
    NtStatus(0xc0190017);
pub const NT_STATUS_CURRENT_TRANSACTION_NOT_VALID: NtStatus =
    NtStatus(0xc0190018);
pub const NT_STATUS_LOG_GROWTH_FAILED: NtStatus = NtStatus(0xc0190019);
pub const NT_STATUS_OBJECT_NO_LONGER_EXISTS: NtStatus = NtStatus(0xc0190021);
pub const NT_STATUS_STREAM_MINIVERSION_NOT_FOUND: NtStatus =
    NtStatus(0xc0190022);
pub const NT_STATUS_STREAM_MINIVERSION_NOT_VALID: NtStatus =
    NtStatus(0xc0190023);
pub const NT_STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION:
    NtStatus = NtStatus(0xc0190024);
pub const NT_STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT: NtStatus =
    NtStatus(0xc0190025);
pub const NT_STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS: NtStatus =
    NtStatus(0xc0190026);
pub const NT_STATUS_HANDLE_NO_LONGER_VALID: NtStatus = NtStatus(0xc0190028);
pub const NT_STATUS_LOG_CORRUPTION_DETECTED: NtStatus = NtStatus(0xc0190030);
pub const NT_STATUS_RM_DISCONNECTED: NtStatus = NtStatus(0xc0190032);
pub const NT_STATUS_ENLISTMENT_NOT_SUPERIOR: NtStatus = NtStatus(0xc0190033);
pub const NT_STATUS_FILE_IDENTITY_NOT_PERSISTENT: NtStatus =
    NtStatus(0xc0190036);
pub const NT_STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY: NtStatus =
    NtStatus(0xc0190037);
pub const NT_STATUS_CANT_CROSS_RM_BOUNDARY: NtStatus = NtStatus(0xc0190038);
pub const NT_STATUS_TXF_DIR_NOT_EMPTY: NtStatus = NtStatus(0xc0190039);
pub const NT_STATUS_INDOUBT_TRANSACTIONS_EXIST: NtStatus = NtStatus(0xc019003a);
pub const NT_STATUS_TM_VOLATILE: NtStatus = NtStatus(0xc019003b);
pub const NT_STATUS_ROLLBACK_TIMER_EXPIRED: NtStatus = NtStatus(0xc019003c);
pub const NT_STATUS_TXF_ATTRIBUTE_CORRUPT: NtStatus = NtStatus(0xc019003d);
pub const NT_STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION: NtStatus =
    NtStatus(0xc019003e);
pub const NT_STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED: NtStatus =
    NtStatus(0xc019003f);
pub const NT_STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE: NtStatus =
    NtStatus(0xc0190040);
pub const NT_STATUS_TRANSACTION_REQUIRED_PROMOTION: NtStatus =
    NtStatus(0xc0190043);
pub const NT_STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION: NtStatus =
    NtStatus(0xc0190044);
pub const NT_STATUS_TRANSACTIONS_NOT_FROZEN: NtStatus = NtStatus(0xc0190045);
pub const NT_STATUS_TRANSACTION_FREEZE_IN_PROGRESS: NtStatus =
    NtStatus(0xc0190046);
pub const NT_STATUS_NOT_SNAPSHOT_VOLUME: NtStatus = NtStatus(0xc0190047);
pub const NT_STATUS_NO_SAVEPOINT_WITH_OPEN_FILES: NtStatus =
    NtStatus(0xc0190048);
pub const NT_STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION: NtStatus =
    NtStatus(0xc0190049);
pub const NT_STATUS_TM_IDENTITY_MISMATCH: NtStatus = NtStatus(0xc019004a);
pub const NT_STATUS_FLOATED_SECTION: NtStatus = NtStatus(0xc019004b);
pub const NT_STATUS_CANNOT_ACCEPT_TRANSACTED_WORK: NtStatus =
    NtStatus(0xc019004c);
pub const NT_STATUS_CANNOT_ABORT_TRANSACTIONS: NtStatus = NtStatus(0xc019004d);
pub const NT_STATUS_TRANSACTION_NOT_FOUND: NtStatus = NtStatus(0xc019004e);
pub const NT_STATUS_RESOURCEMANAGER_NOT_FOUND: NtStatus = NtStatus(0xc019004f);
pub const NT_STATUS_ENLISTMENT_NOT_FOUND: NtStatus = NtStatus(0xc0190050);
pub const NT_STATUS_TRANSACTIONMANAGER_NOT_FOUND: NtStatus =
    NtStatus(0xc0190051);
pub const NT_STATUS_TRANSACTIONMANAGER_NOT_ONLINE: NtStatus =
    NtStatus(0xc0190052);
pub const NT_STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION: NtStatus =
    NtStatus(0xc0190053);
pub const NT_STATUS_TRANSACTION_NOT_ROOT: NtStatus = NtStatus(0xc0190054);
pub const NT_STATUS_TRANSACTION_OBJECT_EXPIRED: NtStatus = NtStatus(0xc0190055);
pub const NT_STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION: NtStatus =
    NtStatus(0xc0190056);
pub const NT_STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED: NtStatus =
    NtStatus(0xc0190057);
pub const NT_STATUS_TRANSACTION_RECORD_TOO_LONG: NtStatus =
    NtStatus(0xc0190058);
pub const NT_STATUS_NO_LINK_TRACKING_IN_TRANSACTION: NtStatus =
    NtStatus(0xc0190059);
pub const NT_STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION: NtStatus =
    NtStatus(0xc019005a);
pub const NT_STATUS_TRANSACTION_INTEGRITY_VIOLATED: NtStatus =
    NtStatus(0xc019005b);
pub const NT_STATUS_EXPIRED_HANDLE: NtStatus = NtStatus(0xc0190060);
pub const NT_STATUS_TRANSACTION_NOT_ENLISTED: NtStatus = NtStatus(0xc0190061);
pub const NT_STATUS_LOG_SECTOR_INVALID: NtStatus = NtStatus(0xc01a0001);
pub const NT_STATUS_LOG_SECTOR_PARITY_INVALID: NtStatus = NtStatus(0xc01a0002);
pub const NT_STATUS_LOG_SECTOR_REMAPPED: NtStatus = NtStatus(0xc01a0003);
pub const NT_STATUS_LOG_BLOCK_INCOMPLETE: NtStatus = NtStatus(0xc01a0004);
pub const NT_STATUS_LOG_INVALID_RANGE: NtStatus = NtStatus(0xc01a0005);
pub const NT_STATUS_LOG_BLOCKS_EXHAUSTED: NtStatus = NtStatus(0xc01a0006);
pub const NT_STATUS_LOG_READ_CONTEXT_INVALID: NtStatus = NtStatus(0xc01a0007);
pub const NT_STATUS_LOG_RESTART_INVALID: NtStatus = NtStatus(0xc01a0008);
pub const NT_STATUS_LOG_BLOCK_VERSION: NtStatus = NtStatus(0xc01a0009);
pub const NT_STATUS_LOG_BLOCK_INVALID: NtStatus = NtStatus(0xc01a000a);
pub const NT_STATUS_LOG_READ_MODE_INVALID: NtStatus = NtStatus(0xc01a000b);
pub const NT_STATUS_LOG_METADATA_CORRUPT: NtStatus = NtStatus(0xc01a000d);
pub const NT_STATUS_LOG_METADATA_INVALID: NtStatus = NtStatus(0xc01a000e);
pub const NT_STATUS_LOG_METADATA_INCONSISTENT: NtStatus = NtStatus(0xc01a000f);
pub const NT_STATUS_LOG_RESERVATION_INVALID: NtStatus = NtStatus(0xc01a0010);
pub const NT_STATUS_LOG_CANT_DELETE: NtStatus = NtStatus(0xc01a0011);
pub const NT_STATUS_LOG_CONTAINER_LIMIT_EXCEEDED: NtStatus =
    NtStatus(0xc01a0012);
pub const NT_STATUS_LOG_START_OF_LOG: NtStatus = NtStatus(0xc01a0013);
pub const NT_STATUS_LOG_POLICY_ALREADY_INSTALLED: NtStatus =
    NtStatus(0xc01a0014);
pub const NT_STATUS_LOG_POLICY_NOT_INSTALLED: NtStatus = NtStatus(0xc01a0015);
pub const NT_STATUS_LOG_POLICY_INVALID: NtStatus = NtStatus(0xc01a0016);
pub const NT_STATUS_LOG_POLICY_CONFLICT: NtStatus = NtStatus(0xc01a0017);
pub const NT_STATUS_LOG_PINNED_ARCHIVE_TAIL: NtStatus = NtStatus(0xc01a0018);
pub const NT_STATUS_LOG_RECORD_NONEXISTENT: NtStatus = NtStatus(0xc01a0019);
pub const NT_STATUS_LOG_RECORDS_RESERVED_INVALID: NtStatus =
    NtStatus(0xc01a001a);
pub const NT_STATUS_LOG_SPACE_RESERVED_INVALID: NtStatus = NtStatus(0xc01a001b);
pub const NT_STATUS_LOG_TAIL_INVALID: NtStatus = NtStatus(0xc01a001c);
pub const NT_STATUS_LOG_FULL: NtStatus = NtStatus(0xc01a001d);
pub const NT_STATUS_LOG_MULTIPLEXED: NtStatus = NtStatus(0xc01a001e);
pub const NT_STATUS_LOG_DEDICATED: NtStatus = NtStatus(0xc01a001f);
pub const NT_STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS: NtStatus =
    NtStatus(0xc01a0020);
pub const NT_STATUS_LOG_ARCHIVE_IN_PROGRESS: NtStatus = NtStatus(0xc01a0021);
pub const NT_STATUS_LOG_EPHEMERAL: NtStatus = NtStatus(0xc01a0022);
pub const NT_STATUS_LOG_NOT_ENOUGH_CONTAINERS: NtStatus = NtStatus(0xc01a0023);
pub const NT_STATUS_LOG_CLIENT_ALREADY_REGISTERED: NtStatus =
    NtStatus(0xc01a0024);
pub const NT_STATUS_LOG_CLIENT_NOT_REGISTERED: NtStatus = NtStatus(0xc01a0025);
pub const NT_STATUS_LOG_FULL_HANDLER_IN_PROGRESS: NtStatus =
    NtStatus(0xc01a0026);
pub const NT_STATUS_LOG_CONTAINER_READ_FAILED: NtStatus = NtStatus(0xc01a0027);
pub const NT_STATUS_LOG_CONTAINER_WRITE_FAILED: NtStatus = NtStatus(0xc01a0028);
pub const NT_STATUS_LOG_CONTAINER_OPEN_FAILED: NtStatus = NtStatus(0xc01a0029);
pub const NT_STATUS_LOG_CONTAINER_STATE_INVALID: NtStatus =
    NtStatus(0xc01a002a);
pub const NT_STATUS_LOG_STATE_INVALID: NtStatus = NtStatus(0xc01a002b);
pub const NT_STATUS_LOG_PINNED: NtStatus = NtStatus(0xc01a002c);
pub const NT_STATUS_LOG_METADATA_FLUSH_FAILED: NtStatus = NtStatus(0xc01a002d);
pub const NT_STATUS_LOG_INCONSISTENT_SECURITY: NtStatus = NtStatus(0xc01a002e);
pub const NT_STATUS_LOG_APPENDED_FLUSH_FAILED: NtStatus = NtStatus(0xc01a002f);
pub const NT_STATUS_LOG_PINNED_RESERVATION: NtStatus = NtStatus(0xc01a0030);
pub const NT_STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD: NtStatus =
    NtStatus(0xc01b00ea);
pub const NT_STATUS_FLT_NO_HANDLER_DEFINED: NtStatus = NtStatus(0xc01c0001);
pub const NT_STATUS_FLT_CONTEXT_ALREADY_DEFINED: NtStatus =
    NtStatus(0xc01c0002);
pub const NT_STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST: NtStatus =
    NtStatus(0xc01c0003);
pub const NT_STATUS_FLT_DISALLOW_FAST_IO: NtStatus = NtStatus(0xc01c0004);
pub const NT_STATUS_FLT_INVALID_NAME_REQUEST: NtStatus = NtStatus(0xc01c0005);
pub const NT_STATUS_FLT_NOT_SAFE_TO_POST_OPERATION: NtStatus =
    NtStatus(0xc01c0006);
pub const NT_STATUS_FLT_NOT_INITIALIZED: NtStatus = NtStatus(0xc01c0007);
pub const NT_STATUS_FLT_FILTER_NOT_READY: NtStatus = NtStatus(0xc01c0008);
pub const NT_STATUS_FLT_POST_OPERATION_CLEANUP: NtStatus = NtStatus(0xc01c0009);
pub const NT_STATUS_FLT_INTERNAL_ERROR: NtStatus = NtStatus(0xc01c000a);
pub const NT_STATUS_FLT_DELETING_OBJECT: NtStatus = NtStatus(0xc01c000b);
pub const NT_STATUS_FLT_MUST_BE_NONPAGED_POOL: NtStatus = NtStatus(0xc01c000c);
pub const NT_STATUS_FLT_DUPLICATE_ENTRY: NtStatus = NtStatus(0xc01c000d);
pub const NT_STATUS_FLT_CBDQ_DISABLED: NtStatus = NtStatus(0xc01c000e);
pub const NT_STATUS_FLT_DO_NOT_ATTACH: NtStatus = NtStatus(0xc01c000f);
pub const NT_STATUS_FLT_DO_NOT_DETACH: NtStatus = NtStatus(0xc01c0010);
pub const NT_STATUS_FLT_INSTANCE_ALTITUDE_COLLISION: NtStatus =
    NtStatus(0xc01c0011);
pub const NT_STATUS_FLT_INSTANCE_NAME_COLLISION: NtStatus =
    NtStatus(0xc01c0012);
pub const NT_STATUS_FLT_FILTER_NOT_FOUND: NtStatus = NtStatus(0xc01c0013);
pub const NT_STATUS_FLT_VOLUME_NOT_FOUND: NtStatus = NtStatus(0xc01c0014);
pub const NT_STATUS_FLT_INSTANCE_NOT_FOUND: NtStatus = NtStatus(0xc01c0015);
pub const NT_STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND: NtStatus =
    NtStatus(0xc01c0016);
pub const NT_STATUS_FLT_INVALID_CONTEXT_REGISTRATION: NtStatus =
    NtStatus(0xc01c0017);
pub const NT_STATUS_FLT_NAME_CACHE_MISS: NtStatus = NtStatus(0xc01c0018);
pub const NT_STATUS_FLT_NO_DEVICE_OBJECT: NtStatus = NtStatus(0xc01c0019);
pub const NT_STATUS_FLT_VOLUME_ALREADY_MOUNTED: NtStatus = NtStatus(0xc01c001a);
pub const NT_STATUS_FLT_ALREADY_ENLISTED: NtStatus = NtStatus(0xc01c001b);
pub const NT_STATUS_FLT_CONTEXT_ALREADY_LINKED: NtStatus = NtStatus(0xc01c001c);
pub const NT_STATUS_FLT_NO_WAITER_FOR_REPLY: NtStatus = NtStatus(0xc01c0020);
pub const NT_STATUS_MONITOR_NO_DESCRIPTOR: NtStatus = NtStatus(0xc01d0001);
pub const NT_STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT: NtStatus =
    NtStatus(0xc01d0002);
pub const NT_STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM: NtStatus =
    NtStatus(0xc01d0003);
pub const NT_STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK: NtStatus =
    NtStatus(0xc01d0004);
pub const NT_STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED: NtStatus =
    NtStatus(0xc01d0005);
pub const NT_STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK: NtStatus =
    NtStatus(0xc01d0006);
pub const NT_STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK: NtStatus =
    NtStatus(0xc01d0007);
pub const NT_STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA: NtStatus =
    NtStatus(0xc01d0008);
pub const NT_STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK: NtStatus =
    NtStatus(0xc01d0009);
pub const NT_STATUS_MONITOR_INVALID_MANUFACTURE_DATE: NtStatus =
    NtStatus(0xc01d000a);
pub const NT_STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER: NtStatus =
    NtStatus(0xc01e0000);
pub const NT_STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER: NtStatus =
    NtStatus(0xc01e0001);
pub const NT_STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER: NtStatus =
    NtStatus(0xc01e0002);
pub const NT_STATUS_GRAPHICS_ADAPTER_WAS_RESET: NtStatus = NtStatus(0xc01e0003);
pub const NT_STATUS_GRAPHICS_INVALID_DRIVER_MODEL: NtStatus =
    NtStatus(0xc01e0004);
pub const NT_STATUS_GRAPHICS_PRESENT_MODE_CHANGED: NtStatus =
    NtStatus(0xc01e0005);
pub const NT_STATUS_GRAPHICS_PRESENT_OCCLUDED: NtStatus = NtStatus(0xc01e0006);
pub const NT_STATUS_GRAPHICS_PRESENT_DENIED: NtStatus = NtStatus(0xc01e0007);
pub const NT_STATUS_GRAPHICS_CANNOTCOLORCONVERT: NtStatus =
    NtStatus(0xc01e0008);
pub const NT_STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED: NtStatus =
    NtStatus(0xc01e000b);
pub const NT_STATUS_GRAPHICS_PRESENT_UNOCCLUDED: NtStatus =
    NtStatus(0xc01e000c);
pub const NT_STATUS_GRAPHICS_NO_VIDEO_MEMORY: NtStatus = NtStatus(0xc01e0100);
pub const NT_STATUS_GRAPHICS_CANT_LOCK_MEMORY: NtStatus = NtStatus(0xc01e0101);
pub const NT_STATUS_GRAPHICS_ALLOCATION_BUSY: NtStatus = NtStatus(0xc01e0102);
pub const NT_STATUS_GRAPHICS_TOO_MANY_REFERENCES: NtStatus =
    NtStatus(0xc01e0103);
pub const NT_STATUS_GRAPHICS_TRY_AGAIN_LATER: NtStatus = NtStatus(0xc01e0104);
pub const NT_STATUS_GRAPHICS_TRY_AGAIN_NOW: NtStatus = NtStatus(0xc01e0105);
pub const NT_STATUS_GRAPHICS_ALLOCATION_INVALID: NtStatus =
    NtStatus(0xc01e0106);
pub const NT_STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE: NtStatus =
    NtStatus(0xc01e0107);
pub const NT_STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED: NtStatus =
    NtStatus(0xc01e0108);
pub const NT_STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION: NtStatus =
    NtStatus(0xc01e0109);
pub const NT_STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE: NtStatus =
    NtStatus(0xc01e0110);
pub const NT_STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION: NtStatus =
    NtStatus(0xc01e0111);
pub const NT_STATUS_GRAPHICS_ALLOCATION_CLOSED: NtStatus = NtStatus(0xc01e0112);
pub const NT_STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE: NtStatus =
    NtStatus(0xc01e0113);
pub const NT_STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE: NtStatus =
    NtStatus(0xc01e0114);
pub const NT_STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE: NtStatus =
    NtStatus(0xc01e0115);
pub const NT_STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST: NtStatus =
    NtStatus(0xc01e0116);
pub const NT_STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE: NtStatus =
    NtStatus(0xc01e0200);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e0300);
pub const NT_STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0301);
pub const NT_STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0302);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN: NtStatus = NtStatus(0xc01e0303);
pub const NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE: NtStatus =
    NtStatus(0xc01e0304);
pub const NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET: NtStatus =
    NtStatus(0xc01e0305);
pub const NT_STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0306);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET: NtStatus =
    NtStatus(0xc01e0308);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET: NtStatus =
    NtStatus(0xc01e0309);
pub const NT_STATUS_GRAPHICS_INVALID_FREQUENCY: NtStatus = NtStatus(0xc01e030a);
pub const NT_STATUS_GRAPHICS_INVALID_ACTIVE_REGION: NtStatus =
    NtStatus(0xc01e030b);
pub const NT_STATUS_GRAPHICS_INVALID_TOTAL_REGION: NtStatus =
    NtStatus(0xc01e030c);
pub const NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE: NtStatus =
    NtStatus(0xc01e0310);
pub const NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE: NtStatus =
    NtStatus(0xc01e0311);
pub const NT_STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET: NtStatus =
    NtStatus(0xc01e0312);
pub const NT_STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e0313);
pub const NT_STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET: NtStatus =
    NtStatus(0xc01e0314);
pub const NT_STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET: NtStatus =
    NtStatus(0xc01e0315);
pub const NT_STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET: NtStatus =
    NtStatus(0xc01e0316);
pub const NT_STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET: NtStatus =
    NtStatus(0xc01e0317);
pub const NT_STATUS_GRAPHICS_TARGET_ALREADY_IN_SET: NtStatus =
    NtStatus(0xc01e0318);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH: NtStatus =
    NtStatus(0xc01e0319);
pub const NT_STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e031a);
pub const NT_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET: NtStatus =
    NtStatus(0xc01e031b);
pub const NT_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE: NtStatus =
    NtStatus(0xc01e031c);
pub const NT_STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET: NtStatus =
    NtStatus(0xc01e031d);
pub const NT_STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET: NtStatus =
    NtStatus(0xc01e031f);
pub const NT_STATUS_GRAPHICS_STALE_MODESET: NtStatus = NtStatus(0xc01e0320);
pub const NT_STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET: NtStatus =
    NtStatus(0xc01e0321);
pub const NT_STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE: NtStatus =
    NtStatus(0xc01e0322);
pub const NT_STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN: NtStatus =
    NtStatus(0xc01e0323);
pub const NT_STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE: NtStatus =
    NtStatus(0xc01e0324);
pub const NT_STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION:
    NtStatus = NtStatus(0xc01e0325);
pub const NT_STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES: NtStatus =
    NtStatus(0xc01e0326);
pub const NT_STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e0327);
pub const NT_STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE: NtStatus =
    NtStatus(0xc01e0328);
pub const NT_STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET: NtStatus =
    NtStatus(0xc01e0329);
pub const NT_STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET: NtStatus =
    NtStatus(0xc01e032a);
pub const NT_STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR: NtStatus =
    NtStatus(0xc01e032b);
pub const NT_STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET: NtStatus =
    NtStatus(0xc01e032c);
pub const NT_STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET: NtStatus =
    NtStatus(0xc01e032d);
pub const NT_STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE: NtStatus =
    NtStatus(0xc01e032e);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE: NtStatus =
    NtStatus(0xc01e032f);
pub const NT_STATUS_GRAPHICS_RESOURCES_NOT_RELATED: NtStatus =
    NtStatus(0xc01e0330);
pub const NT_STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE: NtStatus =
    NtStatus(0xc01e0331);
pub const NT_STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE: NtStatus =
    NtStatus(0xc01e0332);
pub const NT_STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET: NtStatus =
    NtStatus(0xc01e0333);
pub const NT_STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER:
    NtStatus = NtStatus(0xc01e0334);
pub const NT_STATUS_GRAPHICS_NO_VIDPNMGR: NtStatus = NtStatus(0xc01e0335);
pub const NT_STATUS_GRAPHICS_NO_ACTIVE_VIDPN: NtStatus = NtStatus(0xc01e0336);
pub const NT_STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e0337);
pub const NT_STATUS_GRAPHICS_MONITOR_NOT_CONNECTED: NtStatus =
    NtStatus(0xc01e0338);
pub const NT_STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e0339);
pub const NT_STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE: NtStatus =
    NtStatus(0xc01e033a);
pub const NT_STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE: NtStatus =
    NtStatus(0xc01e033b);
pub const NT_STATUS_GRAPHICS_INVALID_STRIDE: NtStatus = NtStatus(0xc01e033c);
pub const NT_STATUS_GRAPHICS_INVALID_PIXELFORMAT: NtStatus =
    NtStatus(0xc01e033d);
pub const NT_STATUS_GRAPHICS_INVALID_COLORBASIS: NtStatus =
    NtStatus(0xc01e033e);
pub const NT_STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE: NtStatus =
    NtStatus(0xc01e033f);
pub const NT_STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY: NtStatus =
    NtStatus(0xc01e0340);
pub const NT_STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT: NtStatus =
    NtStatus(0xc01e0341);
pub const NT_STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE: NtStatus =
    NtStatus(0xc01e0342);
pub const NT_STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN: NtStatus =
    NtStatus(0xc01e0343);
pub const NT_STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL: NtStatus =
    NtStatus(0xc01e0344);
pub const NT_STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION:
    NtStatus = NtStatus(0xc01e0345);
pub const NT_STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0346);
pub const NT_STATUS_GRAPHICS_INVALID_GAMMA_RAMP: NtStatus =
    NtStatus(0xc01e0347);
pub const NT_STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0348);
pub const NT_STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0349);
pub const NT_STATUS_GRAPHICS_MODE_NOT_IN_MODESET: NtStatus =
    NtStatus(0xc01e034a);
pub const NT_STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON:
    NtStatus = NtStatus(0xc01e034d);
pub const NT_STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE: NtStatus =
    NtStatus(0xc01e034e);
pub const NT_STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE: NtStatus =
    NtStatus(0xc01e034f);
pub const NT_STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS: NtStatus =
    NtStatus(0xc01e0350);
pub const NT_STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING: NtStatus =
    NtStatus(0xc01e0352);
pub const NT_STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED: NtStatus =
    NtStatus(0xc01e0353);
pub const NT_STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS: NtStatus =
    NtStatus(0xc01e0354);
pub const NT_STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT: NtStatus =
    NtStatus(0xc01e0355);
pub const NT_STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM: NtStatus =
    NtStatus(0xc01e0356);
pub const NT_STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN: NtStatus =
    NtStatus(0xc01e0357);
pub const NT_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT:
    NtStatus = NtStatus(0xc01e0358);
pub const NT_STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED: NtStatus =
    NtStatus(0xc01e0359);
pub const NT_STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION: NtStatus =
    NtStatus(0xc01e035a);
pub const NT_STATUS_GRAPHICS_INVALID_CLIENT_TYPE: NtStatus =
    NtStatus(0xc01e035b);
pub const NT_STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET: NtStatus =
    NtStatus(0xc01e035c);
pub const NT_STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED: NtStatus =
    NtStatus(0xc01e0400);
pub const NT_STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0401);
pub const NT_STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER: NtStatus =
    NtStatus(0xc01e0430);
pub const NT_STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED: NtStatus =
    NtStatus(0xc01e0431);
pub const NT_STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED: NtStatus =
    NtStatus(0xc01e0432);
pub const NT_STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY: NtStatus =
    NtStatus(0xc01e0433);
pub const NT_STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED: NtStatus =
    NtStatus(0xc01e0434);
pub const NT_STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON: NtStatus =
    NtStatus(0xc01e0435);
pub const NT_STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE: NtStatus =
    NtStatus(0xc01e0436);
pub const NT_STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER: NtStatus =
    NtStatus(0xc01e0438);
pub const NT_STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED: NtStatus =
    NtStatus(0xc01e043b);
pub const NT_STATUS_GRAPHICS_OPM_NOT_SUPPORTED: NtStatus = NtStatus(0xc01e0500);
pub const NT_STATUS_GRAPHICS_COPP_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0501);
pub const NT_STATUS_GRAPHICS_UAB_NOT_SUPPORTED: NtStatus = NtStatus(0xc01e0502);
pub const NT_STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS: NtStatus =
    NtStatus(0xc01e0503);
pub const NT_STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL: NtStatus =
    NtStatus(0xc01e0504);
pub const NT_STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST: NtStatus =
    NtStatus(0xc01e0505);
pub const NT_STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME:
    NtStatus = NtStatus(0xc01e0506);
pub const NT_STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP:
    NtStatus = NtStatus(0xc01e0507);
pub const NT_STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0508);
pub const NT_STATUS_GRAPHICS_OPM_INVALID_POINTER: NtStatus =
    NtStatus(0xc01e050a);
pub const NT_STATUS_GRAPHICS_OPM_INTERNAL_ERROR: NtStatus =
    NtStatus(0xc01e050b);
pub const NT_STATUS_GRAPHICS_OPM_INVALID_HANDLE: NtStatus =
    NtStatus(0xc01e050c);
pub const NT_STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE:
    NtStatus = NtStatus(0xc01e050d);
pub const NT_STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH: NtStatus =
    NtStatus(0xc01e050e);
pub const NT_STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED: NtStatus =
    NtStatus(0xc01e050f);
pub const NT_STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED: NtStatus =
    NtStatus(0xc01e0510);
pub const NT_STATUS_GRAPHICS_PVP_HFS_FAILED: NtStatus = NtStatus(0xc01e0511);
pub const NT_STATUS_GRAPHICS_OPM_INVALID_SRM: NtStatus = NtStatus(0xc01e0512);
pub const NT_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP: NtStatus =
    NtStatus(0xc01e0513);
pub const NT_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP: NtStatus =
    NtStatus(0xc01e0514);
pub const NT_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA: NtStatus =
    NtStatus(0xc01e0515);
pub const NT_STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET: NtStatus =
    NtStatus(0xc01e0516);
pub const NT_STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH: NtStatus =
    NtStatus(0xc01e0517);
pub const NT_STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE: NtStatus =
    NtStatus(0xc01e0518);
pub const NT_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS: NtStatus =
    NtStatus(0xc01e051a);
pub const NT_STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS: NtStatus =
    NtStatus(0xc01e051b);
pub const NT_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS: NtStatus =
    NtStatus(0xc01e051c);
pub const NT_STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST: NtStatus =
    NtStatus(0xc01e051d);
pub const NT_STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR: NtStatus =
    NtStatus(0xc01e051e);
pub const NT_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS: NtStatus =
    NtStatus(0xc01e051f);
pub const NT_STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0520);
pub const NT_STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST: NtStatus =
    NtStatus(0xc01e0521);
pub const NT_STATUS_GRAPHICS_I2C_NOT_SUPPORTED: NtStatus = NtStatus(0xc01e0580);
pub const NT_STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST: NtStatus =
    NtStatus(0xc01e0581);
pub const NT_STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA: NtStatus =
    NtStatus(0xc01e0582);
pub const NT_STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA: NtStatus =
    NtStatus(0xc01e0583);
pub const NT_STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e0584);
pub const NT_STATUS_GRAPHICS_DDCCI_INVALID_DATA: NtStatus =
    NtStatus(0xc01e0585);
pub const NT_STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE: NtStatus =
    NtStatus(0xc01e0586);
pub const NT_STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING: NtStatus =
    NtStatus(0xc01e0587);
pub const NT_STATUS_GRAPHICS_MCA_INTERNAL_ERROR: NtStatus =
    NtStatus(0xc01e0588);
pub const NT_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND: NtStatus =
    NtStatus(0xc01e0589);
pub const NT_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH: NtStatus =
    NtStatus(0xc01e058a);
pub const NT_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM: NtStatus =
    NtStatus(0xc01e058b);
pub const NT_STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE: NtStatus =
    NtStatus(0xc01e058c);
pub const NT_STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS: NtStatus =
    NtStatus(0xc01e058d);
pub const NT_STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED: NtStatus =
    NtStatus(0xc01e05e0);
pub const NT_STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME: NtStatus =
    NtStatus(0xc01e05e1);
pub const NT_STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP: NtStatus =
    NtStatus(0xc01e05e2);
pub const NT_STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc01e05e3);
pub const NT_STATUS_GRAPHICS_INVALID_POINTER: NtStatus = NtStatus(0xc01e05e4);
pub const NT_STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE:
    NtStatus = NtStatus(0xc01e05e5);
pub const NT_STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL: NtStatus =
    NtStatus(0xc01e05e6);
pub const NT_STATUS_GRAPHICS_INTERNAL_ERROR: NtStatus = NtStatus(0xc01e05e7);
pub const NT_STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS: NtStatus =
    NtStatus(0xc01e05e8);
pub const NT_STATUS_FVE_LOCKED_VOLUME: NtStatus = NtStatus(0xc0210000);
pub const NT_STATUS_FVE_NOT_ENCRYPTED: NtStatus = NtStatus(0xc0210001);
pub const NT_STATUS_FVE_BAD_INFORMATION: NtStatus = NtStatus(0xc0210002);
pub const NT_STATUS_FVE_TOO_SMALL: NtStatus = NtStatus(0xc0210003);
pub const NT_STATUS_FVE_FAILED_WRONG_FS: NtStatus = NtStatus(0xc0210004);
pub const NT_STATUS_FVE_FAILED_BAD_FS: NtStatus = NtStatus(0xc0210005);
pub const NT_STATUS_FVE_FS_NOT_EXTENDED: NtStatus = NtStatus(0xc0210006);
pub const NT_STATUS_FVE_FS_MOUNTED: NtStatus = NtStatus(0xc0210007);
pub const NT_STATUS_FVE_NO_LICENSE: NtStatus = NtStatus(0xc0210008);
pub const NT_STATUS_FVE_ACTION_NOT_ALLOWED: NtStatus = NtStatus(0xc0210009);
pub const NT_STATUS_FVE_BAD_DATA: NtStatus = NtStatus(0xc021000a);
pub const NT_STATUS_FVE_VOLUME_NOT_BOUND: NtStatus = NtStatus(0xc021000b);
pub const NT_STATUS_FVE_NOT_DATA_VOLUME: NtStatus = NtStatus(0xc021000c);
pub const NT_STATUS_FVE_CONV_READ_ERROR: NtStatus = NtStatus(0xc021000d);
pub const NT_STATUS_FVE_CONV_WRITE_ERROR: NtStatus = NtStatus(0xc021000e);
pub const NT_STATUS_FVE_OVERLAPPED_UPDATE: NtStatus = NtStatus(0xc021000f);
pub const NT_STATUS_FVE_FAILED_SECTOR_SIZE: NtStatus = NtStatus(0xc0210010);
pub const NT_STATUS_FVE_FAILED_AUTHENTICATION: NtStatus = NtStatus(0xc0210011);
pub const NT_STATUS_FVE_NOT_OS_VOLUME: NtStatus = NtStatus(0xc0210012);
pub const NT_STATUS_FVE_KEYFILE_NOT_FOUND: NtStatus = NtStatus(0xc0210013);
pub const NT_STATUS_FVE_KEYFILE_INVALID: NtStatus = NtStatus(0xc0210014);
pub const NT_STATUS_FVE_KEYFILE_NO_VMK: NtStatus = NtStatus(0xc0210015);
pub const NT_STATUS_FVE_TPM_DISABLED: NtStatus = NtStatus(0xc0210016);
pub const NT_STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO: NtStatus = NtStatus(0xc0210017);
pub const NT_STATUS_FVE_TPM_INVALID_PCR: NtStatus = NtStatus(0xc0210018);
pub const NT_STATUS_FVE_TPM_NO_VMK: NtStatus = NtStatus(0xc0210019);
pub const NT_STATUS_FVE_PIN_INVALID: NtStatus = NtStatus(0xc021001a);
pub const NT_STATUS_FVE_AUTH_INVALID_APPLICATION: NtStatus =
    NtStatus(0xc021001b);
pub const NT_STATUS_FVE_AUTH_INVALID_CONFIG: NtStatus = NtStatus(0xc021001c);
pub const NT_STATUS_FVE_DEBUGGER_ENABLED: NtStatus = NtStatus(0xc021001d);
pub const NT_STATUS_FVE_DRY_RUN_FAILED: NtStatus = NtStatus(0xc021001e);
pub const NT_STATUS_FVE_BAD_METADATA_POINTER: NtStatus = NtStatus(0xc021001f);
pub const NT_STATUS_FVE_OLD_METADATA_COPY: NtStatus = NtStatus(0xc0210020);
pub const NT_STATUS_FVE_REBOOT_REQUIRED: NtStatus = NtStatus(0xc0210021);
pub const NT_STATUS_FVE_RAW_ACCESS: NtStatus = NtStatus(0xc0210022);
pub const NT_STATUS_FVE_RAW_BLOCKED: NtStatus = NtStatus(0xc0210023);
pub const NT_STATUS_FVE_NO_FEATURE_LICENSE: NtStatus = NtStatus(0xc0210026);
pub const NT_STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED: NtStatus =
    NtStatus(0xc0210027);
pub const NT_STATUS_FVE_CONV_RECOVERY_FAILED: NtStatus = NtStatus(0xc0210028);
pub const NT_STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG: NtStatus =
    NtStatus(0xc0210029);
pub const NT_STATUS_FVE_VOLUME_TOO_SMALL: NtStatus = NtStatus(0xc0210030);
pub const NT_STATUS_FWP_CALLOUT_NOT_FOUND: NtStatus = NtStatus(0xc0220001);
pub const NT_STATUS_FWP_CONDITION_NOT_FOUND: NtStatus = NtStatus(0xc0220002);
pub const NT_STATUS_FWP_FILTER_NOT_FOUND: NtStatus = NtStatus(0xc0220003);
pub const NT_STATUS_FWP_LAYER_NOT_FOUND: NtStatus = NtStatus(0xc0220004);
pub const NT_STATUS_FWP_PROVIDER_NOT_FOUND: NtStatus = NtStatus(0xc0220005);
pub const NT_STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND: NtStatus =
    NtStatus(0xc0220006);
pub const NT_STATUS_FWP_SUBLAYER_NOT_FOUND: NtStatus = NtStatus(0xc0220007);
pub const NT_STATUS_FWP_NOT_FOUND: NtStatus = NtStatus(0xc0220008);
pub const NT_STATUS_FWP_ALREADY_EXISTS: NtStatus = NtStatus(0xc0220009);
pub const NT_STATUS_FWP_IN_USE: NtStatus = NtStatus(0xc022000a);
pub const NT_STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS: NtStatus =
    NtStatus(0xc022000b);
pub const NT_STATUS_FWP_WRONG_SESSION: NtStatus = NtStatus(0xc022000c);
pub const NT_STATUS_FWP_NO_TXN_IN_PROGRESS: NtStatus = NtStatus(0xc022000d);
pub const NT_STATUS_FWP_TXN_IN_PROGRESS: NtStatus = NtStatus(0xc022000e);
pub const NT_STATUS_FWP_TXN_ABORTED: NtStatus = NtStatus(0xc022000f);
pub const NT_STATUS_FWP_SESSION_ABORTED: NtStatus = NtStatus(0xc0220010);
pub const NT_STATUS_FWP_INCOMPATIBLE_TXN: NtStatus = NtStatus(0xc0220011);
pub const NT_STATUS_FWP_TIMEOUT: NtStatus = NtStatus(0xc0220012);
pub const NT_STATUS_FWP_NET_EVENTS_DISABLED: NtStatus = NtStatus(0xc0220013);
pub const NT_STATUS_FWP_INCOMPATIBLE_LAYER: NtStatus = NtStatus(0xc0220014);
pub const NT_STATUS_FWP_KM_CLIENTS_ONLY: NtStatus = NtStatus(0xc0220015);
pub const NT_STATUS_FWP_LIFETIME_MISMATCH: NtStatus = NtStatus(0xc0220016);
pub const NT_STATUS_FWP_BUILTIN_OBJECT: NtStatus = NtStatus(0xc0220017);
#[allow(dead_code)]
pub const NT_STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS: NtStatus =
    NtStatus(0xc0220018);
pub const NT_STATUS_FWP_TOO_MANY_CALLOUTS: NtStatus = NtStatus(0xc0220018);
pub const NT_STATUS_FWP_NOTIFICATION_DROPPED: NtStatus = NtStatus(0xc0220019);
pub const NT_STATUS_FWP_TRAFFIC_MISMATCH: NtStatus = NtStatus(0xc022001a);
pub const NT_STATUS_FWP_INCOMPATIBLE_SA_STATE: NtStatus = NtStatus(0xc022001b);
pub const NT_STATUS_FWP_NULL_POINTER: NtStatus = NtStatus(0xc022001c);
pub const NT_STATUS_FWP_INVALID_ENUMERATOR: NtStatus = NtStatus(0xc022001d);
pub const NT_STATUS_FWP_INVALID_FLAGS: NtStatus = NtStatus(0xc022001e);
pub const NT_STATUS_FWP_INVALID_NET_MASK: NtStatus = NtStatus(0xc022001f);
pub const NT_STATUS_FWP_INVALID_RANGE: NtStatus = NtStatus(0xc0220020);
pub const NT_STATUS_FWP_INVALID_INTERVAL: NtStatus = NtStatus(0xc0220021);
pub const NT_STATUS_FWP_ZERO_LENGTH_ARRAY: NtStatus = NtStatus(0xc0220022);
pub const NT_STATUS_FWP_NULL_DISPLAY_NAME: NtStatus = NtStatus(0xc0220023);
pub const NT_STATUS_FWP_INVALID_ACTION_TYPE: NtStatus = NtStatus(0xc0220024);
pub const NT_STATUS_FWP_INVALID_WEIGHT: NtStatus = NtStatus(0xc0220025);
pub const NT_STATUS_FWP_MATCH_TYPE_MISMATCH: NtStatus = NtStatus(0xc0220026);
pub const NT_STATUS_FWP_TYPE_MISMATCH: NtStatus = NtStatus(0xc0220027);
pub const NT_STATUS_FWP_OUT_OF_BOUNDS: NtStatus = NtStatus(0xc0220028);
pub const NT_STATUS_FWP_RESERVED: NtStatus = NtStatus(0xc0220029);
pub const NT_STATUS_FWP_DUPLICATE_CONDITION: NtStatus = NtStatus(0xc022002a);
pub const NT_STATUS_FWP_DUPLICATE_KEYMOD: NtStatus = NtStatus(0xc022002b);
pub const NT_STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER: NtStatus =
    NtStatus(0xc022002c);
pub const NT_STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER: NtStatus =
    NtStatus(0xc022002d);
pub const NT_STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER: NtStatus =
    NtStatus(0xc022002e);
pub const NT_STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT: NtStatus =
    NtStatus(0xc022002f);
pub const NT_STATUS_FWP_INCOMPATIBLE_AUTH_METHOD: NtStatus =
    NtStatus(0xc0220030);
pub const NT_STATUS_FWP_INCOMPATIBLE_DH_GROUP: NtStatus = NtStatus(0xc0220031);
pub const NT_STATUS_FWP_EM_NOT_SUPPORTED: NtStatus = NtStatus(0xc0220032);
pub const NT_STATUS_FWP_NEVER_MATCH: NtStatus = NtStatus(0xc0220033);
pub const NT_STATUS_FWP_PROVIDER_CONTEXT_MISMATCH: NtStatus =
    NtStatus(0xc0220034);
pub const NT_STATUS_FWP_INVALID_PARAMETER: NtStatus = NtStatus(0xc0220035);
pub const NT_STATUS_FWP_TOO_MANY_SUBLAYERS: NtStatus = NtStatus(0xc0220036);
pub const NT_STATUS_FWP_CALLOUT_NOTIFICATION_FAILED: NtStatus =
    NtStatus(0xc0220037);
pub const NT_STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG: NtStatus =
    NtStatus(0xc0220038);
pub const NT_STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG: NtStatus =
    NtStatus(0xc0220039);
pub const NT_STATUS_FWP_DUPLICATE_AUTH_METHOD: NtStatus = NtStatus(0xc022003c);
pub const NT_STATUS_FWP_TCPIP_NOT_READY: NtStatus = NtStatus(0xc0220100);
pub const NT_STATUS_FWP_INJECT_HANDLE_CLOSING: NtStatus = NtStatus(0xc0220101);
pub const NT_STATUS_FWP_INJECT_HANDLE_STALE: NtStatus = NtStatus(0xc0220102);
pub const NT_STATUS_FWP_CANNOT_PEND: NtStatus = NtStatus(0xc0220103);
pub const NT_STATUS_NDIS_CLOSING: NtStatus = NtStatus(0xc0230002);
pub const NT_STATUS_NDIS_BAD_VERSION: NtStatus = NtStatus(0xc0230004);
pub const NT_STATUS_NDIS_BAD_CHARACTERISTICS: NtStatus = NtStatus(0xc0230005);
pub const NT_STATUS_NDIS_ADAPTER_NOT_FOUND: NtStatus = NtStatus(0xc0230006);
pub const NT_STATUS_NDIS_OPEN_FAILED: NtStatus = NtStatus(0xc0230007);
pub const NT_STATUS_NDIS_DEVICE_FAILED: NtStatus = NtStatus(0xc0230008);
pub const NT_STATUS_NDIS_MULTICAST_FULL: NtStatus = NtStatus(0xc0230009);
pub const NT_STATUS_NDIS_MULTICAST_EXISTS: NtStatus = NtStatus(0xc023000a);
pub const NT_STATUS_NDIS_MULTICAST_NOT_FOUND: NtStatus = NtStatus(0xc023000b);
pub const NT_STATUS_NDIS_REQUEST_ABORTED: NtStatus = NtStatus(0xc023000c);
pub const NT_STATUS_NDIS_RESET_IN_PROGRESS: NtStatus = NtStatus(0xc023000d);
pub const NT_STATUS_NDIS_INVALID_PACKET: NtStatus = NtStatus(0xc023000f);
pub const NT_STATUS_NDIS_INVALID_DEVICE_REQUEST: NtStatus =
    NtStatus(0xc0230010);
pub const NT_STATUS_NDIS_ADAPTER_NOT_READY: NtStatus = NtStatus(0xc0230011);
pub const NT_STATUS_NDIS_INVALID_LENGTH: NtStatus = NtStatus(0xc0230014);
pub const NT_STATUS_NDIS_INVALID_DATA: NtStatus = NtStatus(0xc0230015);
pub const NT_STATUS_NDIS_BUFFER_TOO_SHORT: NtStatus = NtStatus(0xc0230016);
pub const NT_STATUS_NDIS_INVALID_OID: NtStatus = NtStatus(0xc0230017);
pub const NT_STATUS_NDIS_ADAPTER_REMOVED: NtStatus = NtStatus(0xc0230018);
pub const NT_STATUS_NDIS_UNSUPPORTED_MEDIA: NtStatus = NtStatus(0xc0230019);
pub const NT_STATUS_NDIS_GROUP_ADDRESS_IN_USE: NtStatus = NtStatus(0xc023001a);
pub const NT_STATUS_NDIS_FILE_NOT_FOUND: NtStatus = NtStatus(0xc023001b);
pub const NT_STATUS_NDIS_ERROR_READING_FILE: NtStatus = NtStatus(0xc023001c);
pub const NT_STATUS_NDIS_ALREADY_MAPPED: NtStatus = NtStatus(0xc023001d);
pub const NT_STATUS_NDIS_RESOURCE_CONFLICT: NtStatus = NtStatus(0xc023001e);
pub const NT_STATUS_NDIS_MEDIA_DISCONNECTED: NtStatus = NtStatus(0xc023001f);
pub const NT_STATUS_NDIS_INVALID_ADDRESS: NtStatus = NtStatus(0xc0230022);
pub const NT_STATUS_NDIS_PAUSED: NtStatus = NtStatus(0xc023002a);
pub const NT_STATUS_NDIS_INTERFACE_NOT_FOUND: NtStatus = NtStatus(0xc023002b);
pub const NT_STATUS_NDIS_UNSUPPORTED_REVISION: NtStatus = NtStatus(0xc023002c);
pub const NT_STATUS_NDIS_INVALID_PORT: NtStatus = NtStatus(0xc023002d);
pub const NT_STATUS_NDIS_INVALID_PORT_STATE: NtStatus = NtStatus(0xc023002e);
pub const NT_STATUS_NDIS_LOW_POWER_STATE: NtStatus = NtStatus(0xc023002f);
pub const NT_STATUS_NDIS_NOT_SUPPORTED: NtStatus = NtStatus(0xc02300bb);
pub const NT_STATUS_NDIS_OFFLOAD_POLICY: NtStatus = NtStatus(0xc023100f);
pub const NT_STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED: NtStatus =
    NtStatus(0xc0231012);
pub const NT_STATUS_NDIS_OFFLOAD_PATH_REJECTED: NtStatus = NtStatus(0xc0231013);
pub const NT_STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED: NtStatus =
    NtStatus(0xc0232000);
pub const NT_STATUS_NDIS_DOT11_MEDIA_IN_USE: NtStatus = NtStatus(0xc0232001);
pub const NT_STATUS_NDIS_DOT11_POWER_STATE_INVALID: NtStatus =
    NtStatus(0xc0232002);
pub const NT_STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL: NtStatus =
    NtStatus(0xc0232003);
pub const NT_STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL: NtStatus =
    NtStatus(0xc0232004);
pub const NT_STATUS_IPSEC_BAD_SPI: NtStatus = NtStatus(0xc0360001);
pub const NT_STATUS_IPSEC_SA_LIFETIME_EXPIRED: NtStatus = NtStatus(0xc0360002);
pub const NT_STATUS_IPSEC_WRONG_SA: NtStatus = NtStatus(0xc0360003);
pub const NT_STATUS_IPSEC_REPLAY_CHECK_FAILED: NtStatus = NtStatus(0xc0360004);
pub const NT_STATUS_IPSEC_INVALID_PACKET: NtStatus = NtStatus(0xc0360005);
pub const NT_STATUS_IPSEC_INTEGRITY_CHECK_FAILED: NtStatus =
    NtStatus(0xc0360006);
pub const NT_STATUS_IPSEC_CLEAR_TEXT_DROP: NtStatus = NtStatus(0xc0360007);
pub const NT_STATUS_IPSEC_AUTH_FIREWALL_DROP: NtStatus = NtStatus(0xc0360008);
pub const NT_STATUS_IPSEC_THROTTLE_DROP: NtStatus = NtStatus(0xc0360009);
pub const NT_STATUS_IPSEC_DOSP_BLOCK: NtStatus = NtStatus(0xc0368000);
pub const NT_STATUS_IPSEC_DOSP_RECEIVED_MULTICAST: NtStatus =
    NtStatus(0xc0368001);
pub const NT_STATUS_IPSEC_DOSP_INVALID_PACKET: NtStatus = NtStatus(0xc0368002);
pub const NT_STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED: NtStatus =
    NtStatus(0xc0368003);
pub const NT_STATUS_IPSEC_DOSP_MAX_ENTRIES: NtStatus = NtStatus(0xc0368004);
pub const NT_STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED: NtStatus =
    NtStatus(0xc0368005);
pub const NT_STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES: NtStatus =
    NtStatus(0xc0368006);
pub const NT_STATUS_VOLMGR_MIRROR_NOT_SUPPORTED: NtStatus =
    NtStatus(0xc038005b);
pub const NT_STATUS_VOLMGR_RAID5_NOT_SUPPORTED: NtStatus = NtStatus(0xc038005c);
pub const NT_STATUS_VIRTDISK_PROVIDER_NOT_FOUND: NtStatus =
    NtStatus(0xc03a0014);
pub const NT_STATUS_VIRTDISK_NOT_VIRTUAL_DISK: NtStatus = NtStatus(0xc03a0015);
pub const NT_STATUS_VHD_PARENT_VHD_ACCESS_DENIED: NtStatus =
    NtStatus(0xc03a0016);
pub const NT_STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH: NtStatus =
    NtStatus(0xc03a0017);
pub const NT_STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED: NtStatus =
    NtStatus(0xc03a0018);
pub const NT_STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT: NtStatus =
    NtStatus(0xc03a0019);

impl NtStatus {
    pub fn val(&self) -> u32 {
        self.0
    }

    pub const fn is_ok(&self) -> bool {
        self.0 == NT_STATUS_OK.0
    }

    fn description(&self) -> &str {
        match *self {
            NT_STATUS_SUCCESS => "The operation completed successfully.",
            NT_STATUS_WAIT_1 => "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
            NT_STATUS_WAIT_2 => "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
            NT_STATUS_WAIT_3 => "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
            NT_STATUS_WAIT_63 => "The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state.",
            NT_STATUS_ABANDONED => "The caller attempted to wait for a mutex that has been abandoned.",
            NT_STATUS_ABANDONED_WAIT_63 => "The caller attempted to wait for a mutex that has been abandoned.",
            NT_STATUS_USER_APC => "A user-mode APC was delivered before the given Interval expired.",
            NT_STATUS_ALERTED => "The delay completed because the thread was alerted.",
            NT_STATUS_TIMEOUT => "The given Timeout interval expired.",
            NT_STATUS_PENDING => "The operation that was requested is pending completion.",
            NT_STATUS_REPARSE => "A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.",
            NT_STATUS_MORE_ENTRIES => "Returned by enumeration APIs to indicate more information is available to successive calls.",
            NT_STATUS_NOT_ALL_ASSIGNED => "Indicates not all privileges or groups that are referenced are assigned to the caller. This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned.",
            NT_STATUS_SOME_NOT_MAPPED => "Some of the information to be translated has not been translated.",
            NT_STATUS_OPLOCK_BREAK_IN_PROGRESS => "An open/create operation completed while an opportunistic lock (oplock) break is underway.",
            NT_STATUS_VOLUME_MOUNTED => "A new volume has been mounted by a file system.",
            NT_STATUS_RXACT_COMMITTED => "This success level status indicates that the transaction state already exists for the registry subtree but that a transaction commit was previously aborted. The commit has now been completed.",
            NT_STATUS_NOTIFY_CLEANUP => "Indicates that a notify change request has been completed due to closing the handle that made the notify change request.",
            NT_STATUS_NOTIFY_ENUM_DIR => "Indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.",
            NT_STATUS_NO_QUOTAS_FOR_ACCOUNT => "{No Quotas} No system quota limits are specifically set for this account.",
            NT_STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED => "{Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer WAS able to connect on a secondary transport.",
            NT_STATUS_PAGE_FAULT_TRANSITION => "The page fault was a transition fault.",
            NT_STATUS_PAGE_FAULT_DEMAND_ZERO => "The page fault was a demand zero fault.",
            NT_STATUS_PAGE_FAULT_COPY_ON_WRITE => "The page fault was a demand zero fault.",
            NT_STATUS_PAGE_FAULT_GUARD_PAGE => "The page fault was a demand zero fault.",
            NT_STATUS_PAGE_FAULT_PAGING_FILE => "The page fault was satisfied by reading from a secondary storage device.",
            NT_STATUS_CACHE_PAGE_LOCKED => "The cached page was locked during operation.",
            NT_STATUS_CRASH_DUMP => "The crash dump exists in a paging file.",
            NT_STATUS_BUFFER_ALL_ZEROS => "The specified buffer contains all zeros.",
            NT_STATUS_REPARSE_OBJECT => "A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.",
            NT_STATUS_RESOURCE_REQUIREMENTS_CHANGED => "The device has succeeded a query-stop and its resource requirements have changed.",
            NT_STATUS_TRANSLATION_COMPLETE => "The translator has translated these resources into the global space and no additional translations should be performed.",
            NT_STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY => "The directory service evaluated group memberships locally, because it was unable to contact a global catalog server.",
            NT_STATUS_NOTHING_TO_TERMINATE => "A process being terminated has no threads to terminate.",
            NT_STATUS_PROCESS_NOT_IN_JOB => "The specified process is not part of a job.",
            NT_STATUS_PROCESS_IN_JOB => "The specified process is part of a job.",
            NT_STATUS_VOLSNAP_HIBERNATE_READY => "{Volume Shadow Copy Service} The system is now ready for hibernation.",
            NT_STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY => "A file system or file system filter driver has successfully completed an FsFilter operation.",
            NT_STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED => "The specified interrupt vector was already connected.",
            NT_STATUS_INTERRUPT_STILL_CONNECTED => "The specified interrupt vector is still connected.",
            NT_STATUS_PROCESS_CLONED => "The current process is a cloned process.",
            NT_STATUS_FILE_LOCKED_WITH_ONLY_READERS => "The file was locked and all users of the file can only read.",
            NT_STATUS_FILE_LOCKED_WITH_WRITERS => "The file was locked and at least one user of the file can write.",
            NT_STATUS_RESOURCEMANAGER_READ_ONLY => "The specified ResourceManager made no changes or updates to the resource under this transaction.",
            NT_STATUS_WAIT_FOR_OPLOCK => "An operation is blocked and waiting for an oplock.",
            NT_STATUS_DBG_EXCEPTION_HANDLED => "Debugger handled the exception.",
            NT_STATUS_DBG_CONTINUE => "The debugger continued.",
            NT_STATUS_FLT_IO_COMPLETE => "The IO was completed by a filter.",
            NT_STATUS_FILE_NOT_AVAILABLE => "The file is temporarily unavailable.",
            NT_STATUS_SHARE_UNAVAILABLE => "The share is temporarily unavailable.",
            NT_STATUS_CALLBACK_RETURNED_THREAD_AFFINITY => "A threadpool worker thread entered a callback at thread affinity %p and exited at affinity %p. This is unexpected, indicating that the callback missed restoring the priority.",
            NT_STATUS_OBJECT_NAME_EXISTS => "{Object Exists} An attempt was made to create an object but the object name already exists.",
            NT_STATUS_THREAD_WAS_SUSPENDED => "{Thread Suspended} A thread termination occurred while the thread was suspended. The thread resumed, and termination proceeded.",
            NT_STATUS_WORKING_SET_LIMIT_RANGE => "{Working Set Range Error} An attempt was made to set the working set minimum or maximum to values that are outside the allowable range.",
            NT_STATUS_IMAGE_NOT_AT_BASE => "{Image Relocated} An image file could not be mapped at the address that is specified in the image file. Local fixes must be performed on this image.",
            NT_STATUS_RXACT_STATE_CREATED => "This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.",
            NT_STATUS_SEGMENT_NOTIFICATION => "{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.",
            NT_STATUS_LOCAL_USER_SESSION_KEY => "{Local Session Key} A user session key was requested for a local remote procedure call (RPC) connection. The session key that is returned is a constant value and not unique to this connection.",
            NT_STATUS_BAD_CURRENT_DIRECTORY => "{Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set the current directory to %hs, or select CANCEL to exit.",
            NT_STATUS_SERIAL_MORE_WRITES => "{Serial IOCTL Complete} A serial I/O operation was completed by another write to a serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)",
            NT_STATUS_REGISTRY_RECOVERED => "{Registry Recovery} One of the files that contains the system registry data had to be recovered by using a log or alternate copy. The recovery was successful.",
            NT_STATUS_FT_READ_RECOVERY_FROM_BACKUP => "{Redundant Read} To satisfy a read request, the Windows NT operating system fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.",
            NT_STATUS_FT_WRITE_RECOVERY => "{Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.",
            NT_STATUS_SERIAL_COUNTER_TIMEOUT => "{Serial IOCTL Timeout} A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)",
            NT_STATUS_NULL_LM_PASSWORD => "{Password Too Complex} The Windows password is too complex to be converted to a LAN Manager password. The LAN Manager password that returned is a NULL string.",
            NT_STATUS_IMAGE_MACHINE_TYPE_MISMATCH => "{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.",
            NT_STATUS_RECEIVE_PARTIAL => "{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.",
            NT_STATUS_RECEIVE_EXPEDITED => "{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.",
            NT_STATUS_RECEIVE_PARTIAL_EXPEDITED => "{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.",
            NT_STATUS_EVENT_DONE => "{TDI Event Done} The TDI indication has completed successfully.",
            NT_STATUS_EVENT_PENDING => "{TDI Event Pending} The TDI indication has entered the pending state.",
            NT_STATUS_CHECKING_FILE_SYSTEM => "Checking file system on %wZ.",
            NT_STATUS_FATAL_APP_EXIT => "{Fatal Application Exit} %hs",
            NT_STATUS_PREDEFINED_HANDLE => "The specified registry key is referenced by a predefined handle.",
            NT_STATUS_WAS_UNLOCKED => "{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.",
            NT_STATUS_SERVICE_NOTIFICATION => "%hs",
            NT_STATUS_WAS_LOCKED => "{Page Locked} One of the pages to lock was already locked.",
            NT_STATUS_LOG_HARD_ERROR => "Application popup: %1 : %2",
            NT_STATUS_ALREADY_WIN32 => "A Win32 process already exists.",
            NT_STATUS_WX86_UNSIMULATE => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_CONTINUE => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_SINGLE_STEP => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_BREAKPOINT => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_EXCEPTION_CONTINUE => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_EXCEPTION_LASTCHANCE => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_EXCEPTION_CHAIN => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE => "{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine.",
            NT_STATUS_NO_YIELD_PERFORMED => "A yield execution was performed and no thread was available to run.",
            NT_STATUS_TIMER_RESUME_IGNORED => "The resume flag to a timer API was ignored.",
            NT_STATUS_ARBITRATION_UNHANDLED => "The arbiter has deferred arbitration of these resources to its parent.",
            NT_STATUS_CARDBUS_NOT_SUPPORTED => "The device has detected a CardBus card in its slot.",
            NT_STATUS_WX86_CREATEWX86TIB => "An exception status code that is used by the Win32 x86 emulation subsystem.",
            NT_STATUS_MP_PROCESSOR_MISMATCH => "The CPUs in this multiprocessor system are not all the same revision level. To use all processors, the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.",
            NT_STATUS_HIBERNATED => "The system was put into hibernation.",
            NT_STATUS_RESUME_HIBERNATION => "The system was resumed from hibernation.",
            NT_STATUS_FIRMWARE_UPDATED => "Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3].",
            NT_STATUS_DRIVERS_LEAKING_LOCKED_PAGES => "A device driver is leaking locked I/O pages and is causing system degradation. The system has automatically enabled the tracking code to try and catch the culprit.",
            NT_STATUS_MESSAGE_RETRIEVED => "The ALPC message being canceled has already been retrieved from the queue on the other side.",
            NT_STATUS_SYSTEM_POWERSTATE_TRANSITION => "The system power state is transitioning from %2 to %3.",
            NT_STATUS_ALPC_CHECK_COMPLETION_LIST => "The receive operation was successful. Check the ALPC completion list for the received message.",
            NT_STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION => "The system power state is transitioning from %2 to %3 but could enter %4.",
            NT_STATUS_ACCESS_AUDIT_BY_POLICY => "Access to %1 is monitored by policy rule %2.",
            NT_STATUS_ABANDON_HIBERFILE => "A valid hibernation file has been invalidated and should be abandoned.",
            NT_STATUS_BIZRULES_NOT_ENABLED => "Business rule scripts are disabled for the calling application.",
            NT_STATUS_WAKE_SYSTEM => "The system has awoken.",
            NT_STATUS_DS_SHUTTING_DOWN => "The directory service is shutting down.",
            NT_STATUS_DBG_REPLY_LATER => "Debugger will reply later.",
            NT_STATUS_DBG_UNABLE_TO_PROVIDE_HANDLE => "Debugger cannot provide a handle.",
            NT_STATUS_DBG_TERMINATE_THREAD => "Debugger terminated the thread.",
            NT_STATUS_DBG_TERMINATE_PROCESS => "Debugger terminated the process.",
            NT_STATUS_DBG_CONTROL_C => "Debugger obtained control of C.",
            NT_STATUS_DBG_PRINTEXCEPTION_C => "Debugger printed an exception on control C.",
            NT_STATUS_DBG_RIPEXCEPTION => "Debugger received a RIP exception.",
            NT_STATUS_DBG_CONTROL_BREAK => "Debugger received a control break.",
            NT_STATUS_DBG_COMMAND_EXCEPTION => "Debugger command communication exception.",
            NT_STATUS_RPC_UUID_LOCAL_ONLY => "A UUID that is valid only on this computer has been allocated.",
            NT_STATUS_RPC_SEND_INCOMPLETE => "Some data remains to be sent in the request buffer.",
            NT_STATUS_CTX_CDM_CONNECT => "The Client Drive Mapping Service has connected on Terminal Connection.",
            NT_STATUS_CTX_CDM_DISCONNECT => "The Client Drive Mapping Service has disconnected on Terminal Connection.",
            NT_STATUS_SXS_RELEASE_ACTIVATION_CONTEXT => "A kernel mode component is releasing a reference on an activation context.",
            NT_STATUS_RECOVERY_NOT_NEEDED => "The transactional resource manager is already consistent. Recovery is not needed.",
            NT_STATUS_RM_ALREADY_STARTED => "The transactional resource manager has already been started.",
            NT_STATUS_LOG_NO_RESTART => "The log service encountered a log stream with no restart area.",
            NT_STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST => "{Display Driver Recovered From Failure} The %hs display driver has detected a failure and recovered from it. Some graphical operations might have failed. The next time you restart the machine, a dialog box appears, giving you an opportunity to upload data about this failure to Microsoft.",
            NT_STATUS_GRAPHICS_PARTIAL_DATA_POPULATED => "The specified buffer is not big enough to contain the entire requested dataset. Partial data is populated up to the size of the buffer. The caller needs to provide a buffer of the size as specified in the partially populated buffer's content (interface specific).",
            NT_STATUS_GRAPHICS_DRIVER_MISMATCH => "The kernel driver detected a version mismatch between it and the user mode driver.",
            NT_STATUS_GRAPHICS_MODE_NOT_PINNED => "No mode is pinned on the specified VidPN source/target.",
            NT_STATUS_GRAPHICS_NO_PREFERRED_MODE => "The specified mode set does not specify a preference for one of its modes.",
            NT_STATUS_GRAPHICS_DATASET_IS_EMPTY => "The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) is empty.",
            NT_STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET => "The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) does not contain any more elements.",
            NT_STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED => "The specified content transformation is not pinned on the specified VidPN present path.",
            NT_STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS => "The child device presence was not reliably detected.",
            NT_STATUS_GRAPHICS_LEADLINK_START_DEFERRED => "Starting the lead adapter in a linked configuration has been temporarily deferred.",
            NT_STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY => "The display adapter is being polled for children too frequently at the same polling level.",
            NT_STATUS_GRAPHICS_START_DEFERRED => "Starting the adapter has been temporarily deferred.",
            NT_STATUS_NDIS_INDICATION_REQUIRED => "The request will be completed later by an NDIS status indication.",
            NT_STATUS_GUARD_PAGE_VIOLATION => "{EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed.",
            NT_STATUS_DATATYPE_MISALIGNMENT => "{EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction.",
            NT_STATUS_BREAKPOINT => "{EXCEPTION} Breakpoint A breakpoint has been reached.",
            NT_STATUS_SINGLE_STEP => "{EXCEPTION} Single Step A single step or trace operation has just been completed.",
            NT_STATUS_BUFFER_OVERFLOW => "{Buffer Overflow} The data was too large to fit into the specified buffer.",
            NT_STATUS_NO_MORE_FILES => "{No More Files} No more files were found which match the file specification.",
            NT_STATUS_WAKE_SYSTEM_DEBUGGER => "{Kernel Debugger Awakened} The system debugger was awakened by an interrupt.",
            NT_STATUS_HANDLES_CLOSED => "{Handles Closed} Handles to objects have been automatically closed because of the requested operation.",
            NT_STATUS_NO_INHERITANCE => "{Non-Inheritable ACL} An access control list (ACL) contains no components that can be inherited.",
            NT_STATUS_GUID_SUBSTITUTION_MADE => "{GUID Substitution} During the translation of a globally unique identifier (GUID) to a Windows security ID (SID), no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this might provide a more restrictive access than intended.",
            NT_STATUS_PARTIAL_COPY => "Because of protection conflicts, not all the requested bytes could be copied.",
            NT_STATUS_DEVICE_PAPER_EMPTY => "{Out of Paper} The printer is out of paper.",
            NT_STATUS_DEVICE_POWERED_OFF => "{Device Power Is Off} The printer power has been turned off.",
            NT_STATUS_DEVICE_OFF_LINE => "{Device Offline} The printer has been taken offline.",
            NT_STATUS_DEVICE_BUSY => "{Device Busy} The device is currently busy.",
            NT_STATUS_NO_MORE_EAS => "{No More EAs} No more extended attributes (EAs) were found for the file.",
            NT_STATUS_INVALID_EA_NAME => "{Illegal EA} The specified extended attribute (EA) name contains at least one illegal character.",
            NT_STATUS_EA_LIST_INCONSISTENT => "{Inconsistent EA List} The extended attribute (EA) list is inconsistent.",
            NT_STATUS_INVALID_EA_FLAG => "{Invalid EA Flag} An invalid extended attribute (EA) flag was set.",
            NT_STATUS_VERIFY_REQUIRED => "{Verifying Disk} The media has changed and a verify operation is in progress; therefore, no reads or writes can be performed to the device, except those that are used in the verify operation.",
            NT_STATUS_EXTRANEOUS_INFORMATION => "{Too Much Information} The specified access control list (ACL) contained more information than was expected.",
            NT_STATUS_RXACT_COMMIT_NECESSARY => "This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed but has not been rolled back either; therefore, it can still be committed, if needed.",
            NT_STATUS_NO_MORE_ENTRIES => "{No More Entries} No more entries are available from an enumeration operation.",
            NT_STATUS_FILEMARK_DETECTED => "{Filemark Found} A filemark was detected.",
            NT_STATUS_MEDIA_CHANGED => "{Media Changed} The media has changed.",
            NT_STATUS_BUS_RESET => "{I/O Bus Reset} An I/O bus reset was detected.",
            NT_STATUS_END_OF_MEDIA => "{End of Media} The end of the media was encountered.",
            NT_STATUS_BEGINNING_OF_MEDIA => "The beginning of a tape or partition has been detected.",
            NT_STATUS_MEDIA_CHECK => "{Media Changed} The media might have changed.",
            NT_STATUS_SETMARK_DETECTED => "A tape access reached a set mark.",
            NT_STATUS_NO_DATA_DETECTED => "During a tape access, the end of the data written is reached.",
            NT_STATUS_REDIRECTOR_HAS_OPEN_HANDLES => "The redirector is in use and cannot be unloaded.",
            NT_STATUS_SERVER_HAS_OPEN_HANDLES => "The server is in use and cannot be unloaded.",
            NT_STATUS_ALREADY_DISCONNECTED => "The specified connection has already been disconnected.",
            NT_STATUS_LONGJUMP => "A long jump has been executed.",
            NT_STATUS_CLEANER_CARTRIDGE_INSTALLED => "A cleaner cartridge is present in the tape library.",
            NT_STATUS_PLUGPLAY_QUERY_VETOED => "The Plug and Play query operation was not successful.",
            NT_STATUS_UNWIND_CONSOLIDATE => "A frame consolidation has been executed.",
            NT_STATUS_REGISTRY_HIVE_RECOVERED => "{Registry Hive Recovered} The registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.",
            NT_STATUS_DLL_MIGHT_BE_INSECURE => "The application is attempting to run executable code from the module %hs. This might be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?",
            NT_STATUS_DLL_MIGHT_BE_INCOMPATIBLE => "The application is loading executable code from the module %hs. This is secure but might be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?",
            NT_STATUS_STOPPED_ON_SYMLINK => "The create operation stopped after reaching a symbolic link.",
            NT_STATUS_DEVICE_REQUIRES_CLEANING => "The device has indicated that cleaning is necessary.",
            NT_STATUS_DEVICE_DOOR_OPEN => "The device has indicated that its door is open. Further operations require it closed and secured.",
            NT_STATUS_DATA_LOST_REPAIR => "Windows discovered a corruption in the file %hs. This file has now been repaired. Check if any data in the file was lost because of the corruption.",
            NT_STATUS_DBG_EXCEPTION_NOT_HANDLED => "Debugger did not handle the exception.",
            NT_STATUS_CLUSTER_NODE_ALREADY_UP => "The cluster node is already up.",
            NT_STATUS_CLUSTER_NODE_ALREADY_DOWN => "The cluster node is already down.",
            NT_STATUS_CLUSTER_NETWORK_ALREADY_ONLINE => "The cluster network is already online.",
            NT_STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE => "The cluster network is already offline.",
            NT_STATUS_CLUSTER_NODE_ALREADY_MEMBER => "The cluster node is already a member of the cluster.",
            NT_STATUS_COULD_NOT_RESIZE_LOG => "The log could not be set to the requested size.",
            NT_STATUS_NO_TXF_METADATA => "There is no transaction metadata on the file.",
            NT_STATUS_CANT_RECOVER_WITH_HANDLE_OPEN => "The file cannot be recovered because there is a handle still open on it.",
            NT_STATUS_TXF_METADATA_ALREADY_PRESENT => "Transaction metadata is already present on this file and cannot be superseded.",
            NT_STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET => "A transaction scope could not be entered because the scope handler has not been initialized.",
            NT_STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED => "{Display Driver Stopped Responding and recovered} The %hs display driver has stopped working normally. The recovery had been performed.",
            NT_STATUS_FLT_BUFFER_TOO_SMALL => "{Buffer too small} The buffer is too small to contain the entry. No information has been written to the buffer.",
            NT_STATUS_FVE_PARTIAL_METADATA => "Volume metadata read or write is incomplete.",
            NT_STATUS_FVE_TRANSIENT_STATE => "BitLocker encryption keys were ignored because the volume was in a transient state.",
            NT_STATUS_UNSUCCESSFUL => "{Operation Failed} The requested operation was unsuccessful.",
            NT_STATUS_NOT_IMPLEMENTED => "{Not Implemented} The requested operation is not implemented.",
            NT_STATUS_INVALID_INFO_CLASS => "{Invalid Parameter} The specified information class is not a valid information class for the specified object.",
            NT_STATUS_INFO_LENGTH_MISMATCH => "The specified information record length does not match the length that is required for the specified information class.",
            NT_STATUS_ACCESS_VIOLATION => "The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s.",
            NT_STATUS_IN_PAGE_ERROR => "The instruction at 0x%08lx referenced memory at 0x%08lx. The required data was not placed into memory because of an I/O error status of 0x%08lx.",
            NT_STATUS_PAGEFILE_QUOTA => "The page file quota for the process has been exhausted.",
            NT_STATUS_INVALID_HANDLE => "An invalid HANDLE was specified.",
            NT_STATUS_BAD_INITIAL_STACK => "An invalid initial stack was specified in a call to NtCreateThread.",
            NT_STATUS_BAD_INITIAL_PC => "An invalid initial start address was specified in a call to NtCreateThread.",
            NT_STATUS_INVALID_CID => "An invalid client ID was specified.",
            NT_STATUS_TIMER_NOT_CANCELED => "An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine.",
            NT_STATUS_INVALID_PARAMETER => "An invalid parameter was passed to a service or function.",
            NT_STATUS_NO_SUCH_DEVICE => "A device that does not exist was specified.",
            NT_STATUS_NO_SUCH_FILE => "{File Not Found} The file %hs does not exist.",
            NT_STATUS_INVALID_DEVICE_REQUEST => "The specified request is not a valid operation for the target device.",
            NT_STATUS_END_OF_FILE => "The end-of-file marker has been reached. There is no valid data in the file beyond this marker.",
            NT_STATUS_WRONG_VOLUME => "{Wrong Volume} The wrong volume is in the drive. Insert volume %hs into drive %hs.",
            NT_STATUS_NO_MEDIA_IN_DEVICE => "{No Disk} There is no disk in the drive. Insert a disk into drive %hs.",
            NT_STATUS_UNRECOGNIZED_MEDIA => "{Unknown Disk Format} The disk in drive %hs is not formatted properly. Check the disk, and reformat it, if needed.",
            NT_STATUS_NONEXISTENT_SECTOR => "{Sector Not Found} The specified sector does not exist.",
            NT_STATUS_MORE_PROCESSING_REQUIRED => "{Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.",
            NT_STATUS_NO_MEMORY => "{Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation.",
            NT_STATUS_CONFLICTING_ADDRESSES => "{Conflicting Address Range} The specified address range conflicts with the address space.",
            NT_STATUS_NOT_MAPPED_VIEW => "The address range to unmap is not a mapped view.",
            NT_STATUS_UNABLE_TO_FREE_VM => "The virtual memory cannot be freed.",
            NT_STATUS_UNABLE_TO_DELETE_SECTION => "The specified section cannot be deleted.",
            NT_STATUS_INVALID_SYSTEM_SERVICE => "An invalid system service was specified in a system service call.",
            NT_STATUS_ILLEGAL_INSTRUCTION => "{EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction.",
            NT_STATUS_INVALID_LOCK_SEQUENCE => "{Invalid Lock Sequence} An attempt was made to execute an invalid lock sequence.",
            NT_STATUS_INVALID_VIEW_SIZE => "{Invalid Mapping} An attempt was made to create a view for a section that is bigger than the section.",
            NT_STATUS_INVALID_FILE_FOR_SECTION => "{Bad File} The attributes of the specified mapping file for a section of memory cannot be read.",
            NT_STATUS_ALREADY_COMMITTED => "{Already Committed} The specified address range is already committed.",
            NT_STATUS_ACCESS_DENIED => "{Access Denied} A process has requested access to an object but has not been granted those access rights.",
            NT_STATUS_BUFFER_TOO_SMALL => "{Buffer Too Small} The buffer is too small to contain the entry. No information has been written to the buffer.",
            NT_STATUS_OBJECT_TYPE_MISMATCH => "{Wrong Type} There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.",
            NT_STATUS_NONCONTINUABLE_EXCEPTION => "{EXCEPTION} Cannot Continue Windows cannot continue from this exception.",
            NT_STATUS_INVALID_DISPOSITION => "An invalid exception disposition was returned by an exception handler.",
            NT_STATUS_UNWIND => "Unwind exception code.",
            NT_STATUS_BAD_STACK => "An invalid or unaligned stack was encountered during an unwind operation.",
            NT_STATUS_INVALID_UNWIND_TARGET => "An invalid unwind target was encountered during an unwind operation.",
            NT_STATUS_NOT_LOCKED => "An attempt was made to unlock a page of memory that was not locked.",
            NT_STATUS_PARITY_ERROR => "A device parity error on an I/O operation.",
            NT_STATUS_UNABLE_TO_DECOMMIT_VM => "An attempt was made to decommit uncommitted virtual memory.",
            NT_STATUS_NOT_COMMITTED => "An attempt was made to change the attributes on memory that has not been committed.",
            NT_STATUS_INVALID_PORT_ATTRIBUTES => "Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.",
            NT_STATUS_PORT_MESSAGE_TOO_LONG => "The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port.",
            NT_STATUS_INVALID_PARAMETER_MIX => "An invalid combination of parameters was specified.",
            NT_STATUS_INVALID_QUOTA_LOWER => "An attempt was made to lower a quota limit below the current usage.",
            NT_STATUS_DISK_CORRUPT_ERROR => "{Corrupt Disk} The file system structure on the disk is corrupt and unusable. Run the Chkdsk utility on the volume %hs.",
            NT_STATUS_OBJECT_NAME_INVALID => "The object name is invalid.",
            NT_STATUS_OBJECT_NAME_NOT_FOUND => "The object name is not found.",
            NT_STATUS_OBJECT_NAME_COLLISION => "The object name already exists.",
            NT_STATUS_PORT_DISCONNECTED => "An attempt was made to send a message to a disconnected communication port.",
            NT_STATUS_DEVICE_ALREADY_ATTACHED => "An attempt was made to attach to a device that was already attached to another device.",
            NT_STATUS_OBJECT_PATH_INVALID => "The object path component was not a directory object.",
            NT_STATUS_OBJECT_PATH_NOT_FOUND => "{Path Not Found} The path %hs does not exist.",
            NT_STATUS_OBJECT_PATH_SYNTAX_BAD => "The object path component was not a directory object.",
            NT_STATUS_DATA_OVERRUN => "{Data Overrun} A data overrun error occurred.",
            NT_STATUS_DATA_LATE_ERROR => "{Data Late} A data late error occurred.",
            NT_STATUS_DATA_ERROR => "{Data Error} An error occurred in reading or writing data.",
            NT_STATUS_CRC_ERROR => "{Bad CRC} A cyclic redundancy check (CRC) checksum error occurred.",
            NT_STATUS_SECTION_TOO_BIG => "{Section Too Large} The specified section is too big to map the file.",
            NT_STATUS_PORT_CONNECTION_REFUSED => "The NtConnectPort request is refused.",
            NT_STATUS_INVALID_PORT_HANDLE => "The type of port handle is invalid for the operation that is requested.",
            NT_STATUS_SHARING_VIOLATION => "A file cannot be opened because the share access flags are incompatible.",
            NT_STATUS_QUOTA_EXCEEDED => "Insufficient quota exists to complete the operation.",
            NT_STATUS_INVALID_PAGE_PROTECTION => "The specified page protection was not valid.",
            NT_STATUS_MUTANT_NOT_OWNED => "An attempt to release a mutant object was made by a thread that was not the owner of the mutant object.",
            NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED => "An attempt was made to release a semaphore such that its maximum count would have been exceeded.",
            NT_STATUS_PORT_ALREADY_SET => "An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set.",
            NT_STATUS_SECTION_NOT_IMAGE => "An attempt was made to query image information on a section that does not map an image.",
            NT_STATUS_SUSPEND_COUNT_EXCEEDED => "An attempt was made to suspend a thread whose suspend count was at its maximum.",
            NT_STATUS_THREAD_IS_TERMINATING => "An attempt was made to suspend a thread that has begun termination.",
            NT_STATUS_BAD_WORKING_SET_LIMIT => "An attempt was made to set the working set limit to an invalid value (for example, the minimum greater than maximum).",
            NT_STATUS_INCOMPATIBLE_FILE_MAP => "A section was created to map a file that is not compatible with an already existing section that maps the same file.",
            NT_STATUS_SECTION_PROTECTION => "A view to a section specifies a protection that is incompatible with the protection of the initial view.",
            NT_STATUS_EAS_NOT_SUPPORTED => "An operation involving EAs failed because the file system does not support EAs.",
            NT_STATUS_EA_TOO_LARGE => "An EA operation failed because the EA set is too large.",
            NT_STATUS_NONEXISTENT_EA_ENTRY => "An EA operation failed because the name or EA index is invalid.",
            NT_STATUS_NO_EAS_ON_FILE => "The file for which EAs were requested has no EAs.",
            NT_STATUS_EA_CORRUPT_ERROR => "The EA is corrupt and cannot be read.",
            NT_STATUS_FILE_LOCK_CONFLICT => "A requested read/write cannot be granted due to a conflicting file lock.",
            NT_STATUS_LOCK_NOT_GRANTED => "A requested file lock cannot be granted due to other existing locks.",
            NT_STATUS_DELETE_PENDING => "A non-close operation has been requested of a file object that has a delete pending.",
            NT_STATUS_CTL_FILE_NOT_SUPPORTED => "An attempt was made to set the control attribute on a file. This attribute is not supported in the destination file system.",
            NT_STATUS_UNKNOWN_REVISION => "Indicates a revision number that was encountered or specified is not one that is known by the service. It might be a more recent revision than the service is aware of.",
            NT_STATUS_REVISION_MISMATCH => "Indicates that two revision levels are incompatible.",
            NT_STATUS_INVALID_OWNER => "Indicates a particular security ID cannot be assigned as the owner of an object.",
            NT_STATUS_INVALID_PRIMARY_GROUP => "Indicates a particular security ID cannot be assigned as the primary group of an object.",
            NT_STATUS_NO_IMPERSONATION_TOKEN => "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.",
            NT_STATUS_CANT_DISABLE_MANDATORY => "A mandatory group cannot be disabled.",
            NT_STATUS_NO_LOGON_SERVERS => "No logon servers are currently available to service the logon request.",
            NT_STATUS_NO_SUCH_LOGON_SESSION => "A specified logon session does not exist. It might already have been terminated.",
            NT_STATUS_NO_SUCH_PRIVILEGE => "A specified privilege does not exist.",
            NT_STATUS_PRIVILEGE_NOT_HELD => "A required privilege is not held by the client.",
            NT_STATUS_INVALID_ACCOUNT_NAME => "The name provided is not a properly formed account name.",
            NT_STATUS_USER_EXISTS => "The specified account already exists.",
            NT_STATUS_NO_SUCH_USER => "The specified account does not exist.",
            NT_STATUS_GROUP_EXISTS => "The specified group already exists.",
            NT_STATUS_NO_SUCH_GROUP => "The specified group does not exist.",
            NT_STATUS_MEMBER_IN_GROUP => "The specified user account is already in the specified group account. Also used to indicate a group cannot be deleted because it contains a member.",
            NT_STATUS_MEMBER_NOT_IN_GROUP => "The specified user account is not a member of the specified group account.",
            NT_STATUS_LAST_ADMIN => "Indicates the requested operation would disable or delete the last remaining administration account. This is not allowed to prevent creating a situation in which the system cannot be administrated.",
            NT_STATUS_WRONG_PASSWORD => "When trying to update a password, this return status indicates that the value provided as the current password is not correct.",
            NT_STATUS_ILL_FORMED_PASSWORD => "When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords.",
            NT_STATUS_PASSWORD_RESTRICTION => "When trying to update a password, this status indicates that some password update rule has been violated. For example, the password might not meet length criteria.",
            NT_STATUS_LOGON_FAILURE => "The attempted logon is invalid. This is either due to a bad username or authentication information.",
            NT_STATUS_ACCOUNT_RESTRICTION => "Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).",
            NT_STATUS_INVALID_LOGON_HOURS => "The user account has time restrictions and cannot be logged onto at this time.",
            NT_STATUS_INVALID_WORKSTATION => "The user account is restricted so that it cannot be used to log on from the source workstation.",
            NT_STATUS_PASSWORD_EXPIRED => "The user account password has expired.",
            NT_STATUS_ACCOUNT_DISABLED => "The referenced account is currently disabled and cannot be logged on to.",
            NT_STATUS_NONE_MAPPED => "None of the information to be translated has been translated.",
            NT_STATUS_TOO_MANY_LUIDS_REQUESTED => "The number of LUIDs requested cannot be allocated with a single allocation.",
            NT_STATUS_LUIDS_EXHAUSTED => "Indicates there are no more LUIDs to allocate.",
            NT_STATUS_INVALID_SUB_AUTHORITY => "Indicates the sub-authority value is invalid for the particular use.",
            NT_STATUS_INVALID_ACL => "Indicates the ACL structure is not valid.",
            NT_STATUS_INVALID_SID => "Indicates the SID structure is not valid.",
            NT_STATUS_INVALID_SECURITY_DESCR => "Indicates the SECURITY_DESCRIPTOR structure is not valid.",
            NT_STATUS_PROCEDURE_NOT_FOUND => "Indicates the specified procedure address cannot be found in the DLL.",
            NT_STATUS_INVALID_IMAGE_FORMAT => "{Bad Image} %hs is either not designed to run on Windows or it contains an error. Try installing the program again using the original installation media or contact your system administrator or the software vendor for support.",
            NT_STATUS_NO_TOKEN => "An attempt was made to reference a token that does not exist. This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client.",
            NT_STATUS_BAD_INHERITANCE_ACL => "Indicates that an attempt to build either an inherited ACL or ACE was not successful. This can be caused by a number of things. One of the more probable causes is the replacement of a CreatorId with a SID that did not fit into the ACE or ACL.",
            NT_STATUS_RANGE_NOT_LOCKED => "The range specified in NtUnlockFile was not locked.",
            NT_STATUS_DISK_FULL => "An operation failed because the disk was full.",
            NT_STATUS_SERVER_DISABLED => "The GUID allocation server is disabled at the moment.",
            NT_STATUS_SERVER_NOT_DISABLED => "The GUID allocation server is enabled at the moment.",
            NT_STATUS_TOO_MANY_GUIDS_REQUESTED => "Too many GUIDs were requested from the allocation server at once.",
            NT_STATUS_GUIDS_EXHAUSTED => "The GUIDs could not be allocated because the Authority Agent was exhausted.",
            NT_STATUS_INVALID_ID_AUTHORITY => "The value provided was an invalid value for an identifier authority.",
            NT_STATUS_AGENTS_EXHAUSTED => "No more authority agent values are available for the particular identifier authority value.",
            NT_STATUS_INVALID_VOLUME_LABEL => "An invalid volume label has been specified.",
            NT_STATUS_SECTION_NOT_EXTENDED => "A mapped section could not be extended.",
            NT_STATUS_NOT_MAPPED_DATA => "Specified section to flush does not map a data file.",
            NT_STATUS_RESOURCE_DATA_NOT_FOUND => "Indicates the specified image file did not contain a resource section.",
            NT_STATUS_RESOURCE_TYPE_NOT_FOUND => "Indicates the specified resource type cannot be found in the image file.",
            NT_STATUS_RESOURCE_NAME_NOT_FOUND => "Indicates the specified resource name cannot be found in the image file.",
            NT_STATUS_ARRAY_BOUNDS_EXCEEDED => "{EXCEPTION} Array bounds exceeded.",
            NT_STATUS_FLOAT_DENORMAL_OPERAND => "{EXCEPTION} Floating-point denormal operand.",
            NT_STATUS_FLOAT_DIVIDE_BY_ZERO => "{EXCEPTION} Floating-point division by zero.",
            NT_STATUS_FLOAT_INEXACT_RESULT => "{EXCEPTION} Floating-point inexact result.",
            NT_STATUS_FLOAT_INVALID_OPERATION => "{EXCEPTION} Floating-point invalid operation.",
            NT_STATUS_FLOAT_OVERFLOW => "{EXCEPTION} Floating-point overflow.",
            NT_STATUS_FLOAT_STACK_CHECK => "{EXCEPTION} Floating-point stack check.",
            NT_STATUS_FLOAT_UNDERFLOW => "{EXCEPTION} Floating-point underflow.",
            NT_STATUS_INTEGER_DIVIDE_BY_ZERO => "{EXCEPTION} Integer division by zero.",
            NT_STATUS_INTEGER_OVERFLOW => "{EXCEPTION} Integer overflow.",
            NT_STATUS_PRIVILEGED_INSTRUCTION => "{EXCEPTION} Privileged instruction.",
            NT_STATUS_TOO_MANY_PAGING_FILES => "An attempt was made to install more paging files than the system supports.",
            NT_STATUS_FILE_INVALID => "The volume for a file has been externally altered such that the opened file is no longer valid.",
            NT_STATUS_ALLOTTED_SPACE_EXCEEDED => "When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates might exceed the amount of memory originally allotted. Because a quota might already have been charged to several processes that have handles to the object, it is not reasonable to alter the size of the allocated memory. Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTTED_SPACE_EXCEEDED error returned.",
            NT_STATUS_INSUFFICIENT_RESOURCES => "Insufficient system resources exist to complete the API.",
            NT_STATUS_DFS_EXIT_PATH_FOUND => "An attempt has been made to open a DFS exit path control file.",
            NT_STATUS_DEVICE_DATA_ERROR => "There are bad blocks (sectors) on the hard disk.",
            NT_STATUS_DEVICE_NOT_CONNECTED => "There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk.",
            NT_STATUS_FREE_VM_NOT_AT_BASE => "Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified.",
            NT_STATUS_MEMORY_NOT_ALLOCATED => "An attempt was made to free virtual memory that is not allocated.",
            NT_STATUS_WORKING_SET_QUOTA => "The working set is not big enough to allow the requested pages to be locked.",
            NT_STATUS_MEDIA_WRITE_PROTECTED => "{Write Protect Error} The disk cannot be written to because it is write-protected. Remove the write protection from the volume %hs in drive %hs.",
            NT_STATUS_DEVICE_NOT_READY => "{Drive Not Ready} The drive is not ready for use; its door might be open. Check drive %hs and make sure that a disk is inserted and that the drive door is closed.",
            NT_STATUS_INVALID_GROUP_ATTRIBUTES => "The specified attributes are invalid or are incompatible with the attributes for the group as a whole.",
            NT_STATUS_BAD_IMPERSONATION_LEVEL => "A specified impersonation level is invalid. Also used to indicate that a required impersonation level was not provided.",
            NT_STATUS_CANT_OPEN_ANONYMOUS => "An attempt was made to open an anonymous-level token. Anonymous tokens cannot be opened.",
            NT_STATUS_BAD_VALIDATION_CLASS => "The validation information class requested was invalid.",
            NT_STATUS_BAD_TOKEN_TYPE => "The type of a token object is inappropriate for its attempted use.",
            NT_STATUS_BAD_MASTER_BOOT_RECORD => "The type of a token object is inappropriate for its attempted use.",
            NT_STATUS_INSTRUCTION_MISALIGNMENT => "An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references.",
            NT_STATUS_INSTANCE_NOT_AVAILABLE => "The maximum named pipe instance count has been reached.",
            NT_STATUS_PIPE_NOT_AVAILABLE => "An instance of a named pipe cannot be found in the listening state.",
            NT_STATUS_INVALID_PIPE_STATE => "The named pipe is not in the connected or closing state.",
            NT_STATUS_PIPE_BUSY => "The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations.",
            NT_STATUS_ILLEGAL_FUNCTION => "The specified handle is not open to the server end of the named pipe.",
            NT_STATUS_PIPE_DISCONNECTED => "The specified named pipe is in the disconnected state.",
            NT_STATUS_PIPE_CLOSING => "The specified named pipe is in the closing state.",
            NT_STATUS_PIPE_CONNECTED => "The specified named pipe is in the connected state.",
            NT_STATUS_PIPE_LISTENING => "The specified named pipe is in the listening state.",
            NT_STATUS_INVALID_READ_MODE => "The specified named pipe is not in message mode.",
            NT_STATUS_IO_TIMEOUT => "{Device Timeout} The specified I/O operation on %hs was not completed before the time-out period expired.",
            NT_STATUS_FILE_FORCED_CLOSED => "The specified file has been closed by another process.",
            NT_STATUS_PROFILING_NOT_STARTED => "Profiling is not started.",
            NT_STATUS_PROFILING_NOT_STOPPED => "Profiling is not stopped.",
            NT_STATUS_COULD_NOT_INTERPRET => "The passed ACL did not contain the minimum required information.",
            NT_STATUS_FILE_IS_A_DIRECTORY => "The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory.",
            NT_STATUS_NOT_SUPPORTED => "The request is not supported.",
            NT_STATUS_REMOTE_NOT_LISTENING => "This remote computer is not listening.",
            NT_STATUS_DUPLICATE_NAME => "A duplicate name exists on the network.",
            NT_STATUS_BAD_NETWORK_PATH => "The network path cannot be located.",
            NT_STATUS_NETWORK_BUSY => "The network is busy.",
            NT_STATUS_DEVICE_DOES_NOT_EXIST => "This device does not exist.",
            NT_STATUS_TOO_MANY_COMMANDS => "The network BIOS command limit has been reached.",
            NT_STATUS_ADAPTER_HARDWARE_ERROR => "An I/O adapter hardware error has occurred.",
            NT_STATUS_INVALID_NETWORK_RESPONSE => "The network responded incorrectly.",
            NT_STATUS_UNEXPECTED_NETWORK_ERROR => "An unexpected network error occurred.",
            NT_STATUS_BAD_REMOTE_ADAPTER => "The remote adapter is not compatible.",
            NT_STATUS_PRINT_QUEUE_FULL => "The print queue is full.",
            NT_STATUS_NO_SPOOL_SPACE => "Space to store the file that is waiting to be printed is not available on the server.",
            NT_STATUS_PRINT_CANCELLED => "The requested print file has been canceled.",
            NT_STATUS_NETWORK_NAME_DELETED => "The network name was deleted.",
            NT_STATUS_NETWORK_ACCESS_DENIED => "Network access is denied.",
            NT_STATUS_BAD_DEVICE_TYPE => "{Incorrect Network Resource Type} The specified device type (LPT, for example) conflicts with the actual device type on the remote resource.",
            NT_STATUS_BAD_NETWORK_NAME => "{Network Name Not Found} The specified share name cannot be found on the remote server.",
            NT_STATUS_TOO_MANY_NAMES => "The name limit for the network adapter card of the local computer was exceeded.",
            NT_STATUS_TOO_MANY_SESSIONS => "The network BIOS session limit was exceeded.",
            NT_STATUS_SHARING_PAUSED => "File sharing has been temporarily paused.",
            NT_STATUS_REQUEST_NOT_ACCEPTED => "No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections.",
            NT_STATUS_REDIRECTOR_PAUSED => "Print or disk redirection is temporarily paused.",
            NT_STATUS_NET_WRITE_FAULT => "A network data fault occurred.",
            NT_STATUS_PROFILING_AT_LIMIT => "The number of active profiling objects is at the maximum and no more can be started.",
            NT_STATUS_NOT_SAME_DEVICE => "{Incorrect Volume} The destination file of a rename request is located on a different device than the source of the rename request.",
            NT_STATUS_FILE_RENAMED => "The specified file has been renamed and thus cannot be modified.",
            NT_STATUS_VIRTUAL_CIRCUIT_CLOSED => "{Network Request Timeout} The session with a remote server has been disconnected because the time-out interval for a request has expired.",
            NT_STATUS_NO_SECURITY_ON_OBJECT => "Indicates an attempt was made to operate on the security of an object that does not have security associated with it.",
            NT_STATUS_CANT_WAIT => "Used to indicate that an operation cannot continue without blocking for I/O.",
            NT_STATUS_PIPE_EMPTY => "Used to indicate that a read operation was done on an empty pipe.",
            NT_STATUS_CANT_ACCESS_DOMAIN_INFO => "Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied.",
            NT_STATUS_CANT_TERMINATE_SELF => "Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.",
            NT_STATUS_INVALID_SERVER_STATE => "Indicates the Sam Server was in the wrong state to perform the desired operation.",
            NT_STATUS_INVALID_DOMAIN_STATE => "Indicates the domain was in the wrong state to perform the desired operation.",
            NT_STATUS_INVALID_DOMAIN_ROLE => "This operation is only allowed for the primary domain controller of the domain.",
            NT_STATUS_NO_SUCH_DOMAIN => "The specified domain did not exist.",
            NT_STATUS_DOMAIN_EXISTS => "The specified domain already exists.",
            NT_STATUS_DOMAIN_LIMIT_EXCEEDED => "An attempt was made to exceed the limit on the number of domains per server for this release.",
            NT_STATUS_OPLOCK_NOT_GRANTED => "An error status returned when the opportunistic lock (oplock) request is denied.",
            NT_STATUS_INVALID_OPLOCK_PROTOCOL => "An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system.",
            NT_STATUS_INTERNAL_DB_CORRUPTION => "This error indicates that the requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption.",
            NT_STATUS_INTERNAL_ERROR => "An internal error occurred.",
            NT_STATUS_GENERIC_NOT_MAPPED => "Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types.",
            NT_STATUS_BAD_DESCRIPTOR_FORMAT => "Indicates a security descriptor is not in the necessary format (absolute or self-relative).",
            NT_STATUS_INVALID_USER_BUFFER => "An access to a user buffer failed at an expected point in time. This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter.",
            NT_STATUS_UNEXPECTED_IO_ERROR => "If an I/O error that is not defined in the standard FsRtl filter is returned, it is converted to the following error, which is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
            NT_STATUS_UNEXPECTED_MM_CREATE_ERR => "If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
            NT_STATUS_UNEXPECTED_MM_MAP_ERROR => "If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
            NT_STATUS_UNEXPECTED_MM_EXTEND_ERR => "If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.",
            NT_STATUS_NOT_LOGON_PROCESS => "The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.",
            NT_STATUS_LOGON_SESSION_EXISTS => "An attempt has been made to start a new session manager or LSA logon session by using an ID that is already in use.",
            NT_STATUS_INVALID_PARAMETER_1 => "An invalid parameter was passed to a service or function as the first argument.",
            NT_STATUS_INVALID_PARAMETER_2 => "An invalid parameter was passed to a service or function as the second argument.",
            NT_STATUS_INVALID_PARAMETER_3 => "An invalid parameter was passed to a service or function as the third argument.",
            NT_STATUS_INVALID_PARAMETER_4 => "An invalid parameter was passed to a service or function as the fourth argument.",
            NT_STATUS_INVALID_PARAMETER_5 => "An invalid parameter was passed to a service or function as the fifth argument.",
            NT_STATUS_INVALID_PARAMETER_6 => "An invalid parameter was passed to a service or function as the sixth argument.",
            NT_STATUS_INVALID_PARAMETER_7 => "An invalid parameter was passed to a service or function as the seventh argument.",
            NT_STATUS_INVALID_PARAMETER_8 => "An invalid parameter was passed to a service or function as the eighth argument.",
            NT_STATUS_INVALID_PARAMETER_9 => "An invalid parameter was passed to a service or function as the ninth argument.",
            NT_STATUS_INVALID_PARAMETER_10 => "An invalid parameter was passed to a service or function as the tenth argument.",
            NT_STATUS_INVALID_PARAMETER_11 => "An invalid parameter was passed to a service or function as the eleventh argument.",
            NT_STATUS_INVALID_PARAMETER_12 => "An invalid parameter was passed to a service or function as the twelfth argument.",
            NT_STATUS_REDIRECTOR_NOT_STARTED => "An attempt was made to access a network file, but the network software was not yet started.",
            NT_STATUS_REDIRECTOR_STARTED => "An attempt was made to start the redirector, but the redirector has already been started.",
            NT_STATUS_STACK_OVERFLOW => "A new guard page for the stack cannot be created.",
            NT_STATUS_NO_SUCH_PACKAGE => "A specified authentication package is unknown.",
            NT_STATUS_BAD_FUNCTION_TABLE => "A malformed function table was encountered during an unwind operation.",
            NT_STATUS_VARIABLE_NOT_FOUND => "Indicates the specified environment variable name was not found in the specified environment block.",
            NT_STATUS_DIRECTORY_NOT_EMPTY => "Indicates that the directory trying to be deleted is not empty.",
            NT_STATUS_FILE_CORRUPT_ERROR => "{Corrupt File} The file or directory %hs is corrupt and unreadable. Run the Chkdsk utility.",
            NT_STATUS_NOT_A_DIRECTORY => "A requested opened file is not a directory.",
            NT_STATUS_BAD_LOGON_SESSION_STATE => "The logon session is not in a state that is consistent with the requested operation.",
            NT_STATUS_LOGON_SESSION_COLLISION => "An internal LSA error has occurred. An authentication package has requested the creation of a logon session but the ID of an already existing logon session has been specified.",
            NT_STATUS_NAME_TOO_LONG => "A specified name string is too long for its intended use.",
            NT_STATUS_FILES_OPEN => "The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force.",
            NT_STATUS_CONNECTION_IN_USE => "The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force.",
            NT_STATUS_MESSAGE_NOT_FOUND => "RtlFindMessage could not locate the requested message ID in the message table resource.",
            NT_STATUS_PROCESS_IS_TERMINATING => "An attempt was made to duplicate an object handle into or out of an exiting process.",
            NT_STATUS_INVALID_LOGON_TYPE => "Indicates an invalid value has been provided for the LogonType requested.",
            NT_STATUS_NO_GUID_TRANSLATION => "Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which might cause a file creation attempt to fail.",
            NT_STATUS_CANNOT_IMPERSONATE => "Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from.",
            NT_STATUS_IMAGE_ALREADY_LOADED => "Indicates that the specified image is already loaded.",
            NT_STATUS_NO_LDT => "Indicates that an attempt was made to change the size of the LDT for a process that has no LDT.",
            NT_STATUS_INVALID_LDT_SIZE => "Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors.",
            NT_STATUS_INVALID_LDT_OFFSET => "Indicates that the starting value for the LDT information was not an integral multiple of the selector size.",
            NT_STATUS_INVALID_LDT_DESCRIPTOR => "Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.",
            NT_STATUS_INVALID_IMAGE_NE_FORMAT => "The specified image file did not have the correct format. It appears to be NE format.",
            NT_STATUS_RXACT_INVALID_STATE => "Indicates that the transaction state of a registry subtree is incompatible with the requested operation. For example, a request has been made to start a new transaction with one already in progress, or a request has been made to apply a transaction when one is not currently in progress.",
            NT_STATUS_RXACT_COMMIT_FAILURE => "Indicates an error has occurred during a registry transaction commit. The database has been left in an unknown, but probably inconsistent, state. The state of the registry transaction is left as COMMITTING.",
            NT_STATUS_MAPPED_FILE_SIZE_ZERO => "An attempt was made to map a file of size zero with the maximum size specified as zero.",
            NT_STATUS_TOO_MANY_OPENED_FILES => "Too many files are opened on a remote server. This error should only be returned by the Windows redirector on a remote drive.",
            NT_STATUS_CANCELLED => "The I/O request was canceled.",
            NT_STATUS_CANNOT_DELETE => "An attempt has been made to remove a file or directory that cannot be deleted.",
            NT_STATUS_INVALID_COMPUTER_NAME => "Indicates a name that was specified as a remote computer name is syntactically invalid.",
            NT_STATUS_FILE_DELETED => "An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose.",
            NT_STATUS_SPECIAL_ACCOUNT => "Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted.",
            NT_STATUS_SPECIAL_GROUP => "The operation requested cannot be performed on the specified group because it is a built-in special group.",
            NT_STATUS_SPECIAL_USER => "The operation requested cannot be performed on the specified user because it is a built-in special user.",
            NT_STATUS_MEMBERS_PRIMARY_GROUP => "Indicates a member cannot be removed from a group because the group is currently the member's primary group.",
            NT_STATUS_FILE_CLOSED => "An I/O request other than close and several other special case operations was attempted using a file object that had already been closed.",
            NT_STATUS_TOO_MANY_THREADS => "Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token can be performed only when a process has zero or one threads.",
            NT_STATUS_THREAD_NOT_IN_PROCESS => "An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process.",
            NT_STATUS_TOKEN_ALREADY_IN_USE => "An attempt was made to establish a token for use as a primary token but the token is already in use. A token can only be the primary token of one process at a time.",
            NT_STATUS_PAGEFILE_QUOTA_EXCEEDED => "The page file quota was exceeded.",
            NT_STATUS_COMMITMENT_LIMIT => "{Out of Virtual Memory} Your system is low on virtual memory. To ensure that Windows runs correctly, increase the size of your virtual memory paging file. For more information, see Help.",
            NT_STATUS_INVALID_IMAGE_LE_FORMAT => "The specified image file did not have the correct format: it appears to be LE format.",
            NT_STATUS_INVALID_IMAGE_NOT_MZ => "The specified image file did not have the correct format: it did not have an initial MZ.",
            NT_STATUS_INVALID_IMAGE_PROTECT => "The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header.",
            NT_STATUS_INVALID_IMAGE_WIN_16 => "The specified image file did not have the correct format: it appears to be a 16-bit Windows image.",
            NT_STATUS_LOGON_SERVER_CONFLICT => "The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.",
            NT_STATUS_TIME_DIFFERENCE_AT_DC => "The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount.",
            NT_STATUS_SYNCHRONIZATION_REQUIRED => "On applicable Windows Server releases, the SAM database is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.",
            NT_STATUS_DLL_NOT_FOUND => "{Unable To Locate Component} This application has failed to start because %hs was not found. Reinstalling the application might fix this problem.",
            NT_STATUS_OPEN_FAILED => "The NtCreateFile API failed. This error should never be returned to an application; it is a place holder for the Windows LAN Manager Redirector to use in its internal error-mapping routines.",
            NT_STATUS_IO_PRIVILEGE_FAILED => "{Privilege Failed} The I/O permissions for the process could not be changed.",
            NT_STATUS_ORDINAL_NOT_FOUND => "{Ordinal Not Found} The ordinal %ld could not be located in the dynamic link library %hs.",
            NT_STATUS_ENTRYPOINT_NOT_FOUND => "{Entry Point Not Found} The procedure entry point %hs could not be located in the dynamic link library %hs.",
            NT_STATUS_CONTROL_C_EXIT => "{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.",
            NT_STATUS_LOCAL_DISCONNECT => "{Virtual Circuit Closed} The network transport on your computer has closed a network connection. There might or might not be I/O requests outstanding.",
            NT_STATUS_REMOTE_DISCONNECT => "{Virtual Circuit Closed} The network transport on a remote computer has closed a network connection. There might or might not be I/O requests outstanding.",
            NT_STATUS_REMOTE_RESOURCES => "{Insufficient Resources on Remote Computer} The remote computer has insufficient resources to complete the network request. For example, the remote computer might not have enough available memory to carry out the request at this time.",
            NT_STATUS_LINK_FAILED => "{Virtual Circuit Closed} An existing connection (virtual circuit) has been broken at the remote computer. There is probably something wrong with the network software protocol or the network hardware on the remote computer.",
            NT_STATUS_LINK_TIMEOUT => "{Virtual Circuit Closed} The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer.",
            NT_STATUS_INVALID_CONNECTION => "The connection handle that was given to the transport was invalid.",
            NT_STATUS_INVALID_ADDRESS => "The address handle that was given to the transport was invalid.",
            NT_STATUS_DLL_INIT_FAILED => "{DLL Initialization Failed} Initialization of the dynamic link library %hs failed. The process is terminating abnormally.",
            NT_STATUS_MISSING_SYSTEMFILE => "{Missing System File} The required system file %hs is bad or missing.",
            NT_STATUS_UNHANDLED_EXCEPTION => "{Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.",
            NT_STATUS_APP_INIT_FAILURE => "{Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application.",
            NT_STATUS_PAGEFILE_CREATE_FAILED => "{Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.",
            NT_STATUS_NO_PAGEFILE => "{No Paging File Specified} No paging file was specified in the system configuration.",
            NT_STATUS_INVALID_LEVEL => "{Incorrect System Call Level} An invalid level was passed into the specified system call.",
            NT_STATUS_WRONG_PASSWORD_CORE => "{Incorrect Password to LAN Manager Server} You specified an incorrect password to a LAN Manager 2.x or MS-NET server.",
            NT_STATUS_ILLEGAL_FLOAT_CONTEXT => "{EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present.",
            NT_STATUS_PIPE_BROKEN => "The pipe operation has failed because the other end of the pipe has been closed.",
            NT_STATUS_REGISTRY_CORRUPT => "{The Registry Is Corrupt} The structure of one of the files that contains registry data is corrupt; the image of the file in memory is corrupt; or the file could not be recovered because the alternate copy or log was absent or corrupt.",
            NT_STATUS_REGISTRY_IO_FAILED => "An I/O operation initiated by the Registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.",
            NT_STATUS_NO_EVENT_PAIR => "An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.",
            NT_STATUS_UNRECOGNIZED_VOLUME => "The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupt.",
            NT_STATUS_SERIAL_NO_DEVICE_INITED => "No serial device was successfully initialized. The serial driver will unload.",
            NT_STATUS_NO_SUCH_ALIAS => "The specified local group does not exist.",
            NT_STATUS_MEMBER_NOT_IN_ALIAS => "The specified account name is not a member of the group.",
            NT_STATUS_MEMBER_IN_ALIAS => "The specified account name is already a member of the group.",
            NT_STATUS_ALIAS_EXISTS => "The specified local group already exists.",
            NT_STATUS_LOGON_NOT_GRANTED => "A requested type of logon (for example, interactive, network, and service) is not granted by the local security policy of the target system. Ask the system administrator to grant the necessary form of logon.",
            NT_STATUS_TOO_MANY_SECRETS => "The maximum number of secrets that can be stored in a single system was exceeded. The length and number of secrets is limited to satisfy U.S. State Department export restrictions.",
            NT_STATUS_SECRET_TOO_LONG => "The length of a secret exceeds the maximum allowable length. The length and number of secrets is limited to satisfy U.S. State Department export restrictions.",
            NT_STATUS_INTERNAL_DB_ERROR => "The local security authority (LSA) database contains an internal inconsistency.",
            NT_STATUS_FULLSCREEN_MODE => "The requested operation cannot be performed in full-screen mode.",
            NT_STATUS_TOO_MANY_CONTEXT_IDS => "During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation. Remove the user from some global or local groups to reduce the number of security IDs to incorporate into the security context.",
            NT_STATUS_LOGON_TYPE_NOT_GRANTED => "A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who can logon interactively and through the network.",
            NT_STATUS_NOT_REGISTRY_FILE => "The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file.",
            NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED => "An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password.",
            NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR => "A domain server has an incorrect configuration.",
            NT_STATUS_FT_MISSING_MEMBER => "An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system.",
            NT_STATUS_ILL_FORMED_SERVICE_ENTRY => "A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries.",
            NT_STATUS_ILLEGAL_CHARACTER => "An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE.",
            NT_STATUS_UNMAPPABLE_CHARACTER => "No mapping for the Unicode character exists in the target multibyte code page.",
            NT_STATUS_UNDEFINED_CHARACTER => "The Unicode character is not defined in the Unicode character set that is installed on the system.",
            NT_STATUS_FLOPPY_VOLUME => "The paging file cannot be created on a floppy disk.",
            NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND => "{Floppy Disk Error} While accessing a floppy disk, an ID address mark was not found.",
            NT_STATUS_FLOPPY_WRONG_CYLINDER => "{Floppy Disk Error} While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller.",
            NT_STATUS_FLOPPY_UNKNOWN_ERROR => "{Floppy Disk Error} The floppy disk controller reported an error that is not recognized by the floppy disk driver.",
            NT_STATUS_FLOPPY_BAD_REGISTERS => "{Floppy Disk Error} While accessing a floppy-disk, the controller returned inconsistent results via its registers.",
            NT_STATUS_DISK_RECALIBRATE_FAILED => "{Hard Disk Error} While accessing the hard disk, a recalibrate operation failed, even after retries.",
            NT_STATUS_DISK_OPERATION_FAILED => "{Hard Disk Error} While accessing the hard disk, a disk operation failed even after retries.",
            NT_STATUS_DISK_RESET_FAILED => "{Hard Disk Error} While accessing the hard disk, a disk controller reset was needed, but even that failed.",
            NT_STATUS_SHARED_IRQ_BUSY => "An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened. Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use.",
            NT_STATUS_FT_ORPHANING => "{FT Orphaning} A disk that is part of a fault-tolerant volume can no longer be accessed.",
            NT_STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT => "The basic input/output system (BIOS) failed to connect a system interrupt to the device or bus for which the device is connected.",
            NT_STATUS_PARTITION_FAILURE => "The tape could not be partitioned.",
            NT_STATUS_INVALID_BLOCK_LENGTH => "When accessing a new tape of a multi-volume partition, the current blocksize is incorrect.",
            NT_STATUS_DEVICE_NOT_PARTITIONED => "The tape partition information could not be found when loading a tape.",
            NT_STATUS_UNABLE_TO_LOCK_MEDIA => "An attempt to lock the eject media mechanism failed.",
            NT_STATUS_UNABLE_TO_UNLOAD_MEDIA => "An attempt to unload media failed.",
            NT_STATUS_EOM_OVERFLOW => "The physical end of tape was detected.",
            NT_STATUS_NO_MEDIA => "{No Media} There is no media in the drive. Insert media into drive %hs.",
            NT_STATUS_NO_SUCH_MEMBER => "A member could not be added to or removed from the local group because the member does not exist.",
            NT_STATUS_INVALID_MEMBER => "A new member could not be added to a local group because the member has the wrong account type.",
            NT_STATUS_KEY_DELETED => "An illegal operation was attempted on a registry key that has been marked for deletion.",
            NT_STATUS_NO_LOG_SPACE => "The system could not allocate the required space in a registry log.",
            NT_STATUS_TOO_MANY_SIDS => "Too many SIDs have been specified.",
            NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED => "An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password.",
            NT_STATUS_KEY_HAS_CHILDREN => "An attempt was made to create a symbolic link in a registry key that already has subkeys or values.",
            NT_STATUS_CHILD_MUST_BE_VOLATILE => "An attempt was made to create a stable subkey under a volatile parent key.",
            NT_STATUS_DEVICE_CONFIGURATION_ERROR => "The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect.",
            NT_STATUS_DRIVER_INTERNAL_ERROR => "An error was detected between two drivers or within an I/O driver.",
            NT_STATUS_INVALID_DEVICE_STATE => "The device is not in a valid state to perform this request.",
            NT_STATUS_IO_DEVICE_ERROR => "The I/O device reported an I/O error.",
            NT_STATUS_DEVICE_PROTOCOL_ERROR => "A protocol error was detected between the driver and the device.",
            NT_STATUS_BACKUP_CONTROLLER => "This operation is only allowed for the primary domain controller of the domain.",
            NT_STATUS_LOG_FILE_FULL => "The log file space is insufficient to support this operation.",
            NT_STATUS_TOO_LATE => "A write operation was attempted to a volume after it was dismounted.",
            NT_STATUS_NO_TRUST_LSA_SECRET => "The workstation does not have a trust secret for the primary domain in the local LSA database.",
            NT_STATUS_NO_TRUST_SAM_ACCOUNT => "On applicable Windows Server releases, the SAM database does not have a computer account for this workstation trust relationship.",
            NT_STATUS_TRUSTED_DOMAIN_FAILURE => "The logon request failed because the trust relationship between the primary domain and the trusted domain failed.",
            NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE => "The logon request failed because the trust relationship between this workstation and the primary domain failed.",
            NT_STATUS_EVENTLOG_FILE_CORRUPT => "The Eventlog log file is corrupt.",
            NT_STATUS_EVENTLOG_CANT_START => "No Eventlog log file could be opened. The Eventlog service did not start.",
            NT_STATUS_TRUST_FAILURE => "The network logon failed. This might be because the validation authority cannot be reached.",
            NT_STATUS_MUTANT_LIMIT_EXCEEDED => "An attempt was made to acquire a mutant such that its maximum count would have been exceeded.",
            NT_STATUS_NETLOGON_NOT_STARTED => "An attempt was made to logon, but the NetLogon service was not started.",
            NT_STATUS_ACCOUNT_EXPIRED => "The user account has expired.",
            NT_STATUS_POSSIBLE_DEADLOCK => "{EXCEPTION} Possible deadlock condition.",
            NT_STATUS_NETWORK_CREDENTIAL_CONFLICT => "Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.",
            NT_STATUS_REMOTE_SESSION_LIMIT => "An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.",
            NT_STATUS_EVENTLOG_FILE_CHANGED => "The log file has changed between reads.",
            NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT => "The account used is an interdomain trust account. Use your global user account or local user account to access this server.",
            NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT => "The account used is a computer account. Use your global user account or local user account to access this server.",
            NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT => "The account used is a server trust account. Use your global user account or local user account to access this server.",
            NT_STATUS_DOMAIN_TRUST_INCONSISTENT => "The name or SID of the specified domain is inconsistent with the trust information for that domain.",
            NT_STATUS_FS_DRIVER_REQUIRED => "A volume has been accessed for which a file system driver is required that has not yet been loaded.",
            NT_STATUS_IMAGE_ALREADY_LOADED_AS_DLL => "Indicates that the specified image is already loaded as a DLL.",
            NT_STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING => "Short name settings cannot be changed on this volume due to the global registry setting.",
            NT_STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME => "Short names are not enabled on this volume.",
            NT_STATUS_SECURITY_STREAM_IS_INCONSISTENT => "The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume.",
            NT_STATUS_INVALID_LOCK_RANGE => "A requested file lock operation cannot be processed due to an invalid byte range.",
            NT_STATUS_INVALID_ACE_CONDITION => "The specified access control entry (ACE) contains an invalid condition.",
            NT_STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT => "The subsystem needed to support the image type is not present.",
            NT_STATUS_NOTIFICATION_GUID_ALREADY_DEFINED => "The specified file already has a notification GUID associated with it.",
            NT_STATUS_NETWORK_OPEN_RESTRICTION => "A remote open failed because the network open restrictions were not satisfied.",
            NT_STATUS_NO_USER_SESSION_KEY => "There is no user session key for the specified logon session.",
            NT_STATUS_USER_SESSION_DELETED => "The remote user session has been deleted.",
            NT_STATUS_RESOURCE_LANG_NOT_FOUND => "Indicates the specified resource language ID cannot be found in the image file.",
            NT_STATUS_INSUFF_SERVER_RESOURCES => "Insufficient server resources exist to complete the request.",
            NT_STATUS_INVALID_BUFFER_SIZE => "The size of the buffer is invalid for the specified operation.",
            NT_STATUS_INVALID_ADDRESS_COMPONENT => "The transport rejected the specified network address as invalid.",
            NT_STATUS_INVALID_ADDRESS_WILDCARD => "The transport rejected the specified network address due to invalid use of a wildcard.",
            NT_STATUS_TOO_MANY_ADDRESSES => "The transport address could not be opened because all the available addresses are in use.",
            NT_STATUS_ADDRESS_ALREADY_EXISTS => "The transport address could not be opened because it already exists.",
            NT_STATUS_ADDRESS_CLOSED => "The transport address is now closed.",
            NT_STATUS_CONNECTION_DISCONNECTED => "The transport connection is now disconnected.",
            NT_STATUS_CONNECTION_RESET => "The transport connection has been reset.",
            NT_STATUS_TOO_MANY_NODES => "The transport cannot dynamically acquire any more nodes.",
            NT_STATUS_TRANSACTION_ABORTED => "The transport aborted a pending transaction.",
            NT_STATUS_TRANSACTION_TIMED_OUT => "The transport timed out a request that is waiting for a response.",
            NT_STATUS_TRANSACTION_NO_RELEASE => "The transport did not receive a release for a pending response.",
            NT_STATUS_TRANSACTION_NO_MATCH => "The transport did not find a transaction that matches the specific token.",
            NT_STATUS_TRANSACTION_RESPONDED => "The transport had previously responded to a transaction request.",
            NT_STATUS_TRANSACTION_INVALID_ID => "The transport does not recognize the specified transaction request ID.",
            NT_STATUS_TRANSACTION_INVALID_TYPE => "The transport does not recognize the specified transaction request type.",
            NT_STATUS_NOT_SERVER_SESSION => "The transport can only process the specified request on the server side of a session.",
            NT_STATUS_NOT_CLIENT_SESSION => "The transport can only process the specified request on the client side of a session.",
            NT_STATUS_CANNOT_LOAD_REGISTRY_FILE => "{Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.",
            NT_STATUS_DEBUG_ATTACH_FAILED => "{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. Choosing OK will terminate the process, and choosing Cancel will ignore the error.",
            NT_STATUS_SYSTEM_PROCESS_TERMINATED => "{Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.",
            NT_STATUS_DATA_NOT_ACCEPTED => "{Data Not Accepted} The TDI client could not handle the data received during an indication.",
            NT_STATUS_NO_BROWSER_SERVERS_FOUND => "{Unable to Retrieve Browser Server List} The list of servers for this workgroup is not currently available.",
            NT_STATUS_VDM_HARD_ERROR => "NTVDM encountered a hard error.",
            NT_STATUS_DRIVER_CANCEL_TIMEOUT => "{Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time.",
            NT_STATUS_REPLY_MESSAGE_MISMATCH => "{Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message.",
            NT_STATUS_MAPPED_ALIGNMENT => "{Mapped View Alignment Incorrect} An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity.",
            NT_STATUS_IMAGE_CHECKSUM_MISMATCH => "{Bad Image Checksum} The image %hs is possibly corrupt. The header checksum does not match the computed checksum.",
            NT_STATUS_LOST_WRITEBEHIND_DATA => "{Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error might be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.",
            NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID => "The parameters passed to the server in the client/server shared memory window were invalid. Too much data might have been put in the shared memory window.",
            NT_STATUS_PASSWORD_MUST_CHANGE => "The user password must be changed before logging on the first time.",
            NT_STATUS_NOT_FOUND => "The object was not found.",
            NT_STATUS_NOT_TINY_STREAM => "The stream is not a tiny stream.",
            NT_STATUS_RECOVERY_FAILURE => "A transaction recovery failed.",
            NT_STATUS_STACK_OVERFLOW_READ => "The request must be handled by the stack overflow code.",
            NT_STATUS_FAIL_CHECK => "A consistency check failed.",
            NT_STATUS_DUPLICATE_OBJECTID => "The attempt to insert the ID in the index failed because the ID is already in the index.",
            NT_STATUS_OBJECTID_EXISTS => "The attempt to set the object ID failed because the object already has an ID.",
            NT_STATUS_CONVERT_TO_LARGE => "Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing oNode is moved or the extent stream is converted to a large stream.",
            NT_STATUS_RETRY => "The request needs to be retried.",
            NT_STATUS_FOUND_OUT_OF_SCOPE => "The attempt to find the object found an object on the volume that matches by ID; however, it is out of the scope of the handle that is used for the operation.",
            NT_STATUS_ALLOCATE_BUCKET => "The bucket array must be grown. Retry the transaction after doing so.",
            NT_STATUS_PROPSET_NOT_FOUND => "The specified property set does not exist on the object.",
            NT_STATUS_MARSHALL_OVERFLOW => "The user/kernel marshaling buffer has overflowed.",
            NT_STATUS_INVALID_VARIANT => "The supplied variant structure contains invalid data.",
            NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND => "A domain controller for this domain was not found.",
            NT_STATUS_ACCOUNT_LOCKED_OUT => "The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested.",
            NT_STATUS_HANDLE_NOT_CLOSABLE => "NtClose was called on a handle that was protected from close via NtSetInformationObject.",
            NT_STATUS_CONNECTION_REFUSED => "The transport-connection attempt was refused by the remote system.",
            NT_STATUS_GRACEFUL_DISCONNECT => "The transport connection was gracefully closed.",
            NT_STATUS_ADDRESS_ALREADY_ASSOCIATED => "The transport endpoint already has an address associated with it.",
            NT_STATUS_ADDRESS_NOT_ASSOCIATED => "An address has not yet been associated with the transport endpoint.",
            NT_STATUS_CONNECTION_INVALID => "An operation was attempted on a nonexistent transport connection.",
            NT_STATUS_CONNECTION_ACTIVE => "An invalid operation was attempted on an active transport connection.",
            NT_STATUS_NETWORK_UNREACHABLE => "The remote network is not reachable by the transport.",
            NT_STATUS_HOST_UNREACHABLE => "The remote system is not reachable by the transport.",
            NT_STATUS_PROTOCOL_UNREACHABLE => "The remote system does not support the transport protocol.",
            NT_STATUS_PORT_UNREACHABLE => "No service is operating at the destination port of the transport on the remote system.",
            NT_STATUS_REQUEST_ABORTED => "The request was aborted.",
            NT_STATUS_CONNECTION_ABORTED => "The transport connection was aborted by the local system.",
            NT_STATUS_BAD_COMPRESSION_BUFFER => "The specified buffer contains ill-formed data.",
            NT_STATUS_USER_MAPPED_FILE => "The requested operation cannot be performed on a file with a user mapped section open.",
            NT_STATUS_AUDIT_FAILED => "{Audit Failed} An attempt to generate a security audit failed.",
            NT_STATUS_TIMER_RESOLUTION_NOT_SET => "The timer resolution was not previously set by the current process.",
            NT_STATUS_CONNECTION_COUNT_LIMIT => "A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.",
            NT_STATUS_LOGIN_TIME_RESTRICTION => "Attempting to log on during an unauthorized time of day for this account.",
            NT_STATUS_LOGIN_WKSTA_RESTRICTION => "The account is not authorized to log on from this station.",
            NT_STATUS_IMAGE_MP_UP_MISMATCH => "{UP/MP Image Mismatch} The image %hs has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine. Reinstall the image file.",
            NT_STATUS_INSUFFICIENT_LOGON_INFO => "There is insufficient account information to log you on.",
            NT_STATUS_BAD_DLL_ENTRYPOINT => "{Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO might cause the application to operate incorrectly.",
            NT_STATUS_BAD_SERVICE_ENTRYPOINT => "{Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process might operate incorrectly.",
            NT_STATUS_LPC_REPLY_LOST => "The server received the messages but did not send a reply.",
            NT_STATUS_IP_ADDRESS_CONFLICT1 => "There is an IP address conflict with another system on the network.",
            NT_STATUS_IP_ADDRESS_CONFLICT2 => "There is an IP address conflict with another system on the network.",
            NT_STATUS_REGISTRY_QUOTA_LIMIT => "{Low On Registry Space} The system has reached the maximum size that is allowed for the system part of the registry. Additional storage requests will be ignored.",
            NT_STATUS_PATH_NOT_COVERED => "The contacted server does not support the indicated part of the DFS namespace.",
            NT_STATUS_NO_CALLBACK_ACTIVE => "A callback return system service cannot be executed when no callback is active.",
            NT_STATUS_LICENSE_QUOTA_EXCEEDED => "The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has already accepted the maximum number of connections.",
            NT_STATUS_PWD_TOO_SHORT => "The password provided is too short to meet the policy of your user account. Choose a longer password.",
            NT_STATUS_PWD_TOO_RECENT => "The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.",
            NT_STATUS_PWD_HISTORY_CONFLICT => "You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used.",
            NT_STATUS_PLUGPLAY_NO_DEVICE => "You have attempted to load a legacy device driver while its device instance had been disabled.",
            NT_STATUS_UNSUPPORTED_COMPRESSION => "The specified compression format is unsupported.",
            NT_STATUS_INVALID_HW_PROFILE => "The specified hardware profile configuration is invalid.",
            NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH => "The specified Plug and Play registry device path is invalid.",
            NT_STATUS_DRIVER_ORDINAL_NOT_FOUND => "{Driver Entry Point Not Found} The %hs device driver could not locate the ordinal %ld in driver %hs.",
            NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND => "{Driver Entry Point Not Found} The %hs device driver could not locate the entry point %hs in driver %hs.",
            NT_STATUS_RESOURCE_NOT_OWNED => "{Application Error} The application attempted to release a resource it did not own. Click OK to terminate the application.",
            NT_STATUS_TOO_MANY_LINKS => "An attempt was made to create more links on a file than the file system supports.",
            NT_STATUS_QUOTA_LIST_INCONSISTENT => "The specified quota list is internally inconsistent with its descriptor.",
            NT_STATUS_FILE_IS_OFFLINE => "The specified file has been relocated to offline storage.",
            NT_STATUS_EVALUATION_EXPIRATION => "{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour. To restore access to this installation of Windows, upgrade this installation by using a licensed distribution of this product.",
            NT_STATUS_ILLEGAL_DLL_RELOCATION => "{Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range that is reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.",
            NT_STATUS_LICENSE_VIOLATION => "{License Violation} The system has detected tampering with your registered product type. This is a violation of your software license. Tampering with the product type is not permitted.",
            NT_STATUS_DLL_INIT_FAILED_LOGOFF => "{DLL Initialization Failed} The application failed to initialize because the window station is shutting down.",
            NT_STATUS_DRIVER_UNABLE_TO_LOAD => "{Unable to Load Device Driver} %hs device driver could not be loaded. Error Status was 0x%x.",
            NT_STATUS_DFS_UNAVAILABLE => "DFS is unavailable on the contacted server.",
            NT_STATUS_VOLUME_DISMOUNTED => "An operation was attempted to a volume after it was dismounted.",
            NT_STATUS_WX86_INTERNAL_ERROR => "An internal error occurred in the Win32 x86 emulation subsystem.",
            NT_STATUS_WX86_FLOAT_STACK_CHECK => "Win32 x86 emulation subsystem floating-point stack check.",
            NT_STATUS_VALIDATE_CONTINUE => "The validation process needs to continue on to the next step.",
            NT_STATUS_NO_MATCH => "There was no match for the specified key in the index.",
            NT_STATUS_NO_MORE_MATCHES => "There are no more matches for the current index enumeration.",
            NT_STATUS_NOT_A_REPARSE_POINT => "The NTFS file or directory is not a reparse point.",
            NT_STATUS_IO_REPARSE_TAG_INVALID => "The Windows I/O reparse tag passed for the NTFS reparse point is invalid.",
            NT_STATUS_IO_REPARSE_TAG_MISMATCH => "The Windows I/O reparse tag does not match the one that is in the NTFS reparse point.",
            NT_STATUS_IO_REPARSE_DATA_INVALID => "The user data passed for the NTFS reparse point is invalid.",
            NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED => "The layered file system driver for this I/O tag did not handle it when needed.",
            NT_STATUS_REPARSE_POINT_NOT_RESOLVED => "The NTFS symbolic link could not be resolved even though the initial file name is valid.",
            NT_STATUS_DIRECTORY_IS_A_REPARSE_POINT => "The NTFS directory is a reparse point.",
            NT_STATUS_RANGE_LIST_CONFLICT => "The range could not be added to the range list because of a conflict.",
            NT_STATUS_SOURCE_ELEMENT_EMPTY => "The specified medium changer source element contains no media.",
            NT_STATUS_DESTINATION_ELEMENT_FULL => "The specified medium changer destination element already contains media.",
            NT_STATUS_ILLEGAL_ELEMENT_ADDRESS => "The specified medium changer element does not exist.",
            NT_STATUS_MAGAZINE_NOT_PRESENT => "The specified element is contained in a magazine that is no longer present.",
            NT_STATUS_REINITIALIZATION_NEEDED => "The device requires re-initialization due to hardware errors.",
            NT_STATUS_ENCRYPTION_FAILED => "The file encryption attempt failed.",
            NT_STATUS_DECRYPTION_FAILED => "The file decryption attempt failed.",
            NT_STATUS_RANGE_NOT_FOUND => "The specified range could not be found in the range list.",
            NT_STATUS_NO_RECOVERY_POLICY => "There is no encryption recovery policy configured for this system.",
            NT_STATUS_NO_EFS => "The required encryption driver is not loaded for this system.",
            NT_STATUS_WRONG_EFS => "The file was encrypted with a different encryption driver than is currently loaded.",
            NT_STATUS_NO_USER_KEYS => "There are no EFS keys defined for the user.",
            NT_STATUS_FILE_NOT_ENCRYPTED => "The specified file is not encrypted.",
            NT_STATUS_NOT_EXPORT_FORMAT => "The specified file is not in the defined EFS export format.",
            NT_STATUS_FILE_ENCRYPTED => "The specified file is encrypted and the user does not have the ability to decrypt it.",
            NT_STATUS_WMI_GUID_NOT_FOUND => "The GUID passed was not recognized as valid by a WMI data provider.",
            NT_STATUS_WMI_INSTANCE_NOT_FOUND => "The instance name passed was not recognized as valid by a WMI data provider.",
            NT_STATUS_WMI_ITEMID_NOT_FOUND => "The data item ID passed was not recognized as valid by a WMI data provider.",
            NT_STATUS_WMI_TRY_AGAIN => "The WMI request could not be completed and should be retried.",
            NT_STATUS_SHARED_POLICY => "The policy object is shared and can only be modified at the root.",
            NT_STATUS_POLICY_OBJECT_NOT_FOUND => "The policy object does not exist when it should.",
            NT_STATUS_POLICY_ONLY_IN_DS => "The requested policy information only lives in the Ds.",
            NT_STATUS_VOLUME_NOT_UPGRADED => "The volume must be upgraded to enable this feature.",
            NT_STATUS_REMOTE_STORAGE_NOT_ACTIVE => "The remote storage service is not operational at this time.",
            NT_STATUS_REMOTE_STORAGE_MEDIA_ERROR => "The remote storage service encountered a media error.",
            NT_STATUS_NO_TRACKING_SERVICE => "The tracking (workstation) service is not running.",
            NT_STATUS_SERVER_SID_MISMATCH => "The server process is running under a SID that is different from the SID that is required by client.",
            NT_STATUS_DS_NO_ATTRIBUTE_OR_VALUE => "The specified directory service attribute or value does not exist.",
            NT_STATUS_DS_INVALID_ATTRIBUTE_SYNTAX => "The attribute syntax specified to the directory service is invalid.",
            NT_STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED => "The attribute type specified to the directory service is not defined.",
            NT_STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS => "The specified directory service attribute or value already exists.",
            NT_STATUS_DS_BUSY => "The directory service is busy.",
            NT_STATUS_DS_UNAVAILABLE => "The directory service is unavailable.",
            NT_STATUS_DS_NO_RIDS_ALLOCATED => "The directory service was unable to allocate a relative identifier.",
            NT_STATUS_DS_NO_MORE_RIDS => "The directory service has exhausted the pool of relative identifiers.",
            NT_STATUS_DS_INCORRECT_ROLE_OWNER => "The requested operation could not be performed because the directory service is not the master for that type of operation.",
            NT_STATUS_DS_RIDMGR_INIT_ERROR => "The directory service was unable to initialize the subsystem that allocates relative identifiers.",
            NT_STATUS_DS_OBJ_CLASS_VIOLATION => "The requested operation did not satisfy one or more constraints that are associated with the class of the object.",
            NT_STATUS_DS_CANT_ON_NON_LEAF => "The directory service can perform the requested operation only on a leaf object.",
            NT_STATUS_DS_CANT_ON_RDN => "The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object.",
            NT_STATUS_DS_CANT_MOD_OBJ_CLASS => "The directory service detected an attempt to modify the object class of an object.",
            NT_STATUS_DS_CROSS_DOM_MOVE_FAILED => "An error occurred while performing a cross domain move operation.",
            NT_STATUS_DS_GC_NOT_AVAILABLE => "Unable to contact the global catalog server.",
            NT_STATUS_DIRECTORY_SERVICE_REQUIRED => "The requested operation requires a directory service, and none was available.",
            NT_STATUS_REPARSE_ATTRIBUTE_CONFLICT => "The reparse attribute cannot be set because it is incompatible with an existing attribute.",
            NT_STATUS_CANT_ENABLE_DENY_ONLY => "A group marked \"use for deny only\" cannot be enabled.",
            NT_STATUS_FLOAT_MULTIPLE_FAULTS => "{EXCEPTION} Multiple floating-point faults.",
            NT_STATUS_FLOAT_MULTIPLE_TRAPS => "{EXCEPTION} Multiple floating-point traps.",
            NT_STATUS_DEVICE_REMOVED => "The device has been removed.",
            NT_STATUS_JOURNAL_DELETE_IN_PROGRESS => "The volume change journal is being deleted.",
            NT_STATUS_JOURNAL_NOT_ACTIVE => "The volume change journal is not active.",
            NT_STATUS_NOINTERFACE => "The requested interface is not supported.",
            NT_STATUS_DS_ADMIN_LIMIT_EXCEEDED => "A directory service resource limit has been exceeded.",
            NT_STATUS_DRIVER_FAILED_SLEEP => "{System Standby Failed} The driver %hs does not support standby mode. Updating this driver allows the system to go to standby mode.",
            NT_STATUS_MUTUAL_AUTHENTICATION_FAILED => "Mutual Authentication failed. The server password is out of date at the domain controller.",
            NT_STATUS_CORRUPT_SYSTEM_FILE => "The system file %1 has become corrupt and has been replaced.",
            NT_STATUS_DATATYPE_MISALIGNMENT_ERROR => "{EXCEPTION} Alignment Error A data type misalignment error was detected in a load or store instruction.",
            NT_STATUS_WMI_READ_ONLY => "The WMI data item or data block is read-only.",
            NT_STATUS_WMI_SET_FAILURE => "The WMI data item or data block could not be changed.",
            NT_STATUS_COMMITMENT_MINIMUM => "{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications might be denied. For more information, see Help.",
            NT_STATUS_REG_NAT_CONSUMPTION => "{EXCEPTION} Register NaT consumption faults. A NaT value is consumed on a non-speculative instruction.",
            NT_STATUS_TRANSPORT_FULL => "The transport element of the medium changer contains media, which is causing the operation to fail.",
            NT_STATUS_DS_SAM_INIT_FAILURE => "Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information.",
            NT_STATUS_ONLY_IF_CONNECTED => "This operation is supported only when you are connected to the server.",
            NT_STATUS_DS_SENSITIVE_GROUP_VIOLATION => "Only an administrator can modify the membership list of an administrative group.",
            NT_STATUS_PNP_RESTART_ENUMERATION => "A device was removed so enumeration must be restarted.",
            NT_STATUS_JOURNAL_ENTRY_DELETED => "The journal entry has been deleted from the journal.",
            NT_STATUS_DS_CANT_MOD_PRIMARYGROUPID => "Cannot change the primary group ID of a domain controller account.",
            NT_STATUS_SYSTEM_IMAGE_BAD_SIGNATURE => "{Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down.",
            NT_STATUS_PNP_REBOOT_REQUIRED => "The device will not start without a reboot.",
            NT_STATUS_POWER_STATE_INVALID => "The power state of the current device cannot support this request.",
            NT_STATUS_DS_INVALID_GROUP_TYPE => "The specified group type is invalid.",
            NT_STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN => "In a mixed domain, no nesting of a global group if the group is security enabled.",
            NT_STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN => "In a mixed domain, cannot nest local groups with other local groups, if the group is security enabled.",
            NT_STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER => "A global group cannot have a local group as a member.",
            NT_STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER => "A global group cannot have a universal group as a member.",
            NT_STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER => "A universal group cannot have a local group as a member.",
            NT_STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER => "A global group cannot have a cross-domain member.",
            NT_STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER => "A local group cannot have another cross-domain local group as a member.",
            NT_STATUS_DS_HAVE_PRIMARY_MEMBERS => "Cannot change to a security-disabled group because primary members are in this group.",
            NT_STATUS_WMI_NOT_SUPPORTED => "The WMI operation is not supported by the data block or method.",
            NT_STATUS_INSUFFICIENT_POWER => "There is not enough power to complete the requested operation.",
            NT_STATUS_SAM_NEED_BOOTKEY_PASSWORD => "The Security Accounts Manager needs to get the boot password.",
            NT_STATUS_SAM_NEED_BOOTKEY_FLOPPY => "The Security Accounts Manager needs to get the boot key from the floppy disk.",
            NT_STATUS_DS_CANT_START => "The directory service cannot start.",
            NT_STATUS_DS_INIT_FAILURE => "The directory service could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information.",
            NT_STATUS_SAM_INIT_FAILURE => "The Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Safe Mode. Check the event log for more detailed information.",
            NT_STATUS_DS_GC_REQUIRED => "The requested operation can be performed only on a global catalog server.",
            NT_STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY => "A local group can only be a member of other local groups in the same domain.",
            NT_STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS => "Foreign security principals cannot be members of universal groups.",
            NT_STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED => "Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.",
            NT_STATUS_CURRENT_DOMAIN_NOT_ALLOWED => "This operation cannot be performed on the current domain.",
            NT_STATUS_CANNOT_MAKE => "The directory or file cannot be created.",
            NT_STATUS_SYSTEM_SHUTDOWN => "The system is in the process of shutting down.",
            NT_STATUS_DS_INIT_FAILURE_CONSOLE => "Directory Services could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further.",
            NT_STATUS_DS_SAM_INIT_FAILURE_CONSOLE => "Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further.",
            NT_STATUS_UNFINISHED_CONTEXT_DELETED => "A security context was deleted before the context was completed. This is considered a logon failure.",
            NT_STATUS_NO_TGT_REPLY => "The client is trying to negotiate a context and the server requires user-to-user but did not send a TGT reply.",
            NT_STATUS_OBJECTID_NOT_FOUND => "An object ID was not found in the file.",
            NT_STATUS_NO_IP_ADDRESSES => "Unable to accomplish the requested task because the local machine does not have any IP addresses.",
            NT_STATUS_WRONG_CREDENTIAL_HANDLE => "The supplied credential handle does not match the credential that is associated with the security context.",
            NT_STATUS_CRYPTO_SYSTEM_INVALID => "The crypto system or checksum function is invalid because a required function is unavailable.",
            NT_STATUS_MAX_REFERRALS_EXCEEDED => "The number of maximum ticket referrals has been exceeded.",
            NT_STATUS_MUST_BE_KDC => "The local machine must be a Kerberos KDC (domain controller) and it is not.",
            NT_STATUS_STRONG_CRYPTO_NOT_SUPPORTED => "The other end of the security negotiation requires strong crypto but it is not supported on the local machine.",
            NT_STATUS_TOO_MANY_PRINCIPALS => "The KDC reply contained more than one principal name.",
            NT_STATUS_NO_PA_DATA => "Expected to find PA data for a hint of what etype to use, but it was not found.",
            NT_STATUS_PKINIT_NAME_MISMATCH => "The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Contact your administrator.",
            NT_STATUS_SMARTCARD_LOGON_REQUIRED => "Smart card logon is required and was not used.",
            NT_STATUS_KDC_INVALID_REQUEST => "An invalid request was sent to the KDC.",
            NT_STATUS_KDC_UNABLE_TO_REFER => "The KDC was unable to generate a referral for the service requested.",
            NT_STATUS_KDC_UNKNOWN_ETYPE => "The encryption type requested is not supported by the KDC.",
            NT_STATUS_SHUTDOWN_IN_PROGRESS => "A system shutdown is in progress.",
            NT_STATUS_SERVER_SHUTDOWN_IN_PROGRESS => "The server machine is shutting down.",
            NT_STATUS_NOT_SUPPORTED_ON_SBS => "This operation is not supported on a computer running Windows Server 2003 operating system for Small Business Server.",
            NT_STATUS_WMI_GUID_DISCONNECTED => "The WMI GUID is no longer available.",
            NT_STATUS_WMI_ALREADY_DISABLED => "Collection or events for the WMI GUID is already disabled.",
            NT_STATUS_WMI_ALREADY_ENABLED => "Collection or events for the WMI GUID is already enabled.",
            NT_STATUS_MFT_TOO_FRAGMENTED => "The master file table on the volume is too fragmented to complete this operation.",
            NT_STATUS_COPY_PROTECTION_FAILURE => "Copy protection failure.",
            NT_STATUS_CSS_AUTHENTICATION_FAILURE => "Copy protection error—DVD CSS Authentication failed.",
            NT_STATUS_CSS_KEY_NOT_PRESENT => "Copy protection error—The specified sector does not contain a valid key.",
            NT_STATUS_CSS_KEY_NOT_ESTABLISHED => "Copy protection error—DVD session key not established.",
            NT_STATUS_CSS_SCRAMBLED_SECTOR => "Copy protection error—The read failed because the sector is encrypted.",
            NT_STATUS_CSS_REGION_MISMATCH => "Copy protection error—The region of the specified DVD does not correspond to the region setting of the drive.",
            NT_STATUS_CSS_RESETS_EXHAUSTED => "Copy protection error—The region setting of the drive might be permanent.",
            NT_STATUS_PKINIT_FAILURE => "The Kerberos protocol encountered an error while validating the KDC certificate during smart card logon. There is more information in the system event log.",
            NT_STATUS_SMARTCARD_SUBSYSTEM_FAILURE => "The Kerberos protocol encountered an error while attempting to use the smart card subsystem.",
            NT_STATUS_NO_KERB_KEY => "The target server does not have acceptable Kerberos credentials.",
            NT_STATUS_HOST_DOWN => "The transport determined that the remote system is down.",
            NT_STATUS_UNSUPPORTED_PREAUTH => "An unsupported pre-authentication mechanism was presented to the Kerberos package.",
            NT_STATUS_EFS_ALG_BLOB_TOO_BIG => "The encryption algorithm that is used on the source file needs a bigger key buffer than the one that is used on the destination file.",
            NT_STATUS_PORT_NOT_SET => "An attempt to remove a processes DebugPort was made, but a port was not already associated with the process.",
            NT_STATUS_DEBUGGER_INACTIVE => "An attempt to do an operation on a debug port failed because the port is in the process of being deleted.",
            NT_STATUS_DS_VERSION_CHECK_FAILURE => "This version of Windows is not compatible with the behavior version of the directory forest, domain, or domain controller.",
            NT_STATUS_AUDITING_DISABLED => "The specified event is currently not being audited.",
            NT_STATUS_PRENT4_MACHINE_ACCOUNT => "The machine account was created prior to Windows NT 4.0 operating system. The account needs to be recreated.",
            NT_STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER => "An account group cannot have a universal group as a member.",
            NT_STATUS_INVALID_IMAGE_WIN_32 => "The specified image file did not have the correct format; it appears to be a 32-bit Windows image.",
            NT_STATUS_INVALID_IMAGE_WIN_64 => "The specified image file did not have the correct format; it appears to be a 64-bit Windows image.",
            NT_STATUS_BAD_BINDINGS => "The client's supplied SSPI channel bindings were incorrect.",
            NT_STATUS_NETWORK_SESSION_EXPIRED => "The client session has expired; so the client must re-authenticate to continue accessing the remote resources.",
            NT_STATUS_APPHELP_BLOCK => "The AppHelp dialog box canceled; thus preventing the application from starting.",
            NT_STATUS_ALL_SIDS_FILTERED => "The SID filtering operation removed all SIDs.",
            NT_STATUS_NOT_SAFE_MODE_DRIVER => "The driver was not loaded because the system is starting in safe mode.",
            NT_STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT => "Access to %1 has been restricted by your Administrator by the default software restriction policy level.",
            NT_STATUS_ACCESS_DISABLED_BY_POLICY_PATH => "Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3.",
            NT_STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER => "Access to %1 has been restricted by your Administrator by software publisher policy.",
            NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER => "Access to %1 has been restricted by your Administrator by policy rule %2.",
            NT_STATUS_FAILED_DRIVER_ENTRY => "The driver was not loaded because it failed its initialization call.",
            NT_STATUS_DEVICE_ENUMERATION_ERROR => "The device encountered an error while applying power or reading the device configuration. This might be caused by a failure of your hardware or by a poor connection.",
            NT_STATUS_MOUNT_POINT_NOT_RESOLVED => "The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.",
            NT_STATUS_INVALID_DEVICE_OBJECT_PARAMETER => "The device object parameter is either not a valid device object or is not attached to the volume that is specified by the file name.",
            NT_STATUS_MCA_OCCURED => "A machine check error has occurred. Check the system event log for additional information.",
            NT_STATUS_DRIVER_BLOCKED_CRITICAL => "Driver %2 has been blocked from loading.",
            NT_STATUS_DRIVER_BLOCKED => "Driver %2 has been blocked from loading.",
            NT_STATUS_DRIVER_DATABASE_ERROR => "There was error [%2] processing the driver database.",
            NT_STATUS_SYSTEM_HIVE_TOO_LARGE => "System hive size has exceeded its limit.",
            NT_STATUS_INVALID_IMPORT_OF_NON_DLL => "A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.",
            NT_STATUS_NO_SECRETS => "The local account store does not contain secret material for the specified account.",
            NT_STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY => "Access to %1 has been restricted by your Administrator by policy rule %2.",
            NT_STATUS_FAILED_STACK_SWITCH => "The system was not able to allocate enough memory to perform a stack switch.",
            NT_STATUS_HEAP_CORRUPTION => "A heap has been corrupted.",
            NT_STATUS_SMARTCARD_WRONG_PIN => "An incorrect PIN was presented to the smart card.",
            NT_STATUS_SMARTCARD_CARD_BLOCKED => "The smart card is blocked.",
            NT_STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED => "No PIN was presented to the smart card.",
            NT_STATUS_SMARTCARD_NO_CARD => "No smart card is available.",
            NT_STATUS_SMARTCARD_NO_KEY_CONTAINER => "The requested key container does not exist on the smart card.",
            NT_STATUS_SMARTCARD_NO_CERTIFICATE => "The requested certificate does not exist on the smart card.",
            NT_STATUS_SMARTCARD_NO_KEYSET => "The requested keyset does not exist.",
            NT_STATUS_SMARTCARD_IO_ERROR => "A communication error with the smart card has been detected.",
            NT_STATUS_DOWNGRADE_DETECTED => "The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.",
            NT_STATUS_SMARTCARD_CERT_REVOKED => "The smart card certificate used for authentication has been revoked. Contact your system administrator. There might be additional information in the event log.",
            NT_STATUS_ISSUING_CA_UNTRUSTED => "An untrusted certificate authority was detected while processing the smart card certificate that is used for authentication. Contact your system administrator.",
            NT_STATUS_REVOCATION_OFFLINE_C => "The revocation status of the smart card certificate that is used for authentication could not be determined. Contact your system administrator.",
            NT_STATUS_PKINIT_CLIENT_FAILURE => "The smart card certificate used for authentication was not trusted. Contact your system administrator.",
            NT_STATUS_SMARTCARD_CERT_EXPIRED => "The smart card certificate used for authentication has expired. Contact your system administrator.",
            NT_STATUS_DRIVER_FAILED_PRIOR_UNLOAD => "The driver could not be loaded because a previous version of the driver is still in memory.",
            NT_STATUS_SMARTCARD_SILENT_CONTEXT => "The smart card provider could not perform the action because the context was acquired as silent.",
            NT_STATUS_PER_USER_TRUST_QUOTA_EXCEEDED => "The delegated trust creation quota of the current user has been exceeded.",
            NT_STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED => "The total delegated trust creation quota has been exceeded.",
            NT_STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED => "The delegated trust deletion quota of the current user has been exceeded.",
            NT_STATUS_DS_NAME_NOT_UNIQUE => "The requested name already exists as a unique identifier.",
            NT_STATUS_DS_DUPLICATE_ID_FOUND => "The requested object has a non-unique identifier and cannot be retrieved.",
            NT_STATUS_DS_GROUP_CONVERSION_ERROR => "The group cannot be converted due to attribute restrictions on the requested group type.",
            NT_STATUS_VOLSNAP_PREPARE_HIBERNATE => "{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.",
            NT_STATUS_USER2USER_REQUIRED => "Kerberos sub-protocol User2User is required.",
            NT_STATUS_STACK_BUFFER_OVERRUN => "The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.",
            NT_STATUS_NO_S4U_PROT_SUPPORT => "The Kerberos subsystem encountered an error. A service for user protocol request was made against a domain controller which does not support service for user.",
            NT_STATUS_CROSSREALM_DELEGATION_FAILURE => "An attempt was made by this server to make a Kerberos constrained delegation request for a target that is outside the server realm. This action is not supported and the resulting error indicates a misconfiguration on the allowed-to-delegate-to list for this server. Contact your administrator.",
            NT_STATUS_REVOCATION_OFFLINE_KDC => "The revocation status of the domain controller certificate used for smart card authentication could not be determined. There is additional information in the system event log. Contact your system administrator.",
            NT_STATUS_ISSUING_CA_UNTRUSTED_KDC => "An untrusted certificate authority was detected while processing the domain controller certificate used for authentication. There is additional information in the system event log. Contact your system administrator.",
            NT_STATUS_KDC_CERT_EXPIRED => "The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log.",
            NT_STATUS_KDC_CERT_REVOKED => "The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log.",
            NT_STATUS_PARAMETER_QUOTA_EXCEEDED => "Data present in one of the parameters is more than the function can operate on.",
            NT_STATUS_HIBERNATION_FAILURE => "The system has failed to hibernate (The error code is %hs). Hibernation will be disabled until the system is restarted.",
            NT_STATUS_DELAY_LOAD_FAILED => "An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.",
            NT_STATUS_AUTHENTICATION_FIREWALL_FAILED => "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.",
            NT_STATUS_VDM_DISALLOWED => "%hs is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator.",
            NT_STATUS_HUNG_DISPLAY_DRIVER_THREAD => "{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft.",
            NT_STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE => "The Desktop heap encountered an error while allocating session memory. There is more information in the system event log.",
            NT_STATUS_INVALID_CRUNTIME_PARAMETER => "An invalid parameter was passed to a C runtime function.",
            NT_STATUS_NTLM_BLOCKED => "The authentication failed because NTLM was blocked.",
            NT_STATUS_DS_SRC_SID_EXISTS_IN_FOREST => "The source object's SID already exists in destination forest.",
            NT_STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST => "The domain name of the trusted domain already exists in the forest.",
            NT_STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST => "The flat name of the trusted domain already exists in the forest.",
            NT_STATUS_INVALID_USER_PRINCIPAL_NAME => "The User Principal Name (UPN) is invalid.",
            NT_STATUS_ASSERTION_FAILURE => "There has been an assertion failure.",
            NT_STATUS_VERIFIER_STOP => "Application verifier has found an error in the current process.",
            NT_STATUS_CALLBACK_POP_STACK => "A user mode unwind is in progress.",
            NT_STATUS_INCOMPATIBLE_DRIVER_BLOCKED => "%2 has been blocked from loading due to incompatibility with this system. Contact your software vendor for a compatible version of the driver.",
            NT_STATUS_HIVE_UNLOADED => "Illegal operation attempted on a registry key which has already been unloaded.",
            NT_STATUS_COMPRESSION_DISABLED => "Compression is disabled for this volume.",
            NT_STATUS_FILE_SYSTEM_LIMITATION => "The requested operation could not be completed due to a file system limitation.",
            NT_STATUS_INVALID_IMAGE_HASH => "The hash for image %hs cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering.",
            NT_STATUS_NOT_CAPABLE => "The implementation is not capable of performing the request.",
            NT_STATUS_REQUEST_OUT_OF_SEQUENCE => "The requested operation is out of order with respect to other operations.",
            NT_STATUS_IMPLEMENTATION_LIMIT => "An operation attempted to exceed an implementation-defined limit.",
            NT_STATUS_ELEVATION_REQUIRED => "The requested operation requires elevation.",
            NT_STATUS_NO_SECURITY_CONTEXT => "The required security context does not exist.",
            NT_STATUS_PKU2U_CERT_FAILURE => "The PKU2U protocol encountered an error while attempting to utilize the associated certificates.",
            NT_STATUS_BEYOND_VDL => "The operation was attempted beyond the valid data length of the file.",
            NT_STATUS_ENCOUNTERED_WRITE_IN_PROGRESS => "The attempted write operation encountered a write already in progress for some portion of the range.",
            NT_STATUS_PTE_CHANGED => "The page fault mappings changed in the middle of processing a fault so the operation must be retried.",
            NT_STATUS_PURGE_FAILED => "The attempt to purge this file from memory failed to purge some or all the data from memory.",
            NT_STATUS_CRED_REQUIRES_CONFIRMATION => "The requested credential requires confirmation.",
            NT_STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE => "The remote server sent an invalid response for a file being opened with Client Side Encryption.",
            NT_STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER => "Client Side Encryption is not supported by the remote server even though it claims to support it.",
            NT_STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE => "File is encrypted and should be opened in Client Side Encryption mode.",
            NT_STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE => "A new encrypted file is being created and a $EFS needs to be provided.",
            NT_STATUS_CS_ENCRYPTION_FILE_NOT_CSE => "The SMB client requested a CSE FSCTL on a non-CSE file.",
            NT_STATUS_INVALID_LABEL => "Indicates a particular Security ID cannot be assigned as the label of an object.",
            NT_STATUS_DRIVER_PROCESS_TERMINATED => "The process hosting the driver for this device has terminated.",
            NT_STATUS_AMBIGUOUS_SYSTEM_DEVICE => "The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria.",
            NT_STATUS_SYSTEM_DEVICE_NOT_FOUND => "The requested system device cannot be found.",
            NT_STATUS_RESTART_BOOT_APPLICATION => "This boot application must be restarted.",
            NT_STATUS_INSUFFICIENT_NVRAM_RESOURCES => "Insufficient NVRAM resources exist to complete the API.  A reboot might be required.",
            NT_STATUS_NO_RANGES_PROCESSED => "No ranges for the specified operation were able to be processed.",
            NT_STATUS_DEVICE_FEATURE_NOT_SUPPORTED => "The storage device does not support Offload Write.",
            NT_STATUS_DEVICE_UNREACHABLE => "Data cannot be moved because the source device cannot communicate with the destination device.",
            NT_STATUS_INVALID_TOKEN => "The token representing the data is invalid or expired.",
            NT_STATUS_SERVER_UNAVAILABLE => "The file server is temporarily unavailable.",
            NT_STATUS_INVALID_TASK_NAME => "The specified task name is invalid.",
            NT_STATUS_INVALID_TASK_INDEX => "The specified task index is invalid.",
            NT_STATUS_THREAD_ALREADY_IN_TASK => "The specified thread is already joining a task.",
            NT_STATUS_CALLBACK_BYPASS => "A callback has requested to bypass native code.",
            NT_STATUS_FAIL_FAST_EXCEPTION => "A fail fast exception occurred. Exception handlers will not be invoked and the process will be terminated immediately.",
            NT_STATUS_IMAGE_CERT_REVOKED => "Windows cannot verify the digital signature for this file. The signing certificate for this file has been revoked.",
            NT_STATUS_PORT_CLOSED => "The ALPC port is closed.",
            NT_STATUS_MESSAGE_LOST => "The ALPC message requested is no longer available.",
            NT_STATUS_INVALID_MESSAGE => "The ALPC message supplied is invalid.",
            NT_STATUS_REQUEST_CANCELED => "The ALPC message has been canceled.",
            NT_STATUS_RECURSIVE_DISPATCH => "Invalid recursive dispatch attempt.",
            NT_STATUS_LPC_RECEIVE_BUFFER_EXPECTED => "No receive buffer has been supplied in a synchronous request.",
            NT_STATUS_LPC_INVALID_CONNECTION_USAGE => "The connection port is used in an invalid context.",
            NT_STATUS_LPC_REQUESTS_NOT_ALLOWED => "The ALPC port does not accept new request messages.",
            NT_STATUS_RESOURCE_IN_USE => "The resource requested is already in use.",
            NT_STATUS_HARDWARE_MEMORY_ERROR => "The hardware has reported an uncorrectable memory error.",
            NT_STATUS_THREADPOOL_HANDLE_EXCEPTION => "Status 0x%08x was returned, waiting on handle 0x%x for wait 0x%p, in waiter 0x%p.",
            NT_STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED => "After a callback to 0x%p(0x%p), a completion call to Set event(0x%p) failed with status 0x%08x.",
            NT_STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED => "After a callback to 0x%p(0x%p), a completion call to ReleaseSemaphore(0x%p, %d) failed with status 0x%08x.",
            NT_STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED => "After a callback to 0x%p(0x%p), a completion call to ReleaseMutex(%p) failed with status 0x%08x.",
            NT_STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED => "After a callback to 0x%p(0x%p), a completion call to FreeLibrary(%p) failed with status 0x%08x.",
            NT_STATUS_THREADPOOL_RELEASED_DURING_OPERATION => "The thread pool 0x%p was released while a thread was posting a callback to 0x%p(0x%p) to it.",
            NT_STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING => "A thread pool worker thread is impersonating a client, after a callback to 0x%p(0x%p). This is unexpected, indicating that the callback is missing a call to revert the impersonation.",
            NT_STATUS_APC_RETURNED_WHILE_IMPERSONATING => "A thread pool worker thread is impersonating a client, after executing an APC. This is unexpected, indicating that the APC is missing a call to revert the impersonation.",
            NT_STATUS_PROCESS_IS_PROTECTED => "Either the target process, or the target thread's containing process, is a protected process.",
            NT_STATUS_MCA_EXCEPTION => "A thread is getting dispatched with MCA EXCEPTION because of MCA.",
            NT_STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE => "The client certificate account mapping is not unique.",
            NT_STATUS_SYMLINK_CLASS_DISABLED => "The symbolic link cannot be followed because its type is disabled.",
            NT_STATUS_INVALID_IDN_NORMALIZATION => "Indicates that the specified string is not valid for IDN normalization.",
            NT_STATUS_NO_UNICODE_TRANSLATION => "No mapping for the Unicode character exists in the target multi-byte code page.",
            NT_STATUS_ALREADY_REGISTERED => "The provided callback is already registered.",
            NT_STATUS_CONTEXT_MISMATCH => "The provided context did not match the target.",
            NT_STATUS_PORT_ALREADY_HAS_COMPLETION_LIST => "The specified port already has a completion list.",
            NT_STATUS_CALLBACK_RETURNED_THREAD_PRIORITY => "A threadpool worker thread entered a callback at thread base priority 0x%x and exited at priority 0x%x. This is unexpected, indicating that the callback missed restoring the priority.",
            NT_STATUS_INVALID_THREAD => "An invalid thread, handle %p, is specified for this operation. Possibly, a threadpool worker thread was specified.",
            NT_STATUS_CALLBACK_RETURNED_TRANSACTION => "A threadpool worker thread entered a callback, which left transaction state. This is unexpected, indicating that the callback missed clearing the transaction.",
            NT_STATUS_CALLBACK_RETURNED_LDR_LOCK => "A threadpool worker thread entered a callback, which left the loader lock held. This is unexpected, indicating that the callback missed releasing the lock.",
            NT_STATUS_CALLBACK_RETURNED_LANG => "A threadpool worker thread entered a callback, which left with preferred languages set. This is unexpected, indicating that the callback missed clearing them.",
            NT_STATUS_CALLBACK_RETURNED_PRI_BACK => "A threadpool worker thread entered a callback, which left with background priorities set. This is unexpected, indicating that the callback missed restoring the original priorities.",
            NT_STATUS_DISK_REPAIR_DISABLED => "The attempted operation required self healing to be enabled.",
            NT_STATUS_DS_DOMAIN_RENAME_IN_PROGRESS => "The directory service cannot perform the requested operation because a domain rename operation is in progress.",
            NT_STATUS_DISK_QUOTA_EXCEEDED => "An operation failed because the storage quota was exceeded.",
            NT_STATUS_CONTENT_BLOCKED => "An operation failed because the content was blocked.",
            NT_STATUS_BAD_CLUSTERS => "The operation could not be completed due to bad clusters on disk.",
            NT_STATUS_VOLUME_DIRTY => "The operation could not be completed because the volume is dirty. Please run the Chkdsk utility and try again.",
            NT_STATUS_FILE_CHECKED_OUT => "This file is checked out or locked for editing by another user.",
            NT_STATUS_CHECKOUT_REQUIRED => "The file must be checked out before saving changes.",
            NT_STATUS_BAD_FILE_TYPE => "The file type being saved or retrieved has been blocked.",
            NT_STATUS_FILE_TOO_LARGE => "The file size exceeds the limit allowed and cannot be saved.",
            NT_STATUS_FORMS_AUTH_REQUIRED => "Access Denied. Before opening files in this location, you must first browse to the e.g. site and select the option to log on automatically.",
            NT_STATUS_VIRUS_INFECTED => "The operation did not complete successfully because the file contains a virus.",
            NT_STATUS_VIRUS_DELETED => "This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location.",
            NT_STATUS_BAD_MCFG_TABLE => "The resources required for this device conflict with the MCFG table.",
            NT_STATUS_CANNOT_BREAK_OPLOCK => "The operation did not complete successfully because it would cause an oplock to be broken. The caller has requested that existing oplocks not be broken.",
            NT_STATUS_WOW_ASSERTION => "WOW Assertion Error.",
            NT_STATUS_INVALID_SIGNATURE => "The cryptographic signature is invalid.",
            NT_STATUS_HMAC_NOT_SUPPORTED => "The cryptographic provider does not support HMAC.",
            NT_STATUS_IPSEC_QUEUE_OVERFLOW => "The IPsec queue overflowed.",
            NT_STATUS_ND_QUEUE_OVERFLOW => "The neighbor discovery queue overflowed.",
            NT_STATUS_HOPLIMIT_EXCEEDED => "An Internet Control Message Protocol (ICMP) hop limit exceeded error was received.",
            NT_STATUS_PROTOCOL_NOT_SUPPORTED => "The protocol is not installed on the local machine.",
            NT_STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED => "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error might be caused by network connectivity issues. Try to save this file elsewhere.",
            NT_STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR => "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere.",
            NT_STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR => "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error might be caused if the device has been removed or the media is write-protected.",
            NT_STATUS_XML_PARSE_ERROR => "Windows was unable to parse the requested XML data.",
            NT_STATUS_XMLDSIG_ERROR => "An error was encountered while processing an XML digital signature.",
            NT_STATUS_WRONG_COMPARTMENT => "This indicates that the caller made the connection request in the wrong routing compartment.",
            NT_STATUS_AUTHIP_FAILURE => "This indicates that there was an AuthIP failure when attempting to connect to the remote host.",
            NT_STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS => "OID mapped groups cannot have members.",
            NT_STATUS_DS_OID_NOT_FOUND => "The specified OID cannot be found.",
            NT_STATUS_HASH_NOT_SUPPORTED => "Hash generation for the specified version and hash type is not enabled on server.",
            NT_STATUS_HASH_NOT_PRESENT => "The hash requests is not present or not up to date with the current file contents.",
            NT_STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED => "A file system filter on the server has not opted in for Offload Read support.",
            NT_STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED => "A file system filter on the server has not opted in for Offload Write support.",
            NT_STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED => "Offload read operations cannot be performed on: Compressed files Sparse files Encrypted files File system metadata files",
            NT_STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED => "Offload write operations cannot be performed on: Compressed files Sparse files Encrypted files File system metadata files",
            NT_STATUS_DBG_NO_STATE_CHANGE => "The debugger did not perform a state change.",
            NT_STATUS_DBG_APP_NOT_IDLE => "The debugger found that the application is not idle.",
            NT_STATUS_RPC_INVALID_STRING_BINDING => "The string binding is invalid.",
            NT_STATUS_RPC_WRONG_KIND_OF_BINDING => "The binding handle is not the correct type.",
            NT_STATUS_RPC_INVALID_BINDING => "The binding handle is invalid.",
            NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED => "The RPC protocol sequence is not supported.",
            NT_STATUS_RPC_INVALID_RPC_PROTSEQ => "The RPC protocol sequence is invalid.",
            NT_STATUS_RPC_INVALID_STRING_UUID => "The string UUID is invalid.",
            NT_STATUS_RPC_INVALID_ENDPOINT_FORMAT => "The endpoint format is invalid.",
            NT_STATUS_RPC_INVALID_NET_ADDR => "The network address is invalid.",
            NT_STATUS_RPC_NO_ENDPOINT_FOUND => "No endpoint was found.",
            NT_STATUS_RPC_INVALID_TIMEOUT => "The time-out value is invalid.",
            NT_STATUS_RPC_OBJECT_NOT_FOUND => "The object UUID was not found.",
            NT_STATUS_RPC_ALREADY_REGISTERED => "The object UUID has already been registered.",
            NT_STATUS_RPC_TYPE_ALREADY_REGISTERED => "The type UUID has already been registered.",
            NT_STATUS_RPC_ALREADY_LISTENING => "The RPC server is already listening.",
            NT_STATUS_RPC_NO_PROTSEQS_REGISTERED => "No protocol sequences have been registered.",
            NT_STATUS_RPC_NOT_LISTENING => "The RPC server is not listening.",
            NT_STATUS_RPC_UNKNOWN_MGR_TYPE => "The manager type is unknown.",
            NT_STATUS_RPC_UNKNOWN_IF => "The interface is unknown.",
            NT_STATUS_RPC_NO_BINDINGS => "There are no bindings.",
            NT_STATUS_RPC_NO_PROTSEQS => "There are no protocol sequences.",
            NT_STATUS_RPC_CANT_CREATE_ENDPOINT => "The endpoint cannot be created.",
            NT_STATUS_RPC_OUT_OF_RESOURCES => "Insufficient resources are available to complete this operation.",
            NT_STATUS_RPC_SERVER_UNAVAILABLE => "The RPC server is unavailable.",
            NT_STATUS_RPC_SERVER_TOO_BUSY => "The RPC server is too busy to complete this operation.",
            NT_STATUS_RPC_INVALID_NETWORK_OPTIONS => "The network options are invalid.",
            NT_STATUS_RPC_NO_CALL_ACTIVE => "No RPCs are active on this thread.",
            NT_STATUS_RPC_CALL_FAILED => "The RPC failed.",
            NT_STATUS_RPC_CALL_FAILED_DNE => "The RPC failed and did not execute.",
            NT_STATUS_RPC_PROTOCOL_ERROR => "An RPC protocol error occurred.",
            NT_STATUS_RPC_UNSUPPORTED_TRANS_SYN => "The RPC server does not support the transfer syntax.",
            NT_STATUS_RPC_UNSUPPORTED_TYPE => "The type UUID is not supported.",
            NT_STATUS_RPC_INVALID_TAG => "The tag is invalid.",
            NT_STATUS_RPC_INVALID_BOUND => "The array bounds are invalid.",
            NT_STATUS_RPC_NO_ENTRY_NAME => "The binding does not contain an entry name.",
            NT_STATUS_RPC_INVALID_NAME_SYNTAX => "The name syntax is invalid.",
            NT_STATUS_RPC_UNSUPPORTED_NAME_SYNTAX => "The name syntax is not supported.",
            NT_STATUS_RPC_UUID_NO_ADDRESS => "No network address is available to construct a UUID.",
            NT_STATUS_RPC_DUPLICATE_ENDPOINT => "The endpoint is a duplicate.",
            NT_STATUS_RPC_UNKNOWN_AUTHN_TYPE => "The authentication type is unknown.",
            NT_STATUS_RPC_MAX_CALLS_TOO_SMALL => "The maximum number of calls is too small.",
            NT_STATUS_RPC_STRING_TOO_LONG => "The string is too long.",
            NT_STATUS_RPC_PROTSEQ_NOT_FOUND => "The RPC protocol sequence was not found.",
            NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE => "The procedure number is out of range.",
            NT_STATUS_RPC_BINDING_HAS_NO_AUTH => "The binding does not contain any authentication information.",
            NT_STATUS_RPC_UNKNOWN_AUTHN_SERVICE => "The authentication service is unknown.",
            NT_STATUS_RPC_UNKNOWN_AUTHN_LEVEL => "The authentication level is unknown.",
            NT_STATUS_RPC_INVALID_AUTH_IDENTITY => "The security context is invalid.",
            NT_STATUS_RPC_UNKNOWN_AUTHZ_SERVICE => "The authorization service is unknown.",
            NT_STATUS_EPT_INVALID_ENTRY => "The entry is invalid.",
            NT_STATUS_EPT_CANT_PERFORM_OP => "The operation cannot be performed.",
            NT_STATUS_EPT_NOT_REGISTERED => "No more endpoints are available from the endpoint mapper.",
            NT_STATUS_RPC_NOTHING_TO_EXPORT => "No interfaces have been exported.",
            NT_STATUS_RPC_INCOMPLETE_NAME => "The entry name is incomplete.",
            NT_STATUS_RPC_INVALID_VERS_OPTION => "The version option is invalid.",
            NT_STATUS_RPC_NO_MORE_MEMBERS => "There are no more members.",
            NT_STATUS_RPC_NOT_ALL_OBJS_UNEXPORTED => "There is nothing to unexport.",
            NT_STATUS_RPC_INTERFACE_NOT_FOUND => "The interface was not found.",
            NT_STATUS_RPC_ENTRY_ALREADY_EXISTS => "The entry already exists.",
            NT_STATUS_RPC_ENTRY_NOT_FOUND => "The entry was not found.",
            NT_STATUS_RPC_NAME_SERVICE_UNAVAILABLE => "The name service is unavailable.",
            NT_STATUS_RPC_INVALID_NAF_ID => "The network address family is invalid.",
            NT_STATUS_RPC_CANNOT_SUPPORT => "The requested operation is not supported.",
            NT_STATUS_RPC_NO_CONTEXT_AVAILABLE => "No security context is available to allow impersonation.",
            NT_STATUS_RPC_INTERNAL_ERROR => "An internal error occurred in the RPC.",
            NT_STATUS_RPC_ZERO_DIVIDE => "The RPC server attempted to divide an integer by zero.",
            NT_STATUS_RPC_ADDRESS_ERROR => "An addressing error occurred in the RPC server.",
            NT_STATUS_RPC_FP_DIV_ZERO => "A floating point operation at the RPC server caused a divide by zero.",
            NT_STATUS_RPC_FP_UNDERFLOW => "A floating point underflow occurred at the RPC server.",
            NT_STATUS_RPC_FP_OVERFLOW => "A floating point overflow occurred at the RPC server.",
            NT_STATUS_RPC_CALL_IN_PROGRESS => "An RPC is already in progress for this thread.",
            NT_STATUS_RPC_NO_MORE_BINDINGS => "There are no more bindings.",
            NT_STATUS_RPC_GROUP_MEMBER_NOT_FOUND => "The group member was not found.",
            NT_STATUS_EPT_CANT_CREATE => "The endpoint mapper database entry could not be created.",
            NT_STATUS_RPC_INVALID_OBJECT => "The object UUID is the nil UUID.",
            NT_STATUS_RPC_NO_INTERFACES => "No interfaces have been registered.",
            NT_STATUS_RPC_CALL_CANCELLED => "The RPC was canceled.",
            NT_STATUS_RPC_BINDING_INCOMPLETE => "The binding handle does not contain all the required information.",
            NT_STATUS_RPC_COMM_FAILURE => "A communications failure occurred during an RPC.",
            NT_STATUS_RPC_UNSUPPORTED_AUTHN_LEVEL => "The requested authentication level is not supported.",
            NT_STATUS_RPC_NO_PRINC_NAME => "No principal name was registered.",
            NT_STATUS_RPC_NOT_RPC_ERROR => "The error specified is not a valid Windows RPC error code.",
            NT_STATUS_RPC_SEC_PKG_ERROR => "A security package-specific error occurred.",
            NT_STATUS_RPC_NOT_CANCELLED => "The thread was not canceled.",
            NT_STATUS_RPC_INVALID_ASYNC_HANDLE => "Invalid asynchronous RPC handle.",
            NT_STATUS_RPC_INVALID_ASYNC_CALL => "Invalid asynchronous RPC call handle for this operation.",
            NT_STATUS_RPC_PROXY_ACCESS_DENIED => "Access to the HTTP proxy is denied.",
            NT_STATUS_RPC_NO_MORE_ENTRIES => "The list of RPC servers available for auto-handle binding has been exhausted.",
            NT_STATUS_RPC_SS_CHAR_TRANS_OPEN_FAIL => "The file designated by DCERPCCHARTRANS cannot be opened.",
            NT_STATUS_RPC_SS_CHAR_TRANS_SHORT_FILE => "The file containing the character translation table has fewer than 512 bytes.",
            NT_STATUS_RPC_SS_IN_NULL_CONTEXT => "A null context handle is passed as an [in] parameter.",
            NT_STATUS_RPC_SS_CONTEXT_MISMATCH => "The context handle does not match any known context handles.",
            NT_STATUS_RPC_SS_CONTEXT_DAMAGED => "The context handle changed during a call.",
            NT_STATUS_RPC_SS_HANDLES_MISMATCH => "The binding handles passed to an RPC do not match.",
            NT_STATUS_RPC_SS_CANNOT_GET_CALL_HANDLE => "The stub is unable to get the call handle.",
            NT_STATUS_RPC_NULL_REF_POINTER => "A null reference pointer was passed to the stub.",
            NT_STATUS_RPC_ENUM_VALUE_OUT_OF_RANGE => "The enumeration value is out of range.",
            NT_STATUS_RPC_BYTE_COUNT_TOO_SMALL => "The byte count is too small.",
            NT_STATUS_RPC_BAD_STUB_DATA => "The stub received bad data.",
            NT_STATUS_RPC_INVALID_ES_ACTION => "Invalid operation on the encoding/decoding handle.",
            NT_STATUS_RPC_WRONG_ES_VERSION => "Incompatible version of the serializing package.",
            NT_STATUS_RPC_WRONG_STUB_VERSION => "Incompatible version of the RPC stub.",
            NT_STATUS_RPC_INVALID_PIPE_OBJECT => "The RPC pipe object is invalid or corrupt.",
            NT_STATUS_RPC_INVALID_PIPE_OPERATION => "An invalid operation was attempted on an RPC pipe object.",
            NT_STATUS_RPC_WRONG_PIPE_VERSION => "Unsupported RPC pipe version.",
            NT_STATUS_RPC_PIPE_CLOSED => "The RPC pipe object has already been closed.",
            NT_STATUS_RPC_PIPE_DISCIPLINE_ERROR => "The RPC call completed before all pipes were processed.",
            NT_STATUS_RPC_PIPE_EMPTY => "No more data is available from the RPC pipe.",
            NT_STATUS_PNP_BAD_MPS_TABLE => "A device is missing in the system BIOS MPS table. This device will not be used. Contact your system vendor for a system BIOS update.",
            NT_STATUS_PNP_TRANSLATION_FAILED => "A translator failed to translate resources.",
            NT_STATUS_PNP_IRQ_TRANSLATION_FAILED => "An IRQ translator failed to translate resources.",
            NT_STATUS_PNP_INVALID_ID => "Driver %2 returned an invalid ID for a child device (%3).",
            NT_STATUS_IO_REISSUE_AS_CACHED => "Reissue the given operation as a cached I/O operation",
            NT_STATUS_CTX_WINSTATION_NAME_INVALID => "Session name %1 is invalid.",
            NT_STATUS_CTX_INVALID_PD => "The protocol driver %1 is invalid.",
            NT_STATUS_CTX_PD_NOT_FOUND => "The protocol driver %1 was not found in the system path.",
            NT_STATUS_CTX_CLOSE_PENDING => "A close operation is pending on the terminal connection.",
            NT_STATUS_CTX_NO_OUTBUF => "No free output buffers are available.",
            NT_STATUS_CTX_MODEM_INF_NOT_FOUND => "The MODEM.INF file was not found.",
            NT_STATUS_CTX_INVALID_MODEMNAME => "The modem (%1) was not found in the MODEM.INF file.",
            NT_STATUS_CTX_RESPONSE_ERROR => "The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem.",
            NT_STATUS_CTX_MODEM_RESPONSE_TIMEOUT => "The modem did not respond to the command sent to it. Verify that the modem cable is properly attached and the modem is turned on.",
            NT_STATUS_CTX_MODEM_RESPONSE_NO_CARRIER => "Carrier detection has failed or the carrier has been dropped due to disconnection.",
            NT_STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE => "A dial tone was not detected within the required time. Verify that the phone cable is properly attached and functional.",
            NT_STATUS_CTX_MODEM_RESPONSE_BUSY => "A busy signal was detected at a remote site on callback.",
            NT_STATUS_CTX_MODEM_RESPONSE_VOICE => "A voice was detected at a remote site on callback.",
            NT_STATUS_CTX_TD_ERROR => "Transport driver error.",
            NT_STATUS_CTX_LICENSE_CLIENT_INVALID => "The client you are using is not licensed to use this system. Your logon request is denied.",
            NT_STATUS_CTX_LICENSE_NOT_AVAILABLE => "The system has reached its licensed logon limit. Try again later.",
            NT_STATUS_CTX_LICENSE_EXPIRED => "The system license has expired. Your logon request is denied.",
            NT_STATUS_CTX_WINSTATION_NOT_FOUND => "The specified session cannot be found.",
            NT_STATUS_CTX_WINSTATION_NAME_COLLISION => "The specified session name is already in use.",
            NT_STATUS_CTX_WINSTATION_BUSY => "The requested operation cannot be completed because the terminal connection is currently processing a connect, disconnect, reset, or delete operation.",
            NT_STATUS_CTX_BAD_VIDEO_MODE => "An attempt has been made to connect to a session whose video mode is not supported by the current client.",
            NT_STATUS_CTX_GRAPHICS_INVALID => "The application attempted to enable DOS graphics mode. DOS graphics mode is not supported.",
            NT_STATUS_CTX_NOT_CONSOLE => "The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access.",
            NT_STATUS_CTX_CLIENT_QUERY_TIMEOUT => "The client failed to respond to the server connect message.",
            NT_STATUS_CTX_CONSOLE_DISCONNECT => "Disconnecting the console session is not supported.",
            NT_STATUS_CTX_CONSOLE_CONNECT => "Reconnecting a disconnected session to the console is not supported.",
            NT_STATUS_CTX_SHADOW_DENIED => "The request to control another session remotely was denied.",
            NT_STATUS_CTX_WINSTATION_ACCESS_DENIED => "A process has requested access to a session, but has not been granted those access rights.",
            NT_STATUS_CTX_INVALID_WD => "The terminal connection driver %1 is invalid.",
            NT_STATUS_CTX_WD_NOT_FOUND => "The terminal connection driver %1 was not found in the system path.",
            NT_STATUS_CTX_SHADOW_INVALID => "The requested session cannot be controlled remotely. You cannot control your own session, a session that is trying to control your session, a session that has no user logged on, or other sessions from the console.",
            NT_STATUS_CTX_SHADOW_DISABLED => "The requested session is not configured to allow remote control.",
            NT_STATUS_RDP_PROTOCOL_ERROR => "The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client.",
            NT_STATUS_CTX_CLIENT_LICENSE_NOT_SET => "Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal client. Contact your system administrator for help in entering a valid, unique license number for this terminal server client. Click OK to continue.",
            NT_STATUS_CTX_CLIENT_LICENSE_IN_USE => "Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Contact your system administrator to obtain a new copy of the terminal server client with a valid, unique license number. Click OK to continue.",
            NT_STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE => "The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.",
            NT_STATUS_CTX_SHADOW_NOT_RUNNING => "Remote control could not be terminated because the specified session is not currently being remotely controlled.",
            NT_STATUS_CTX_LOGON_DISABLED => "Your interactive logon privilege has been disabled. Contact your system administrator.",
            NT_STATUS_CTX_SECURITY_LAYER_ERROR => "The terminal server security layer detected an error in the protocol stream and has disconnected the client.",
            NT_STATUS_TS_INCOMPATIBLE_SESSIONS => "The target session is incompatible with the current session.",
            NT_STATUS_MUI_FILE_NOT_FOUND => "The resource loader failed to find an MUI file.",
            NT_STATUS_MUI_INVALID_FILE => "The resource loader failed to load an MUI file because the file failed to pass validation.",
            NT_STATUS_MUI_INVALID_RC_CONFIG => "The RC manifest is corrupted with garbage data, is an unsupported version, or is missing a required item.",
            NT_STATUS_MUI_INVALID_LOCALE_NAME => "The RC manifest has an invalid culture name.",
            NT_STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME => "The RC manifest has and invalid ultimate fallback name.",
            NT_STATUS_MUI_FILE_NOT_LOADED => "The resource loader cache does not have a loaded MUI entry.",
            NT_STATUS_RESOURCE_ENUM_USER_STOP => "The user stopped resource enumeration.",
            NT_STATUS_CLUSTER_INVALID_NODE => "The cluster node is not valid.",
            NT_STATUS_CLUSTER_NODE_EXISTS => "The cluster node already exists.",
            NT_STATUS_CLUSTER_JOIN_IN_PROGRESS => "A node is in the process of joining the cluster.",
            NT_STATUS_CLUSTER_NODE_NOT_FOUND => "The cluster node was not found.",
            NT_STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND => "The cluster local node information was not found.",
            NT_STATUS_CLUSTER_NETWORK_EXISTS => "The cluster network already exists.",
            NT_STATUS_CLUSTER_NETWORK_NOT_FOUND => "The cluster network was not found.",
            NT_STATUS_CLUSTER_NETINTERFACE_EXISTS => "The cluster network interface already exists.",
            NT_STATUS_CLUSTER_NETINTERFACE_NOT_FOUND => "The cluster network interface was not found.",
            NT_STATUS_CLUSTER_INVALID_REQUEST => "The cluster request is not valid for this object.",
            NT_STATUS_CLUSTER_INVALID_NETWORK_PROVIDER => "The cluster network provider is not valid.",
            NT_STATUS_CLUSTER_NODE_DOWN => "The cluster node is down.",
            NT_STATUS_CLUSTER_NODE_UNREACHABLE => "The cluster node is not reachable.",
            NT_STATUS_CLUSTER_NODE_NOT_MEMBER => "The cluster node is not a member of the cluster.",
            NT_STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS => "A cluster join operation is not in progress.",
            NT_STATUS_CLUSTER_INVALID_NETWORK => "The cluster network is not valid.",
            NT_STATUS_CLUSTER_NO_NET_ADAPTERS => "No network adapters are available.",
            NT_STATUS_CLUSTER_NODE_UP => "The cluster node is up.",
            NT_STATUS_CLUSTER_NODE_PAUSED => "The cluster node is paused.",
            NT_STATUS_CLUSTER_NODE_NOT_PAUSED => "The cluster node is not paused.",
            NT_STATUS_CLUSTER_NO_SECURITY_CONTEXT => "No cluster security context is available.",
            NT_STATUS_CLUSTER_NETWORK_NOT_INTERNAL => "The cluster network is not configured for internal cluster communication.",
            NT_STATUS_CLUSTER_POISONED => "The cluster node has been poisoned.",
            NT_STATUS_ACPI_INVALID_OPCODE => "An attempt was made to run an invalid AML opcode.",
            NT_STATUS_ACPI_STACK_OVERFLOW => "The AML interpreter stack has overflowed.",
            NT_STATUS_ACPI_ASSERT_FAILED => "An inconsistent state has occurred.",
            NT_STATUS_ACPI_INVALID_INDEX => "An attempt was made to access an array outside its bounds.",
            NT_STATUS_ACPI_INVALID_ARGUMENT => "A required argument was not specified.",
            NT_STATUS_ACPI_FATAL => "A fatal error has occurred.",
            NT_STATUS_ACPI_INVALID_SUPERNAME => "An invalid SuperName was specified.",
            NT_STATUS_ACPI_INVALID_ARGTYPE => "An argument with an incorrect type was specified.",
            NT_STATUS_ACPI_INVALID_OBJTYPE => "An object with an incorrect type was specified.",
            NT_STATUS_ACPI_INVALID_TARGETTYPE => "A target with an incorrect type was specified.",
            NT_STATUS_ACPI_INCORRECT_ARGUMENT_COUNT => "An incorrect number of arguments was specified.",
            NT_STATUS_ACPI_ADDRESS_NOT_MAPPED => "An address failed to translate.",
            NT_STATUS_ACPI_INVALID_EVENTTYPE => "An incorrect event type was specified.",
            NT_STATUS_ACPI_HANDLER_COLLISION => "A handler for the target already exists.",
            NT_STATUS_ACPI_INVALID_DATA => "Invalid data for the target was specified.",
            NT_STATUS_ACPI_INVALID_REGION => "An invalid region for the target was specified.",
            NT_STATUS_ACPI_INVALID_ACCESS_SIZE => "An attempt was made to access a field outside the defined range.",
            NT_STATUS_ACPI_ACQUIRE_GLOBAL_LOCK => "The global system lock could not be acquired.",
            NT_STATUS_ACPI_ALREADY_INITIALIZED => "An attempt was made to reinitialize the ACPI subsystem.",
            NT_STATUS_ACPI_NOT_INITIALIZED => "The ACPI subsystem has not been initialized.",
            NT_STATUS_ACPI_INVALID_MUTEX_LEVEL => "An incorrect mutex was specified.",
            NT_STATUS_ACPI_MUTEX_NOT_OWNED => "The mutex is not currently owned.",
            NT_STATUS_ACPI_MUTEX_NOT_OWNER => "An attempt was made to access the mutex by a process that was not the owner.",
            NT_STATUS_ACPI_RS_ACCESS => "An error occurred during an access to region space.",
            NT_STATUS_ACPI_INVALID_TABLE => "An attempt was made to use an incorrect table.",
            NT_STATUS_ACPI_REG_HANDLER_FAILED => "The registration of an ACPI event failed.",
            NT_STATUS_ACPI_POWER_REQUEST_FAILED => "An ACPI power object failed to transition state.",
            NT_STATUS_SXS_SECTION_NOT_FOUND => "The requested section is not present in the activation context.",
            NT_STATUS_SXS_CANT_GEN_ACTCTX => "Windows was unble to process the application binding information. Refer to the system event log for further information.",
            NT_STATUS_SXS_INVALID_ACTCTXDATA_FORMAT => "The application binding data format is invalid.",
            NT_STATUS_SXS_ASSEMBLY_NOT_FOUND => "The referenced assembly is not installed on the system.",
            NT_STATUS_SXS_MANIFEST_FORMAT_ERROR => "The manifest file does not begin with the required tag and format information.",
            NT_STATUS_SXS_MANIFEST_PARSE_ERROR => "The manifest file contains one or more syntax errors.",
            NT_STATUS_SXS_ACTIVATION_CONTEXT_DISABLED => "The application attempted to activate a disabled activation context.",
            NT_STATUS_SXS_KEY_NOT_FOUND => "The requested lookup key was not found in any active activation context.",
            NT_STATUS_SXS_VERSION_CONFLICT => "A component version required by the application conflicts with another component version that is already active.",
            NT_STATUS_SXS_WRONG_SECTION_TYPE => "The type requested activation context section does not match the query API used.",
            NT_STATUS_SXS_THREAD_QUERIES_DISABLED => "Lack of system resources has required isolated activation to be disabled for the current thread of execution.",
            NT_STATUS_SXS_ASSEMBLY_MISSING => "The referenced assembly could not be found.",
            NT_STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET => "An attempt to set the process default activation context failed because the process default activation context was already set.",
            NT_STATUS_SXS_EARLY_DEACTIVATION => "The activation context being deactivated is not the most recently activated one.",
            NT_STATUS_SXS_INVALID_DEACTIVATION => "The activation context being deactivated is not active for the current thread of execution.",
            NT_STATUS_SXS_MULTIPLE_DEACTIVATION => "The activation context being deactivated has already been deactivated.",
            NT_STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY => "The activation context of the system default assembly could not be generated.",
            NT_STATUS_SXS_PROCESS_TERMINATION_REQUESTED => "A component used by the isolation facility has requested that the process be terminated.",
            NT_STATUS_SXS_CORRUPT_ACTIVATION_STACK => "The activation context activation stack for the running thread of execution is corrupt.",
            NT_STATUS_SXS_CORRUPTION => "The application isolation metadata for this process or thread has become corrupt.",
            NT_STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE => "The value of an attribute in an identity is not within the legal range.",
            NT_STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME => "The name of an attribute in an identity is not within the legal range.",
            NT_STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE => "An identity contains two definitions for the same attribute.",
            NT_STATUS_SXS_IDENTITY_PARSE_ERROR => "The identity string is malformed. This might be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value.",
            NT_STATUS_SXS_COMPONENT_STORE_CORRUPT => "The component store has become corrupted.",
            NT_STATUS_SXS_FILE_HASH_MISMATCH => "A component's file does not match the verification information present in the component manifest.",
            NT_STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT => "The identities of the manifests are identical, but their contents are different.",
            NT_STATUS_SXS_IDENTITIES_DIFFERENT => "The component identities are different.",
            NT_STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT => "The assembly is not a deployment.",
            NT_STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY => "The file is not a part of the assembly.",
            NT_STATUS_ADVANCED_INSTALLER_FAILED => "An advanced installer failed during setup or servicing.",
            NT_STATUS_XML_ENCODING_MISMATCH => "The character encoding in the XML declaration did not match the encoding used in the document.",
            NT_STATUS_SXS_MANIFEST_TOO_BIG => "The size of the manifest exceeds the maximum allowed.",
            NT_STATUS_SXS_SETTING_NOT_REGISTERED => "The setting is not registered.",
            NT_STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE => "One or more required transaction members are not present.",
            NT_STATUS_SMI_PRIMITIVE_INSTALLER_FAILED => "The SMI primitive installer failed during setup or servicing.",
            NT_STATUS_GENERIC_COMMAND_FAILED => "A generic command executable returned a result that indicates failure.",
            NT_STATUS_SXS_FILE_HASH_MISSING => "A component is missing file verification information in its manifest.",
            NT_STATUS_TRANSACTIONAL_CONFLICT => "The function attempted to use a name that is reserved for use by another transaction.",
            NT_STATUS_INVALID_TRANSACTION => "The transaction handle associated with this operation is invalid.",
            NT_STATUS_TRANSACTION_NOT_ACTIVE => "The requested operation was made in the context of a transaction that is no longer active.",
            NT_STATUS_TM_INITIALIZATION_FAILED => "The transaction manager was unable to be successfully initialized. Transacted operations are not supported.",
            NT_STATUS_RM_NOT_ACTIVE => "Transaction support within the specified file system resource manager was not started or was shut down due to an error.",
            NT_STATUS_RM_METADATA_CORRUPT => "The metadata of the resource manager has been corrupted. The resource manager will not function.",
            NT_STATUS_TRANSACTION_NOT_JOINED => "The resource manager attempted to prepare a transaction that it has not successfully joined.",
            NT_STATUS_DIRECTORY_NOT_RM => "The specified directory does not contain a file system resource manager.",
            NT_STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE => "The remote server or share does not support transacted file operations.",
            NT_STATUS_LOG_RESIZE_INVALID_SIZE => "The requested log size for the file system resource manager is invalid.",
            NT_STATUS_REMOTE_FILE_VERSION_MISMATCH => "The remote server sent mismatching version number or Fid for a file opened with transactions.",
            NT_STATUS_CRM_PROTOCOL_ALREADY_EXISTS => "The resource manager tried to register a protocol that already exists.",
            NT_STATUS_TRANSACTION_PROPAGATION_FAILED => "The attempt to propagate the transaction failed.",
            NT_STATUS_CRM_PROTOCOL_NOT_FOUND => "The requested propagation protocol was not registered as a CRM.",
            NT_STATUS_TRANSACTION_SUPERIOR_EXISTS => "The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed.",
            NT_STATUS_TRANSACTION_REQUEST_NOT_VALID => "The requested operation is not valid on the transaction object in its current state.",
            NT_STATUS_TRANSACTION_NOT_REQUESTED => "The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller.",
            NT_STATUS_TRANSACTION_ALREADY_ABORTED => "It is too late to perform the requested operation, because the transaction has already been aborted.",
            NT_STATUS_TRANSACTION_ALREADY_COMMITTED => "It is too late to perform the requested operation, because the transaction has already been committed.",
            NT_STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER => "The buffer passed in to NtPushTransaction or NtPullTransaction is not in a valid format.",
            NT_STATUS_CURRENT_TRANSACTION_NOT_VALID => "The current transaction context associated with the thread is not a valid handle to a transaction object.",
            NT_STATUS_LOG_GROWTH_FAILED => "An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log.",
            NT_STATUS_OBJECT_NO_LONGER_EXISTS => "The object (file, stream, or link) that corresponds to the handle has been deleted by a transaction savepoint rollback.",
            NT_STATUS_STREAM_MINIVERSION_NOT_FOUND => "The specified file miniversion was not found for this transacted file open.",
            NT_STATUS_STREAM_MINIVERSION_NOT_VALID => "The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback.",
            NT_STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION => "A miniversion can be opened only in the context of the transaction that created it.",
            NT_STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT => "It is not possible to open a miniversion with modify access.",
            NT_STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS => "It is not possible to create any more miniversions for this stream.",
            NT_STATUS_HANDLE_NO_LONGER_VALID => "The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file or an open handle when the transaction ended or rolled back to savepoint.",
            NT_STATUS_LOG_CORRUPTION_DETECTED => "The log data is corrupt.",
            NT_STATUS_RM_DISCONNECTED => "The transaction outcome is unavailable because the resource manager responsible for it is disconnected.",
            NT_STATUS_ENLISTMENT_NOT_SUPERIOR => "The request was rejected because the enlistment in question is not a superior enlistment.",
            NT_STATUS_FILE_IDENTITY_NOT_PERSISTENT => "The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction.",
            NT_STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY => "The operation cannot be performed because another transaction is depending on this property not changing.",
            NT_STATUS_CANT_CROSS_RM_BOUNDARY => "The operation would involve a single file with two transactional resource managers and is, therefore, not allowed.",
            NT_STATUS_TXF_DIR_NOT_EMPTY => "The $Txf directory must be empty for this operation to succeed.",
            NT_STATUS_INDOUBT_TRANSACTIONS_EXIST => "The operation would leave a transactional resource manager in an inconsistent state and is therefore not allowed.",
            NT_STATUS_TM_VOLATILE => "The operation could not be completed because the transaction manager does not have a log.",
            NT_STATUS_ROLLBACK_TIMER_EXPIRED => "A rollback could not be scheduled because a previously scheduled rollback has already executed or been queued for execution.",
            NT_STATUS_TXF_ATTRIBUTE_CORRUPT => "The transactional metadata attribute on the file or directory %hs is corrupt and unreadable.",
            NT_STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION => "The encryption operation could not be completed because a transaction is active.",
            NT_STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED => "This object is not allowed to be opened in a transaction.",
            NT_STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE => "Memory mapping (creating a mapped section) a remote file under a transaction is not supported.",
            NT_STATUS_TRANSACTION_REQUIRED_PROMOTION => "Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it.",
            NT_STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION => "This file is open for modification in an unresolved transaction and can be opened for execute only by a transacted reader.",
            NT_STATUS_TRANSACTIONS_NOT_FROZEN => "The request to thaw frozen transactions was ignored because transactions were not previously frozen.",
            NT_STATUS_TRANSACTION_FREEZE_IN_PROGRESS => "Transactions cannot be frozen because a freeze is already in progress.",
            NT_STATUS_NOT_SNAPSHOT_VOLUME => "The target volume is not a snapshot volume. This operation is valid only on a volume mounted as a snapshot.",
            NT_STATUS_NO_SAVEPOINT_WITH_OPEN_FILES => "The savepoint operation failed because files are open on the transaction, which is not permitted.",
            NT_STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION => "The sparse operation could not be completed because a transaction is active on the file.",
            NT_STATUS_TM_IDENTITY_MISMATCH => "The call to create a transaction manager object failed because the Tm Identity that is stored in the log file does not match the Tm Identity that was passed in as an argument.",
            NT_STATUS_FLOATED_SECTION => "I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data.",
            NT_STATUS_CANNOT_ACCEPT_TRANSACTED_WORK => "The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources.",
            NT_STATUS_CANNOT_ABORT_TRANSACTIONS => "The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down.",
            NT_STATUS_TRANSACTION_NOT_FOUND => "The specified transaction was unable to be opened because it was not found.",
            NT_STATUS_RESOURCEMANAGER_NOT_FOUND => "The specified resource manager was unable to be opened because it was not found.",
            NT_STATUS_ENLISTMENT_NOT_FOUND => "The specified enlistment was unable to be opened because it was not found.",
            NT_STATUS_TRANSACTIONMANAGER_NOT_FOUND => "The specified transaction manager was unable to be opened because it was not found.",
            NT_STATUS_TRANSACTIONMANAGER_NOT_ONLINE => "The specified resource manager was unable to create an enlistment because its associated transaction manager is not online.",
            NT_STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION => "The specified transaction manager was unable to create the objects contained in its log file in the Ob namespace. Therefore, the transaction manager was unable to recover.",
            NT_STATUS_TRANSACTION_NOT_ROOT => "The call to create a superior enlistment on this transaction object could not be completed because the transaction object specified for the enlistment is a subordinate branch of the transaction. Only the root of the transaction can be enlisted as a superior.",
            NT_STATUS_TRANSACTION_OBJECT_EXPIRED => "Because the associated transaction manager or resource manager has been closed, the handle is no longer valid.",
            NT_STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION => "The compression operation could not be completed because a transaction is active on the file.",
            NT_STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED => "The specified operation could not be performed on this superior enlistment because the enlistment was not created with the corresponding completion response in the NotificationMask.",
            NT_STATUS_TRANSACTION_RECORD_TOO_LONG => "The specified operation could not be performed because the record to be logged was too long. This can occur because either there are too many enlistments on this transaction or the combined RecoveryInformation being logged on behalf of those enlistments is too long.",
            NT_STATUS_NO_LINK_TRACKING_IN_TRANSACTION => "The link-tracking operation could not be completed because a transaction is active.",
            NT_STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION => "This operation cannot be performed in a transaction.",
            NT_STATUS_TRANSACTION_INTEGRITY_VIOLATED => "The kernel transaction manager had to abort or forget the transaction because it blocked forward progress.",
            NT_STATUS_EXPIRED_HANDLE => "The handle is no longer properly associated with its transaction.  It might have been opened in a transactional resource manager that was subsequently forced to restart.  Please close the handle and open a new one.",
            NT_STATUS_TRANSACTION_NOT_ENLISTED => "The specified operation could not be performed because the resource manager is not enlisted in the transaction.",
            NT_STATUS_LOG_SECTOR_INVALID => "The log service found an invalid log sector.",
            NT_STATUS_LOG_SECTOR_PARITY_INVALID => "The log service encountered a log sector with invalid block parity.",
            NT_STATUS_LOG_SECTOR_REMAPPED => "The log service encountered a remapped log sector.",
            NT_STATUS_LOG_BLOCK_INCOMPLETE => "The log service encountered a partial or incomplete log block.",
            NT_STATUS_LOG_INVALID_RANGE => "The log service encountered an attempt to access data outside the active log range.",
            NT_STATUS_LOG_BLOCKS_EXHAUSTED => "The log service user-log marshaling buffers are exhausted.",
            NT_STATUS_LOG_READ_CONTEXT_INVALID => "The log service encountered an attempt to read from a marshaling area with an invalid read context.",
            NT_STATUS_LOG_RESTART_INVALID => "The log service encountered an invalid log restart area.",
            NT_STATUS_LOG_BLOCK_VERSION => "The log service encountered an invalid log block version.",
            NT_STATUS_LOG_BLOCK_INVALID => "The log service encountered an invalid log block.",
            NT_STATUS_LOG_READ_MODE_INVALID => "The log service encountered an attempt to read the log with an invalid read mode.",
            NT_STATUS_LOG_METADATA_CORRUPT => "The log service encountered a corrupted metadata file.",
            NT_STATUS_LOG_METADATA_INVALID => "The log service encountered a metadata file that could not be created by the log file system.",
            NT_STATUS_LOG_METADATA_INCONSISTENT => "The log service encountered a metadata file with inconsistent data.",
            NT_STATUS_LOG_RESERVATION_INVALID => "The log service encountered an attempt to erroneously allocate or dispose reservation space.",
            NT_STATUS_LOG_CANT_DELETE => "The log service cannot delete the log file or the file system container.",
            NT_STATUS_LOG_CONTAINER_LIMIT_EXCEEDED => "The log service has reached the maximum allowable containers allocated to a log file.",
            NT_STATUS_LOG_START_OF_LOG => "The log service has attempted to read or write backward past the start of the log.",
            NT_STATUS_LOG_POLICY_ALREADY_INSTALLED => "The log policy could not be installed because a policy of the same type is already present.",
            NT_STATUS_LOG_POLICY_NOT_INSTALLED => "The log policy in question was not installed at the time of the request.",
            NT_STATUS_LOG_POLICY_INVALID => "The installed set of policies on the log is invalid.",
            NT_STATUS_LOG_POLICY_CONFLICT => "A policy on the log in question prevented the operation from completing.",
            NT_STATUS_LOG_PINNED_ARCHIVE_TAIL => "The log space cannot be reclaimed because the log is pinned by the archive tail.",
            NT_STATUS_LOG_RECORD_NONEXISTENT => "The log record is not a record in the log file.",
            NT_STATUS_LOG_RECORDS_RESERVED_INVALID => "The number of reserved log records or the adjustment of the number of reserved log records is invalid.",
            NT_STATUS_LOG_SPACE_RESERVED_INVALID => "The reserved log space or the adjustment of the log space is invalid.",
            NT_STATUS_LOG_TAIL_INVALID => "A new or existing archive tail or the base of the active log is invalid.",
            NT_STATUS_LOG_FULL => "The log space is exhausted.",
            NT_STATUS_LOG_MULTIPLEXED => "The log is multiplexed; no direct writes to the physical log are allowed.",
            NT_STATUS_LOG_DEDICATED => "The operation failed because the log is dedicated.",
            NT_STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS => "The operation requires an archive context.",
            NT_STATUS_LOG_ARCHIVE_IN_PROGRESS => "Log archival is in progress.",
            NT_STATUS_LOG_EPHEMERAL => "The operation requires a nonephemeral log, but the log is ephemeral.",
            NT_STATUS_LOG_NOT_ENOUGH_CONTAINERS => "The log must have at least two containers before it can be read from or written to.",
            NT_STATUS_LOG_CLIENT_ALREADY_REGISTERED => "A log client has already registered on the stream.",
            NT_STATUS_LOG_CLIENT_NOT_REGISTERED => "A log client has not been registered on the stream.",
            NT_STATUS_LOG_FULL_HANDLER_IN_PROGRESS => "A request has already been made to handle the log full condition.",
            NT_STATUS_LOG_CONTAINER_READ_FAILED => "The log service encountered an error when attempting to read from a log container.",
            NT_STATUS_LOG_CONTAINER_WRITE_FAILED => "The log service encountered an error when attempting to write to a log container.",
            NT_STATUS_LOG_CONTAINER_OPEN_FAILED => "The log service encountered an error when attempting to open a log container.",
            NT_STATUS_LOG_CONTAINER_STATE_INVALID => "The log service encountered an invalid container state when attempting a requested action.",
            NT_STATUS_LOG_STATE_INVALID => "The log service is not in the correct state to perform a requested action.",
            NT_STATUS_LOG_PINNED => "The log space cannot be reclaimed because the log is pinned.",
            NT_STATUS_LOG_METADATA_FLUSH_FAILED => "The log metadata flush failed.",
            NT_STATUS_LOG_INCONSISTENT_SECURITY => "Security on the log and its containers is inconsistent.",
            NT_STATUS_LOG_APPENDED_FLUSH_FAILED => "Records were appended to the log or reservation changes were made, but the log could not be flushed.",
            NT_STATUS_LOG_PINNED_RESERVATION => "The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available.",
            NT_STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD => "{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the computer, a dialog box will allow you to upload data about this failure to Microsoft.",
            NT_STATUS_FLT_NO_HANDLER_DEFINED => "A handler was not defined by the filter for this operation.",
            NT_STATUS_FLT_CONTEXT_ALREADY_DEFINED => "A context is already defined for this object.",
            NT_STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST => "Asynchronous requests are not valid for this operation.",
            NT_STATUS_FLT_DISALLOW_FAST_IO => "This is an internal error code used by the filter manager to determine if a fast I/O operation should be forced down the input/output request packet (IRP) path. Minifilters should never return this value.",
            NT_STATUS_FLT_INVALID_NAME_REQUEST => "An invalid name request was made. The name requested cannot be retrieved at this time.",
            NT_STATUS_FLT_NOT_SAFE_TO_POST_OPERATION => "Posting this operation to a worker thread for further processing is not safe at this time because it could lead to a system deadlock.",
            NT_STATUS_FLT_NOT_INITIALIZED => "The Filter Manager was not initialized when a filter tried to register. Make sure that the Filter Manager is loaded as a driver.",
            NT_STATUS_FLT_FILTER_NOT_READY => "The filter is not ready for attachment to volumes because it has not finished initializing (FltStartFiltering has not been called).",
            NT_STATUS_FLT_POST_OPERATION_CLEANUP => "The filter must clean up any operation-specific context at this time because it is being removed from the system before the operation is completed by the lower drivers.",
            NT_STATUS_FLT_INTERNAL_ERROR => "The Filter Manager had an internal error from which it cannot recover; therefore, the operation has failed. This is usually the result of a filter returning an invalid value from a pre-operation callback.",
            NT_STATUS_FLT_DELETING_OBJECT => "The object specified for this action is in the process of being deleted; therefore, the action requested cannot be completed at this time.",
            NT_STATUS_FLT_MUST_BE_NONPAGED_POOL => "A nonpaged pool must be used for this type of context.",
            NT_STATUS_FLT_DUPLICATE_ENTRY => "A duplicate handler definition has been provided for an operation.",
            NT_STATUS_FLT_CBDQ_DISABLED => "The callback data queue has been disabled.",
            NT_STATUS_FLT_DO_NOT_ATTACH => "Do not attach the filter to the volume at this time.",
            NT_STATUS_FLT_DO_NOT_DETACH => "Do not detach the filter from the volume at this time.",
            NT_STATUS_FLT_INSTANCE_ALTITUDE_COLLISION => "An instance already exists at this altitude on the volume specified.",
            NT_STATUS_FLT_INSTANCE_NAME_COLLISION => "An instance already exists with this name on the volume specified.",
            NT_STATUS_FLT_FILTER_NOT_FOUND => "The system could not find the filter specified.",
            NT_STATUS_FLT_VOLUME_NOT_FOUND => "The system could not find the volume specified.",
            NT_STATUS_FLT_INSTANCE_NOT_FOUND => "The system could not find the instance specified.",
            NT_STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND => "No registered context allocation definition was found for the given request.",
            NT_STATUS_FLT_INVALID_CONTEXT_REGISTRATION => "An invalid parameter was specified during context registration.",
            NT_STATUS_FLT_NAME_CACHE_MISS => "The name requested was not found in the Filter Manager name cache and could not be retrieved from the file system.",
            NT_STATUS_FLT_NO_DEVICE_OBJECT => "The requested device object does not exist for the given volume.",
            NT_STATUS_FLT_VOLUME_ALREADY_MOUNTED => "The specified volume is already mounted.",
            NT_STATUS_FLT_ALREADY_ENLISTED => "The specified transaction context is already enlisted in a transaction.",
            NT_STATUS_FLT_CONTEXT_ALREADY_LINKED => "The specified context is already attached to another object.",
            NT_STATUS_FLT_NO_WAITER_FOR_REPLY => "No waiter is present for the filter's reply to this message.",
            NT_STATUS_MONITOR_NO_DESCRIPTOR => "A monitor descriptor could not be obtained.",
            NT_STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT => "This release does not support the format of the obtained monitor descriptor.",
            NT_STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM => "The checksum of the obtained monitor descriptor is invalid.",
            NT_STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK => "The monitor descriptor contains an invalid standard timing block.",
            NT_STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED => "WMI data-block registration failed for one of the MSMonitorClass WMI subclasses.",
            NT_STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK => "The provided monitor descriptor block is either corrupted or does not contain the monitor's detailed serial number.",
            NT_STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK => "The provided monitor descriptor block is either corrupted or does not contain the monitor's user-friendly name.",
            NT_STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA => "There is no monitor descriptor data at the specified (offset or size) region.",
            NT_STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK => "The monitor descriptor contains an invalid detailed timing block.",
            NT_STATUS_MONITOR_INVALID_MANUFACTURE_DATE => "Monitor descriptor contains invalid manufacture date.",
            NT_STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER => "Exclusive mode ownership is needed to create an unmanaged primary allocation.",
            NT_STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER => "The driver needs more DMA buffer space to complete the requested operation.",
            NT_STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER => "The specified display adapter handle is invalid.",
            NT_STATUS_GRAPHICS_ADAPTER_WAS_RESET => "The specified display adapter and all of its state have been reset.",
            NT_STATUS_GRAPHICS_INVALID_DRIVER_MODEL => "The driver stack does not match the expected driver model.",
            NT_STATUS_GRAPHICS_PRESENT_MODE_CHANGED => "Present happened but ended up into the changed desktop mode.",
            NT_STATUS_GRAPHICS_PRESENT_OCCLUDED => "Nothing to present due to desktop occlusion.",
            NT_STATUS_GRAPHICS_PRESENT_DENIED => "Not able to present due to denial of desktop access.",
            NT_STATUS_GRAPHICS_CANNOTCOLORCONVERT => "Not able to present with color conversion.",
            NT_STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED => "Present redirection is disabled (desktop windowing management subsystem is off).",
            NT_STATUS_GRAPHICS_PRESENT_UNOCCLUDED => "Previous exclusive VidPn source owner has released its ownership",
            NT_STATUS_GRAPHICS_NO_VIDEO_MEMORY => "Not enough video memory is available to complete the operation.",
            NT_STATUS_GRAPHICS_CANT_LOCK_MEMORY => "Could not probe and lock the underlying memory of an allocation.",
            NT_STATUS_GRAPHICS_ALLOCATION_BUSY => "The allocation is currently busy.",
            NT_STATUS_GRAPHICS_TOO_MANY_REFERENCES => "An object being referenced has already reached the maximum reference count and cannot be referenced further.",
            NT_STATUS_GRAPHICS_TRY_AGAIN_LATER => "A problem could not be solved due to an existing condition. Try again later.",
            NT_STATUS_GRAPHICS_TRY_AGAIN_NOW => "A problem could not be solved due to an existing condition. Try again now.",
            NT_STATUS_GRAPHICS_ALLOCATION_INVALID => "The allocation is invalid.",
            NT_STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE => "No more unswizzling apertures are currently available.",
            NT_STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED => "The current allocation cannot be unswizzled by an aperture.",
            NT_STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION => "The request failed because a pinned allocation cannot be evicted.",
            NT_STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE => "The allocation cannot be used from its current segment location for the specified operation.",
            NT_STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION => "A locked allocation cannot be used in the current command buffer.",
            NT_STATUS_GRAPHICS_ALLOCATION_CLOSED => "The allocation being referenced has been closed permanently.",
            NT_STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE => "An invalid allocation instance is being referenced.",
            NT_STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE => "An invalid allocation handle is being referenced.",
            NT_STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE => "The allocation being referenced does not belong to the current device.",
            NT_STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST => "The specified allocation lost its content.",
            NT_STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE => "A GPU exception was detected on the given device. The device cannot be scheduled.",
            NT_STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY => "The specified VidPN topology is invalid.",
            NT_STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED => "The specified VidPN topology is valid but is not supported by this model of the display adapter.",
            NT_STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED => "The specified VidPN topology is valid but is not currently supported by the display adapter due to allocation of its resources.",
            NT_STATUS_GRAPHICS_INVALID_VIDPN => "The specified VidPN handle is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE => "The specified video present source is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET => "The specified video present target is invalid.",
            NT_STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED => "The specified VidPN modality is not supported (for example, at least two of the pinned modes are not co-functional).",
            NT_STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET => "The specified VidPN source mode set is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET => "The specified VidPN target mode set is invalid.",
            NT_STATUS_GRAPHICS_INVALID_FREQUENCY => "The specified video signal frequency is invalid.",
            NT_STATUS_GRAPHICS_INVALID_ACTIVE_REGION => "The specified video signal active region is invalid.",
            NT_STATUS_GRAPHICS_INVALID_TOTAL_REGION => "The specified video signal total region is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE => "The specified video present source mode is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE => "The specified video present target mode is invalid.",
            NT_STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET => "The pinned mode must remain in the set on the VidPN's co-functional modality enumeration.",
            NT_STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY => "The specified video present path is already in the VidPN's topology.",
            NT_STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET => "The specified mode is already in the mode set.",
            NT_STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET => "The specified video present source set is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET => "The specified video present target set is invalid.",
            NT_STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET => "The specified video present source is already in the video present source set.",
            NT_STATUS_GRAPHICS_TARGET_ALREADY_IN_SET => "The specified video present target is already in the video present target set.",
            NT_STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH => "The specified VidPN present path is invalid.",
            NT_STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY => "The miniport has no recommendation for augmenting the specified VidPN's topology.",
            NT_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET => "The specified monitor frequency range set is invalid.",
            NT_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE => "The specified monitor frequency range is invalid.",
            NT_STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET => "The specified frequency range is not in the specified monitor frequency range set.",
            NT_STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET => "The specified frequency range is already in the specified monitor frequency range set.",
            NT_STATUS_GRAPHICS_STALE_MODESET => "The specified mode set is stale. Reacquire the new mode set.",
            NT_STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET => "The specified monitor source mode set is invalid.",
            NT_STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE => "The specified monitor source mode is invalid.",
            NT_STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN => "The miniport does not have a recommendation regarding the request to provide a functional VidPN given the current display adapter configuration.",
            NT_STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE => "The ID of the specified mode is being used by another mode in the set.",
            NT_STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION => "The system failed to determine a mode that is supported by both the display adapter and the monitor connected to it.",
            NT_STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES => "The number of video present targets must be greater than or equal to the number of video present sources.",
            NT_STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY => "The specified present path is not in the VidPN's topology.",
            NT_STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE => "The display adapter must have at least one video present source.",
            NT_STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET => "The display adapter must have at least one video present target.",
            NT_STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET => "The specified monitor descriptor set is invalid.",
            NT_STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR => "The specified monitor descriptor is invalid.",
            NT_STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET => "The specified descriptor is not in the specified monitor descriptor set.",
            NT_STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET => "The specified descriptor is already in the specified monitor descriptor set.",
            NT_STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE => "The ID of the specified monitor descriptor is being used by another descriptor in the set.",
            NT_STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE => "The specified video present target subset type is invalid.",
            NT_STATUS_GRAPHICS_RESOURCES_NOT_RELATED => "Two or more of the specified resources are not related to each other, as defined by the interface semantics.",
            NT_STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE => "The ID of the specified video present source is being used by another source in the set.",
            NT_STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE => "The ID of the specified video present target is being used by another target in the set.",
            NT_STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET => "The specified VidPN source cannot be used because there is no available VidPN target to connect it to.",
            NT_STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER => "The newly arrived monitor could not be associated with a display adapter.",
            NT_STATUS_GRAPHICS_NO_VIDPNMGR => "The particular display adapter does not have an associated VidPN manager.",
            NT_STATUS_GRAPHICS_NO_ACTIVE_VIDPN => "The VidPN manager of the particular display adapter does not have an active VidPN.",
            NT_STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY => "The specified VidPN topology is stale; obtain the new topology.",
            NT_STATUS_GRAPHICS_MONITOR_NOT_CONNECTED => "No monitor is connected on the specified video present target.",
            NT_STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY => "The specified source is not part of the specified VidPN's topology.",
            NT_STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE => "The specified primary surface size is invalid.",
            NT_STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE => "The specified visible region size is invalid.",
            NT_STATUS_GRAPHICS_INVALID_STRIDE => "The specified stride is invalid.",
            NT_STATUS_GRAPHICS_INVALID_PIXELFORMAT => "The specified pixel format is invalid.",
            NT_STATUS_GRAPHICS_INVALID_COLORBASIS => "The specified color basis is invalid.",
            NT_STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE => "The specified pixel value access mode is invalid.",
            NT_STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY => "The specified target is not part of the specified VidPN's topology.",
            NT_STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT => "Failed to acquire the display mode management interface.",
            NT_STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE => "The specified VidPN source is already owned by a DMM client and cannot be used until that client releases it.",
            NT_STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN => "The specified VidPN is active and cannot be accessed.",
            NT_STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL => "The specified VidPN's present path importance ordinal is invalid.",
            NT_STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION => "The specified VidPN's present path content geometry transformation is invalid.",
            NT_STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED => "The specified content geometry transformation is not supported on the respective VidPN present path.",
            NT_STATUS_GRAPHICS_INVALID_GAMMA_RAMP => "The specified gamma ramp is invalid.",
            NT_STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED => "The specified gamma ramp is not supported on the respective VidPN present path.",
            NT_STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED => "Multisampling is not supported on the respective VidPN present path.",
            NT_STATUS_GRAPHICS_MODE_NOT_IN_MODESET => "The specified mode is not in the specified mode set.",
            NT_STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON => "The specified VidPN topology recommendation reason is invalid.",
            NT_STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE => "The specified VidPN present path content type is invalid.",
            NT_STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE => "The specified VidPN present path copy protection type is invalid.",
            NT_STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS => "Only one unassigned mode set can exist at any one time for a particular VidPN source or target.",
            NT_STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING => "The specified scan line ordering type is invalid.",
            NT_STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED => "The topology changes are not allowed for the specified VidPN.",
            NT_STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS => "All available importance ordinals are being used in the specified topology.",
            NT_STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT => "The specified primary surface has a different private-format attribute than the current primary surface.",
            NT_STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM => "The specified mode-pruning algorithm is invalid.",
            NT_STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN => "The specified monitor-capability origin is invalid.",
            NT_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT => "The specified monitor-frequency range constraint is invalid.",
            NT_STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED => "The maximum supported number of present paths has been reached.",
            NT_STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION => "The miniport requested that augmentation be canceled for the specified source of the specified VidPN's topology.",
            NT_STATUS_GRAPHICS_INVALID_CLIENT_TYPE => "The specified client type was not recognized.",
            NT_STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET => "The client VidPN is not set on this adapter (for example, no user mode-initiated mode changes have taken place on this adapter).",
            NT_STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED => "The specified display adapter child device already has an external device connected to it.",
            NT_STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED => "The display adapter child device does not support reporting a descriptor.",
            NT_STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER => "The display adapter is not linked to any other adapters.",
            NT_STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED => "The lead adapter in a linked configuration was not enumerated yet.",
            NT_STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED => "Some chain adapters in a linked configuration have not yet been enumerated.",
            NT_STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY => "The chain of linked adapters is not ready to start because of an unknown failure.",
            NT_STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED => "An attempt was made to start a lead link display adapter when the chain links had not yet started.",
            NT_STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON => "An attempt was made to turn on a lead link display adapter when the chain links were turned off.",
            NT_STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE => "The adapter link was found in an inconsistent state. Not all adapters are in an expected PNP/power state.",
            NT_STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER => "The driver trying to start is not the same as the driver for the posted display adapter.",
            NT_STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED => "An operation is being attempted that requires the display adapter to be in a quiescent state.",
            NT_STATUS_GRAPHICS_OPM_NOT_SUPPORTED => "The driver does not support OPM.",
            NT_STATUS_GRAPHICS_COPP_NOT_SUPPORTED => "The driver does not support COPP.",
            NT_STATUS_GRAPHICS_UAB_NOT_SUPPORTED => "The driver does not support UAB.",
            NT_STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS => "The specified encrypted parameters are invalid.",
            NT_STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL => "An array passed to a function cannot hold all of the data that the function wants to put in it.",
            NT_STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST => "The GDI display device passed to this function does not have any active protected outputs.",
            NT_STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME => "The PVP cannot find an actual GDI display device that corresponds to the passed-in GDI display device name.",
            NT_STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP => "This function failed because the GDI display device passed to it was not attached to the Windows desktop.",
            NT_STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED => "The PVP does not support mirroring display devices because they do not have any protected outputs.",
            NT_STATUS_GRAPHICS_OPM_INVALID_POINTER => "The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or it points to an invalid address or a kernel mode address.",
            NT_STATUS_GRAPHICS_OPM_INTERNAL_ERROR => "An internal error caused an operation to fail.",
            NT_STATUS_GRAPHICS_OPM_INVALID_HANDLE => "The function failed because the caller passed in an invalid OPM user-mode handle.",
            NT_STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE => "This function failed because the GDI device passed to it did not have any monitors associated with it.",
            NT_STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH => "A certificate could not be returned because the certificate buffer passed to the function was too small.",
            NT_STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED => "DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present yarget is in spanning mode.",
            NT_STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED => "DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present target is in theater mode.",
            NT_STATUS_GRAPHICS_PVP_HFS_FAILED => "The function call failed because the display adapter's hardware functionality scan (HFS) failed to validate the graphics hardware.",
            NT_STATUS_GRAPHICS_OPM_INVALID_SRM => "The HDCP SRM passed to this function did not comply with section 5 of the HDCP 1.1 specification.",
            NT_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP => "The protected output cannot enable the HDCP system because it does not support it.",
            NT_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP => "The protected output cannot enable analog copy protection because it does not support it.",
            NT_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA => "The protected output cannot enable the CGMS-A protection technology because it does not support it.",
            NT_STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET => "DxgkDdiOPMGetInformation() cannot return the version of the SRM being used because the application never successfully passed an SRM to the protected output.",
            NT_STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH => "DxgkDdiOPMConfigureProtectedOutput() cannot enable the specified output protection technology because the output's screen resolution is too high.",
            NT_STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE => "DxgkDdiOPMConfigureProtectedOutput() cannot enable HDCP because other physical outputs are using the display adapter's HDCP hardware.",
            NT_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS => "The operating system asynchronously destroyed this OPM-protected output because the operating system state changed. This error typically occurs because the monitor PDO associated with this protected output was removed or stopped, the protected output's session became a nonconsole session, or the protected output's desktop became inactive.",
            NT_STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS => "OPM functions cannot be called when a session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA).",
            NT_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS => "The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has OPM semantics. DxgkDdiOPMGetCOPPCompatibleInformation always returns this error if a protected output has OPM semantics. DxgkDdiOPMGetInformation returns this error code if the caller requested COPP-specific information. DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use a COPP-specific command.",
            NT_STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST => "The DxgkDdiOPMGetInformation and DxgkDdiOPMGetCOPPCompatibleInformation functions return this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid.",
            NT_STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR => "The function failed because an unexpected error occurred inside a display driver.",
            NT_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS => "The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has COPP semantics. DxgkDdiOPMGetCOPPCompatibleInformation returns this error code if the caller requested OPM-specific information. DxgkDdiOPMGetInformation always returns this error if a protected output has COPP semantics. DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use an OPM-specific command.",
            NT_STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED => "The DxgkDdiOPMGetCOPPCompatibleInformation and DxgkDdiOPMConfigureProtectedOutput functions return this error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXGKMDT_OPM_SET_ACP_AND_CGMSA_SIGNALING GUIDs.",
            NT_STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST => "The DxgkDdiOPMConfigureProtectedOutput function returns this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid.",
            NT_STATUS_GRAPHICS_I2C_NOT_SUPPORTED => "The monitor connected to the specified video output does not have an I2C bus.",
            NT_STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST => "No device on the I2C bus has the specified address.",
            NT_STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA => "An error occurred while transmitting data to the device on the I2C bus.",
            NT_STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA => "An error occurred while receiving data from the device on the I2C bus.",
            NT_STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED => "The monitor does not support the specified VCP code.",
            NT_STATUS_GRAPHICS_DDCCI_INVALID_DATA => "The data received from the monitor is invalid.",
            NT_STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE => "A function call failed because a monitor returned an invalid timing status byte when the operating system used the DDC/CI get timing report and timing message command to get a timing report from a monitor.",
            NT_STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING => "A monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification.",
            NT_STATUS_GRAPHICS_MCA_INTERNAL_ERROR => "An internal error caused an operation to fail.",
            NT_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND => "An operation failed because a DDC/CI message had an invalid value in its command field.",
            NT_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH => "This error occurred because a DDC/CI message had an invalid value in its length field.",
            NT_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM => "This error occurred because the value in a DDC/CI message's checksum field did not match the message's computed checksum value. This error implies that the data was corrupted while it was being transmitted from a monitor to a computer.",
            NT_STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE => "This function failed because an invalid monitor handle was passed to it.",
            NT_STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS => "The operating system asynchronously destroyed the monitor that corresponds to this handle because the operating system's state changed. This error typically occurs because the monitor PDO associated with this handle was removed or stopped, or a display mode change occurred. A display mode change occurs when Windows sends a WM_DISPLAYCHANGE message to applications.",
            NT_STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED => "This function can be used only if a program is running in the local console session. It cannot be used if a program is running on a remote desktop session or on a terminal server session.",
            NT_STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME => "This function cannot find an actual GDI display device that corresponds to the specified GDI display device name.",
            NT_STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP => "The function failed because the specified GDI display device was not attached to the Windows desktop.",
            NT_STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED => "This function does not support GDI mirroring display devices because GDI mirroring display devices do not have any physical monitors associated with them.",
            NT_STATUS_GRAPHICS_INVALID_POINTER => "The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or points to an invalid address or to a kernel mode address.",
            NT_STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE => "This function failed because the GDI device passed to it did not have a monitor associated with it.",
            NT_STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL => "An array passed to the function cannot hold all of the data that the function must copy into the array.",
            NT_STATUS_GRAPHICS_INTERNAL_ERROR => "An internal error caused an operation to fail.",
            NT_STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS => "The function failed because the current session is changing its type. This function cannot be called when the current session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA).",
            NT_STATUS_FVE_LOCKED_VOLUME => "The volume must be unlocked before it can be used.",
            NT_STATUS_FVE_NOT_ENCRYPTED => "The volume is fully decrypted and no key is available.",
            NT_STATUS_FVE_BAD_INFORMATION => "The control block for the encrypted volume is not valid.",
            NT_STATUS_FVE_TOO_SMALL => "Not enough free space remains on the volume to allow encryption.",
            NT_STATUS_FVE_FAILED_WRONG_FS => "The partition cannot be encrypted because the file system is not supported.",
            NT_STATUS_FVE_FAILED_BAD_FS => "The file system is inconsistent. Run the Check Disk utility.",
            NT_STATUS_FVE_FS_NOT_EXTENDED => "The file system does not extend to the end of the volume.",
            NT_STATUS_FVE_FS_MOUNTED => "This operation cannot be performed while a file system is mounted on the volume.",
            NT_STATUS_FVE_NO_LICENSE => "BitLocker Drive Encryption is not included with this version of Windows.",
            NT_STATUS_FVE_ACTION_NOT_ALLOWED => "The requested action was denied by the FVE control engine.",
            NT_STATUS_FVE_BAD_DATA => "The data supplied is malformed.",
            NT_STATUS_FVE_VOLUME_NOT_BOUND => "The volume is not bound to the system.",
            NT_STATUS_FVE_NOT_DATA_VOLUME => "The volume specified is not a data volume.",
            NT_STATUS_FVE_CONV_READ_ERROR => "A read operation failed while converting the volume.",
            NT_STATUS_FVE_CONV_WRITE_ERROR => "A write operation failed while converting the volume.",
            NT_STATUS_FVE_OVERLAPPED_UPDATE => "The control block for the encrypted volume was updated by another thread. Try again.",
            NT_STATUS_FVE_FAILED_SECTOR_SIZE => "The volume encryption algorithm cannot be used on this sector size.",
            NT_STATUS_FVE_FAILED_AUTHENTICATION => "BitLocker recovery authentication failed.",
            NT_STATUS_FVE_NOT_OS_VOLUME => "The volume specified is not the boot operating system volume.",
            NT_STATUS_FVE_KEYFILE_NOT_FOUND => "The BitLocker startup key or recovery password could not be read from external media.",
            NT_STATUS_FVE_KEYFILE_INVALID => "The BitLocker startup key or recovery password file is corrupt or invalid.",
            NT_STATUS_FVE_KEYFILE_NO_VMK => "The BitLocker encryption key could not be obtained from the startup key or the recovery password.",
            NT_STATUS_FVE_TPM_DISABLED => "The TPM is disabled.",
            NT_STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO => "The authorization data for the SRK of the TPM is not zero.",
            NT_STATUS_FVE_TPM_INVALID_PCR => "The system boot information changed or the TPM locked out access to BitLocker encryption keys until the computer is restarted.",
            NT_STATUS_FVE_TPM_NO_VMK => "The BitLocker encryption key could not be obtained from the TPM.",
            NT_STATUS_FVE_PIN_INVALID => "The BitLocker encryption key could not be obtained from the TPM and PIN.",
            NT_STATUS_FVE_AUTH_INVALID_APPLICATION => "A boot application hash does not match the hash computed when BitLocker was turned on.",
            NT_STATUS_FVE_AUTH_INVALID_CONFIG => "The Boot Configuration Data (BCD) settings are not supported or have changed because BitLocker was enabled.",
            NT_STATUS_FVE_DEBUGGER_ENABLED => "Boot debugging is enabled. Run Windows Boot Configuration Data Store Editor (bcdedit.exe) to turn it off.",
            NT_STATUS_FVE_DRY_RUN_FAILED => "The BitLocker encryption key could not be obtained.",
            NT_STATUS_FVE_BAD_METADATA_POINTER => "The metadata disk region pointer is incorrect.",
            NT_STATUS_FVE_OLD_METADATA_COPY => "The backup copy of the metadata is out of date.",
            NT_STATUS_FVE_REBOOT_REQUIRED => "No action was taken because a system restart is required.",
            NT_STATUS_FVE_RAW_ACCESS => "No action was taken because BitLocker Drive Encryption is in RAW access mode.",
            NT_STATUS_FVE_RAW_BLOCKED => "BitLocker Drive Encryption cannot enter RAW access mode for this volume.",
            NT_STATUS_FVE_NO_FEATURE_LICENSE => "This feature of BitLocker Drive Encryption is not included with this version of Windows.",
            NT_STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED => "Group policy does not permit turning off BitLocker Drive Encryption on roaming data volumes.",
            NT_STATUS_FVE_CONV_RECOVERY_FAILED => "Bitlocker Drive Encryption failed to recover from aborted conversion. This could be due to either all conversion logs being corrupted or the media being write-protected.",
            NT_STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG => "The requested virtualization size is too big.",
            NT_STATUS_FVE_VOLUME_TOO_SMALL => "The drive is too small to be protected using BitLocker Drive Encryption.",
            NT_STATUS_FWP_CALLOUT_NOT_FOUND => "The callout does not exist.",
            NT_STATUS_FWP_CONDITION_NOT_FOUND => "The filter condition does not exist.",
            NT_STATUS_FWP_FILTER_NOT_FOUND => "The filter does not exist.",
            NT_STATUS_FWP_LAYER_NOT_FOUND => "The layer does not exist.",
            NT_STATUS_FWP_PROVIDER_NOT_FOUND => "The provider does not exist.",
            NT_STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND => "The provider context does not exist.",
            NT_STATUS_FWP_SUBLAYER_NOT_FOUND => "The sublayer does not exist.",
            NT_STATUS_FWP_NOT_FOUND => "The object does not exist.",
            NT_STATUS_FWP_ALREADY_EXISTS => "An object with that GUID or LUID already exists.",
            NT_STATUS_FWP_IN_USE => "The object is referenced by other objects and cannot be deleted.",
            NT_STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS => "The call is not allowed from within a dynamic session.",
            NT_STATUS_FWP_WRONG_SESSION => "The call was made from the wrong session and cannot be completed.",
            NT_STATUS_FWP_NO_TXN_IN_PROGRESS => "The call must be made from within an explicit transaction.",
            NT_STATUS_FWP_TXN_IN_PROGRESS => "The call is not allowed from within an explicit transaction.",
            NT_STATUS_FWP_TXN_ABORTED => "The explicit transaction has been forcibly canceled.",
            NT_STATUS_FWP_SESSION_ABORTED => "The session has been canceled.",
            NT_STATUS_FWP_INCOMPATIBLE_TXN => "The call is not allowed from within a read-only transaction.",
            NT_STATUS_FWP_TIMEOUT => "The call timed out while waiting to acquire the transaction lock.",
            NT_STATUS_FWP_NET_EVENTS_DISABLED => "The collection of network diagnostic events is disabled.",
            NT_STATUS_FWP_INCOMPATIBLE_LAYER => "The operation is not supported by the specified layer.",
            NT_STATUS_FWP_KM_CLIENTS_ONLY => "The call is allowed for kernel-mode callers only.",
            NT_STATUS_FWP_LIFETIME_MISMATCH => "The call tried to associate two objects with incompatible lifetimes.",
            NT_STATUS_FWP_BUILTIN_OBJECT => "The object is built-in and cannot be deleted.",
            NT_STATUS_FWP_TOO_MANY_CALLOUTS => "The maximum number of callouts has been reached.",
            NT_STATUS_FWP_NOTIFICATION_DROPPED => "A notification could not be delivered because a message queue has reached maximum capacity.",
            NT_STATUS_FWP_TRAFFIC_MISMATCH => "The traffic parameters do not match those for the security association context.",
            NT_STATUS_FWP_INCOMPATIBLE_SA_STATE => "The call is not allowed for the current security association state.",
            NT_STATUS_FWP_NULL_POINTER => "A required pointer is null.",
            NT_STATUS_FWP_INVALID_ENUMERATOR => "An enumerator is not valid.",
            NT_STATUS_FWP_INVALID_FLAGS => "The flags field contains an invalid value.",
            NT_STATUS_FWP_INVALID_NET_MASK => "A network mask is not valid.",
            NT_STATUS_FWP_INVALID_RANGE => "An FWP_RANGE is not valid.",
            NT_STATUS_FWP_INVALID_INTERVAL => "The time interval is not valid.",
            NT_STATUS_FWP_ZERO_LENGTH_ARRAY => "An array that must contain at least one element has a zero length.",
            NT_STATUS_FWP_NULL_DISPLAY_NAME => "The displayData.name field cannot be null.",
            NT_STATUS_FWP_INVALID_ACTION_TYPE => "The action type is not one of the allowed action types for a filter.",
            NT_STATUS_FWP_INVALID_WEIGHT => "The filter weight is not valid.",
            NT_STATUS_FWP_MATCH_TYPE_MISMATCH => "A filter condition contains a match type that is not compatible with the operands.",
            NT_STATUS_FWP_TYPE_MISMATCH => "An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type.",
            NT_STATUS_FWP_OUT_OF_BOUNDS => "An integer value is outside the allowed range.",
            NT_STATUS_FWP_RESERVED => "A reserved field is nonzero.",
            NT_STATUS_FWP_DUPLICATE_CONDITION => "A filter cannot contain multiple conditions operating on a single field.",
            NT_STATUS_FWP_DUPLICATE_KEYMOD => "A policy cannot contain the same keying module more than once.",
            NT_STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER => "The action type is not compatible with the layer.",
            NT_STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER => "The action type is not compatible with the sublayer.",
            NT_STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER => "The raw context or the provider context is not compatible with the layer.",
            NT_STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT => "The raw context or the provider context is not compatible with the callout.",
            NT_STATUS_FWP_INCOMPATIBLE_AUTH_METHOD => "The authentication method is not compatible with the policy type.",
            NT_STATUS_FWP_INCOMPATIBLE_DH_GROUP => "The Diffie-Hellman group is not compatible with the policy type.",
            NT_STATUS_FWP_EM_NOT_SUPPORTED => "An IKE policy cannot contain an Extended Mode policy.",
            NT_STATUS_FWP_NEVER_MATCH => "The enumeration template or subscription will never match any objects.",
            NT_STATUS_FWP_PROVIDER_CONTEXT_MISMATCH => "The provider context is of the wrong type.",
            NT_STATUS_FWP_INVALID_PARAMETER => "The parameter is incorrect.",
            NT_STATUS_FWP_TOO_MANY_SUBLAYERS => "The maximum number of sublayers has been reached.",
            NT_STATUS_FWP_CALLOUT_NOTIFICATION_FAILED => "The notification function for a callout returned an error.",
            NT_STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG => "The IPsec authentication configuration is not compatible with the authentication type.",
            NT_STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG => "The IPsec cipher configuration is not compatible with the cipher type.",
            NT_STATUS_FWP_DUPLICATE_AUTH_METHOD => "A policy cannot contain the same auth method more than once.",
            NT_STATUS_FWP_TCPIP_NOT_READY => "The TCP/IP stack is not ready.",
            NT_STATUS_FWP_INJECT_HANDLE_CLOSING => "The injection handle is being closed by another thread.",
            NT_STATUS_FWP_INJECT_HANDLE_STALE => "The injection handle is stale.",
            NT_STATUS_FWP_CANNOT_PEND => "The classify cannot be pended.",
            NT_STATUS_NDIS_CLOSING => "The binding to the network interface is being closed.",
            NT_STATUS_NDIS_BAD_VERSION => "An invalid version was specified.",
            NT_STATUS_NDIS_BAD_CHARACTERISTICS => "An invalid characteristics table was used.",
            NT_STATUS_NDIS_ADAPTER_NOT_FOUND => "Failed to find the network interface or the network interface is not ready.",
            NT_STATUS_NDIS_OPEN_FAILED => "Failed to open the network interface.",
            NT_STATUS_NDIS_DEVICE_FAILED => "The network interface has encountered an internal unrecoverable failure.",
            NT_STATUS_NDIS_MULTICAST_FULL => "The multicast list on the network interface is full.",
            NT_STATUS_NDIS_MULTICAST_EXISTS => "An attempt was made to add a duplicate multicast address to the list.",
            NT_STATUS_NDIS_MULTICAST_NOT_FOUND => "At attempt was made to remove a multicast address that was never added.",
            NT_STATUS_NDIS_REQUEST_ABORTED => "The network interface aborted the request.",
            NT_STATUS_NDIS_RESET_IN_PROGRESS => "The network interface cannot process the request because it is being reset.",
            NT_STATUS_NDIS_INVALID_PACKET => "An attempt was made to send an invalid packet on a network interface.",
            NT_STATUS_NDIS_INVALID_DEVICE_REQUEST => "The specified request is not a valid operation for the target device.",
            NT_STATUS_NDIS_ADAPTER_NOT_READY => "The network interface is not ready to complete this operation.",
            NT_STATUS_NDIS_INVALID_LENGTH => "The length of the buffer submitted for this operation is not valid.",
            NT_STATUS_NDIS_INVALID_DATA => "The data used for this operation is not valid.",
            NT_STATUS_NDIS_BUFFER_TOO_SHORT => "The length of the submitted buffer for this operation is too small.",
            NT_STATUS_NDIS_INVALID_OID => "The network interface does not support this object identifier.",
            NT_STATUS_NDIS_ADAPTER_REMOVED => "The network interface has been removed.",
            NT_STATUS_NDIS_UNSUPPORTED_MEDIA => "The network interface does not support this media type.",
            NT_STATUS_NDIS_GROUP_ADDRESS_IN_USE => "An attempt was made to remove a token ring group address that is in use by other components.",
            NT_STATUS_NDIS_FILE_NOT_FOUND => "An attempt was made to map a file that cannot be found.",
            NT_STATUS_NDIS_ERROR_READING_FILE => "An error occurred while NDIS tried to map the file.",
            NT_STATUS_NDIS_ALREADY_MAPPED => "An attempt was made to map a file that is already mapped.",
            NT_STATUS_NDIS_RESOURCE_CONFLICT => "An attempt to allocate a hardware resource failed because the resource is used by another component.",
            NT_STATUS_NDIS_MEDIA_DISCONNECTED => "The I/O operation failed because the network media is disconnected or the wireless access point is out of range.",
            NT_STATUS_NDIS_INVALID_ADDRESS => "The network address used in the request is invalid.",
            NT_STATUS_NDIS_PAUSED => "The offload operation on the network interface has been paused.",
            NT_STATUS_NDIS_INTERFACE_NOT_FOUND => "The network interface was not found.",
            NT_STATUS_NDIS_UNSUPPORTED_REVISION => "The revision number specified in the structure is not supported.",
            NT_STATUS_NDIS_INVALID_PORT => "The specified port does not exist on this network interface.",
            NT_STATUS_NDIS_INVALID_PORT_STATE => "The current state of the specified port on this network interface does not support the requested operation.",
            NT_STATUS_NDIS_LOW_POWER_STATE => "The miniport adapter is in a lower power state.",
            NT_STATUS_NDIS_NOT_SUPPORTED => "The network interface does not support this request.",
            NT_STATUS_NDIS_OFFLOAD_POLICY => "The TCP connection is not offloadable because of a local policy setting.",
            NT_STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED => "The TCP connection is not offloadable by the Chimney offload target.",
            NT_STATUS_NDIS_OFFLOAD_PATH_REJECTED => "The IP Path object is not in an offloadable state.",
            NT_STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED => "The wireless LAN interface is in auto-configuration mode and does not support the requested parameter change operation.",
            NT_STATUS_NDIS_DOT11_MEDIA_IN_USE => "The wireless LAN interface is busy and cannot perform the requested operation.",
            NT_STATUS_NDIS_DOT11_POWER_STATE_INVALID => "The wireless LAN interface is power down and does not support the requested operation.",
            NT_STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL => "The list of wake on LAN patterns is full.",
            NT_STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL => "The list of low power protocol offloads is full.",
            NT_STATUS_IPSEC_BAD_SPI => "The SPI in the packet does not match a valid IPsec SA.",
            NT_STATUS_IPSEC_SA_LIFETIME_EXPIRED => "The packet was received on an IPsec SA whose lifetime has expired.",
            NT_STATUS_IPSEC_WRONG_SA => "The packet was received on an IPsec SA that does not match the packet characteristics.",
            NT_STATUS_IPSEC_REPLAY_CHECK_FAILED => "The packet sequence number replay check failed.",
            NT_STATUS_IPSEC_INVALID_PACKET => "The IPsec header and/or trailer in the packet is invalid.",
            NT_STATUS_IPSEC_INTEGRITY_CHECK_FAILED => "The IPsec integrity check failed.",
            NT_STATUS_IPSEC_CLEAR_TEXT_DROP => "IPsec dropped a clear text packet.",
            NT_STATUS_IPSEC_AUTH_FIREWALL_DROP => "IPsec dropped an incoming ESP packet in authenticated firewall mode.  This drop is benign.",
            NT_STATUS_IPSEC_THROTTLE_DROP => "IPsec dropped a packet due to DOS throttle.",
            NT_STATUS_IPSEC_DOSP_BLOCK => "IPsec Dos Protection matched an explicit block rule.",
            NT_STATUS_IPSEC_DOSP_RECEIVED_MULTICAST => "IPsec Dos Protection received an IPsec specific multicast packet which is not allowed.",
            NT_STATUS_IPSEC_DOSP_INVALID_PACKET => "IPsec Dos Protection received an incorrectly formatted packet.",
            NT_STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED => "IPsec Dos Protection failed to lookup state.",
            NT_STATUS_IPSEC_DOSP_MAX_ENTRIES => "IPsec Dos Protection failed to create state because there are already maximum number of entries allowed by policy.",
            NT_STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED => "IPsec Dos Protection received an IPsec negotiation packet for a keying module which is not allowed by policy.",
            NT_STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES => "IPsec Dos Protection failed to create per internal IP ratelimit queue because there is already maximum number of queues allowed by policy.",
            NT_STATUS_VOLMGR_MIRROR_NOT_SUPPORTED => "The system does not support mirrored volumes.",
            NT_STATUS_VOLMGR_RAID5_NOT_SUPPORTED => "The system does not support RAID-5 volumes.",
            NT_STATUS_VIRTDISK_PROVIDER_NOT_FOUND => "A virtual disk support provider for the specified file was not found.",
            NT_STATUS_VIRTDISK_NOT_VIRTUAL_DISK => "The specified disk is not a virtual disk.",
            NT_STATUS_VHD_PARENT_VHD_ACCESS_DENIED => "The chain of virtual hard disks is inaccessible. The process has not been granted access rights to the parent virtual hard disk for the differencing disk.",
            NT_STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH => "The chain of virtual hard disks is corrupted. There is a mismatch in the virtual sizes of the parent virtual hard disk and differencing disk.",
            NT_STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED => "The chain of virtual hard disks is corrupted. A differencing disk is indicated in its own parent chain.",
            NT_STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT => "The chain of virtual hard disks is inaccessible. There was an error opening a virtual hard disk further up the chain.",
            _ => "Unknown NtStatus error code",
        }
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtStatus({:#x}): {}", self.0, self.description())
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtStatus({:#x})", self.0)
    }
}

impl std::error::Error for NtStatus {}
