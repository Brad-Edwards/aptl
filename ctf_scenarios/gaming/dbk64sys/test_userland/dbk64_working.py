#!/usr/bin/env python3
"""
DBK64 Working Client - Properly initializes the driver
Based on InitializeDriver from DBK32functions.pas
"""

import ctypes
import struct
from ctypes import wintypes

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
INVALID_HANDLE_VALUE = -1
SYNCHRONIZE = 0x00100000
EVENT_ALL_ACCESS = 0x1F0003

# Token privileges
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# LUID structure
class LUID(ctypes.Structure):
    _fields_ = [
        ('LowPart', wintypes.DWORD),
        ('HighPart', ctypes.c_long)
    ]

# LUID_AND_ATTRIBUTES structure
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', wintypes.DWORD)
    ]

# TOKEN_PRIVILEGES structure
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', wintypes.DWORD),
        ('Privileges', LUID_AND_ATTRIBUTES * 1)
    ]

def CTL_CODE(DeviceType, Function, Method, Access):
    """Create Windows IOCTL code"""
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# IOCTL codes
IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)  # 0x00222034
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)  # 0x00222058
IOCTL_CE_TEST = CTL_CODE(0x22, 0x0804, 0, 0)       # 0x00222010

print("=== DBK64 Working Client ===\n")

# Step 0: Enable SeDebugPrivilege FIRST
print("[*] Enabling SeDebugPrivilege...")
h_token = wintypes.HANDLE()

if not advapi32.OpenProcessToken(
    kernel32.GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES,
    ctypes.byref(h_token)
):
    print(f"[-] Failed to open process token! Error: {kernel32.GetLastError()}")
    exit(1)

luid = LUID()
if not advapi32.LookupPrivilegeValueW(
    None,
    SE_DEBUG_NAME,
    ctypes.byref(luid)
):
    print(f"[-] Failed to lookup privilege! Error: {kernel32.GetLastError()}")
    kernel32.CloseHandle(h_token)
    exit(1)

tp = TOKEN_PRIVILEGES()
tp.PrivilegeCount = 1
tp.Privileges[0].Luid = luid
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

if not advapi32.AdjustTokenPrivileges(
    h_token,
    False,
    ctypes.byref(tp),
    ctypes.sizeof(tp),
    None,
    None
):
    print(f"[-] Failed to adjust privileges! Error: {kernel32.GetLastError()}")
    kernel32.CloseHandle(h_token)
    exit(1)

error = kernel32.GetLastError()
if error == 1300:
    print("[-] Warning: Not all privileges assigned (need admin?)")
else:
    print("[+] SeDebugPrivilege enabled!")

kernel32.CloseHandle(h_token)
print()

# Step 1: Open device with CE-compatible flags
print("[*] Opening \\\\.\\ DBK64...")
handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    None,
    OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,
    None
)

if handle == INVALID_HANDLE_VALUE:
    print(f"[-] Failed to open device! Error: {kernel32.GetLastError()}")
    exit(1)

print(f"[+] Device opened! Handle: {handle}\n")

# Step 2: Create event handles (critical!)
print("[*] Creating event handles...")
process_event = kernel32.CreateEventW(None, False, False, None)
thread_event = kernel32.CreateEventW(None, False, False, None)

if process_event == 0 or thread_event == 0:
    print("[-] Failed to create events!")
    kernel32.CloseHandle(handle)
    exit(1)

print(f"[+] Process event: {process_event}")
print(f"[+] Thread event: {thread_event}\n")

# Step 3: Initialize driver with proper structure
print("[*] Initializing driver...")

# Create initialization structure (from InitializeDriver in DBK32functions.pas)
# struct input {
#   UINT64 AddressOfWin32K;
#   UINT64 SizeOfWin32K;
#   UINT64 NtUserBuildHwndList_callnumber;
#   UINT64 NtUserQueryWindow_callnumber;
#   UINT64 NtUserFindWindowEx_callnumber;
#   UINT64 NtUserGetForegroundWindow_callnumber;
#   UINT64 ActiveLinkOffset;
#   UINT64 ProcessNameOffset;
#   UINT64 DebugportOffset;
#   UINT64 ProcessEvent;
#   UINT64 ThreadEvent;
# }

init_struct = struct.pack('<' + 'Q' * 11,
    0,  # AddressOfWin32K
    0,  # SizeOfWin32K
    0,  # NtUserBuildHwndList_callnumber
    0,  # NtUserQueryWindow_callnumber
    0,  # NtUserFindWindowEx_callnumber
    0,  # NtUserGetForegroundWindow_callnumber
    0,  # ActiveLinkOffset
    0,  # ProcessNameOffset
    0,  # DebugportOffset
    process_event,  # ProcessEvent handle (critical!)
    thread_event    # ThreadEvent handle (critical!)
)

in_buffer = ctypes.create_string_buffer(init_struct)
out_buffer = ctypes.create_string_buffer(8)
bytes_returned = wintypes.DWORD()

result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_INITIALIZE,
    in_buffer,
    len(init_struct),
    out_buffer,
    8,
    ctypes.byref(bytes_returned),
    None
)

if result:
    print("[+] Driver initialized successfully!")
    if bytes_returned.value > 0:
        sdt_shadow = struct.unpack('<Q', out_buffer.raw)[0]
        print(f"    SDT Shadow: 0x{sdt_shadow:016X}")
else:
    error = kernel32.GetLastError()
    print(f"[-] Initialization failed! Error: {error}")
    kernel32.CloseHandle(handle)
    exit(1)

print()

# Step 4: Now try other IOCTLs - they should work after initialization
print("[*] Testing driver functions after initialization...\n")

# Test GETVERSION
print("[*] Getting driver version...")
out_buffer = ctypes.create_string_buffer(4)
bytes_returned = wintypes.DWORD()

result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_GETVERSION,
    None,
    0,
    out_buffer,
    4,
    ctypes.byref(bytes_returned),
    None
)

if result:
    version = struct.unpack('<I', out_buffer.raw)[0]
    print(f"[+] SUCCESS! Driver version: 0x{version:08X}")
else:
    error = kernel32.GetLastError()
    print(f"[-] Failed! Error: {error}")

# Test TEST IOCTL
print("\n[*] Sending TEST IOCTL...")
test_input = struct.pack('<Q', 0x1234567890ABCDEF)
in_buffer = ctypes.create_string_buffer(test_input)
out_buffer = ctypes.create_string_buffer(256)
bytes_returned = wintypes.DWORD()

result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_TEST,
    in_buffer,
    8,
    out_buffer,
    256,
    ctypes.byref(bytes_returned),
    None
)

if result:
    print(f"[+] SUCCESS! Test IOCTL worked!")
    print(f"    Bytes returned: {bytes_returned.value}")
else:
    error = kernel32.GetLastError()
    print(f"[-] Failed! Error: {error}")

# Cleanup
print("\n[*] Cleaning up...")
kernel32.CloseHandle(process_event)
kernel32.CloseHandle(thread_event)
kernel32.CloseHandle(handle)
print("[+] Done!")