#!/usr/bin/env python3
"""
DBK64 Privileged Client - Enables SeDebugPrivilege before opening device
This is likely required for the driver to work properly
"""

import ctypes
import struct
from ctypes import wintypes

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

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
IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)
IOCTL_CE_TEST = CTL_CODE(0x22, 0x0804, 0, 0)

print("=== DBK64 Privileged Client ===\n")

# Step 1: Enable SeDebugPrivilege
print("[*] Enabling SeDebugPrivilege...")
h_token = wintypes.HANDLE()

# Get current process token
if not advapi32.OpenProcessToken(
    kernel32.GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES,
    ctypes.byref(h_token)
):
    print(f"[-] Failed to open process token! Error: {kernel32.GetLastError()}")
    exit(1)

print(f"[+] Got process token: {h_token.value}")

# Lookup privilege value
luid = LUID()
if not advapi32.LookupPrivilegeValueW(
    None,
    SE_DEBUG_NAME,
    ctypes.byref(luid)
):
    print(f"[-] Failed to lookup privilege! Error: {kernel32.GetLastError()}")
    kernel32.CloseHandle(h_token)
    exit(1)

print(f"[+] Found SeDebugPrivilege LUID: {luid.LowPart:08X}:{luid.HighPart:08X}")

# Set up privilege structure
tp = TOKEN_PRIVILEGES()
tp.PrivilegeCount = 1
tp.Privileges[0].Luid = luid
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

# Adjust token privileges
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

# Check if it actually worked
error = kernel32.GetLastError()
if error == 1300:  # ERROR_NOT_ALL_ASSIGNED
    print("[-] Warning: Not all privileges were assigned (need to run as admin?)")
else:
    print("[+] SeDebugPrivilege enabled successfully!")

kernel32.CloseHandle(h_token)
print()

# Step 2: NOW open the device - it should work!
print("[*] Opening \\\\.\\ DBK64 with elevated privileges...")
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
    error = kernel32.GetLastError()
    print(f"[-] Failed to open device! Error: {error}")
    exit(1)

print(f"[+] Device opened successfully! Handle: {handle}\n")

# Step 3: Create event handles
print("[*] Creating event handles...")
process_event = kernel32.CreateEventW(None, False, False, None)
thread_event = kernel32.CreateEventW(None, False, False, None)

print(f"[+] Process event: {process_event}")
print(f"[+] Thread event: {thread_event}\n")

# Step 4: Initialize driver
print("[*] Initializing driver...")

init_struct = struct.pack('<' + 'Q' * 11,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    process_event,
    thread_event
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
    if bytes_returned.value >= 8:
        sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
        print(f"    SDTShadow: 0x{sdt_shadow:016X}")
else:
    error = kernel32.GetLastError()
    print(f"[-] Initialization failed! Error: {error}")
    if error == 31:
        print("    Still getting ERROR_GEN_FAILURE even with privileges!")

print()

# Step 5: Test GETVERSION
print("[*] Testing GETVERSION...")
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
    version = struct.unpack('<I', out_buffer.raw[:4])[0]
    print(f"[+] SUCCESS! Driver version: 0x{version:08X}")
    print("\n[!!!] DRIVER IS WORKING! SeDebugPrivilege was the key!")
else:
    error = kernel32.GetLastError()
    print(f"[-] Failed! Error: {error}")

# Step 6: Test other IOCTLs
print("\n[*] Testing TEST IOCTL...")
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
    print(f"[+] TEST IOCTL worked! Bytes returned: {bytes_returned.value}")
else:
    print(f"[-] TEST IOCTL failed! Error: {kernel32.GetLastError()}")

# Cleanup
print("\n[*] Cleaning up...")
kernel32.CloseHandle(process_event)
kernel32.CloseHandle(thread_event)
kernel32.CloseHandle(handle)
print("[+] Done!")