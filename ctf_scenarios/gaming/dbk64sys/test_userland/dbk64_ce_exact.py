#!/usr/bin/env python3
"""
DBK64 Cheat Engine Exact - Uses exact same CreateFile flags as CE
Based on DBK32functions.pas CreateFile call
"""

import ctypes
import struct
from ctypes import wintypes

# Windows Constants (matching CE exactly)
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000  # Critical flag CE uses!
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def CTL_CODE(DeviceType, Function, Method, Access):
    """Create Windows IOCTL code"""
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# IOCTL codes (from CE source)
IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)  # 0x00222034
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)  # 0x00222058
IOCTL_CE_TEST = CTL_CODE(0x22, 0x0804, 0, 0)       # 0x00222010

print("=== DBK64 CE-Exact Client ===\n")

# Step 1: Open device EXACTLY like Cheat Engine does
print("[*] Opening \\\\.\\ DBK64 with CE flags...")
print(f"    GENERIC_READ | GENERIC_WRITE: 0x{GENERIC_READ | GENERIC_WRITE:08X}")
print(f"    FILE_SHARE_READ | FILE_SHARE_WRITE: 0x{FILE_SHARE_READ | FILE_SHARE_WRITE:08X}")
print(f"    FILE_FLAG_OVERLAPPED: 0x{FILE_FLAG_OVERLAPPED:08X}")

handle = kernel32.CreateFileW(
    r'\\.\DBK64',                           # servicename
    GENERIC_READ | GENERIC_WRITE,           # dwDesiredAccess
    FILE_SHARE_READ | FILE_SHARE_WRITE,     # dwShareMode (CE uses this!)
    None,                                    # lpSecurityAttributes
    OPEN_EXISTING,                           # dwCreationDisposition
    FILE_FLAG_OVERLAPPED,                    # dwFlagsAndAttributes (Critical!)
    None                                     # hTemplateFile (0 in CE)
)

if handle == INVALID_HANDLE_VALUE:
    error = kernel32.GetLastError()
    print(f"[-] Failed to open device! Error: {error}")
    if error == 2:
        print("    (File not found - driver not loaded)")
    elif error == 5:
        print("    (Access denied - check permissions)")
    exit(1)

print(f"[+] Device opened! Handle: {handle}\n")

# Step 2: Create event handles (from InitializeDriver)
print("[*] Creating event handles...")
process_event = kernel32.CreateEventW(None, False, False, None)
thread_event = kernel32.CreateEventW(None, False, False, None)

if process_event == 0 or thread_event == 0:
    print("[-] Failed to create events!")
    kernel32.CloseHandle(handle)
    exit(1)

print(f"[+] Process event: {process_event}")
print(f"[+] Thread event: {thread_event}\n")

# Step 3: Initialize driver with exact structure from CE
print("[*] Initializing driver (CE method)...")

# From tinput record in InitializeDriver
init_struct = struct.pack('<' + 'Q' * 11,
    0,  # address (AddressOfWin32K)
    0,  # size (SizeOfWin32K)
    0,  # NtUserBuildHwndList_callnumber
    0,  # NtUserQueryWindow_callnumber
    0,  # NtUserFindWindowEx_callnumber
    0,  # NtUserGetForegroundWindow_callnumber
    0,  # activelinkoffset
    0,  # processnameoffset
    0,  # debugportoffset
    process_event,  # processevent (driver rev. 10+)
    thread_event    # threadevent
)

in_buffer = ctypes.create_string_buffer(init_struct)
out_buffer = ctypes.create_string_buffer(8)
bytes_returned = wintypes.DWORD()

# Since we're using FILE_FLAG_OVERLAPPED, we might need OVERLAPPED structure
# But CE code seems to pass nil for overlapped, so let's try that first
result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_INITIALIZE,
    in_buffer,
    len(init_struct),
    out_buffer,
    8,
    ctypes.byref(bytes_returned),
    None  # CE passes nil for overlapped
)

if result:
    print("[+] Driver initialized successfully!")
    if bytes_returned.value >= 8:
        sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
        print(f"    SDTShadow: 0x{sdt_shadow:016X}")
else:
    error = kernel32.GetLastError()
    print(f"[-] Initialization failed! Error: {error}")
    if error == 997:
        print("    (ERROR_IO_PENDING - overlapped operation)")
    elif error == 31:
        print("    (ERROR_GEN_FAILURE - device not functioning)")

print()

# Step 4: Test GETVERSION
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
else:
    error = kernel32.GetLastError()
    print(f"[-] Failed! Error: {error}")
    if error == 997:
        print("    (ERROR_IO_PENDING - needs overlapped handling)")

# Cleanup
print("\n[*] Cleaning up...")
kernel32.CloseHandle(process_event)
kernel32.CloseHandle(thread_event)
kernel32.CloseHandle(handle)
print("[+] Done!")