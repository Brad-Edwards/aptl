#!/usr/bin/env python3
"""
DBK64 CE Complete - Use EXACT Cheat Engine service setup and initialization
Based on complete source code analysis
"""

import ctypes
import struct
from ctypes import wintypes

# Windows Constants (exact CE values)
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def CTL_CODE(DeviceType, Function, Method, Access):
    """Create Windows IOCTL code"""
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# IOCTL codes (from CE source)
IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)  # 0x00222034
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)  # 0x00222058
IOCTL_CE_TEST = CTL_CODE(0x22, 0x0804, 0, 0)       # 0x00222010

print("=== DBK64 Complete CE Method ===\n")
print("Using EXACT Cheat Engine setup:")
print("  Service Name: CEDRIVER73")
print("  Device Path: \\\\.\CEDRIVER73")
print("  Event Names: DBKProcList60, DBKThreadList60")

# Step 1: Open device with EXACT CE parameters
print("\n[*] Opening \\\\.\CEDRIVER73 with CE flags...")
handle = kernel32.CreateFileW(
    r'\\.\CEDRIVER73',                     # CE uses servicename, not hardcoded "DBK64"!
    GENERIC_READ | GENERIC_WRITE,          # dwDesiredAccess
    FILE_SHARE_READ | FILE_SHARE_WRITE,    # dwShareMode (CE uses this!)
    None,                                   # lpSecurityAttributes
    OPEN_EXISTING,                          # dwCreationDisposition
    FILE_FLAG_OVERLAPPED,                   # dwFlagsAndAttributes (Critical!)
    None                                    # hTemplateFile
)

if handle == INVALID_HANDLE_VALUE:
    error = kernel32.GetLastError()
    print(f"[-] Failed to open device! Error: {error}")
    if error == 161:
        print("    ERROR 161 = Bad pathname - device objects not created")
        print("    This suggests the driver DriverEntry is failing to create device objects")
        print("    Possible causes:")
        print("    1. Driver expects specific registry configuration")
        print("    2. Driver validates service name or path")
        print("    3. Driver requires specific initialization before device creation")
    exit(1)

print(f"[+] SUCCESS! Device opened! Handle: {handle}")

# Step 2: Create NAMED events exactly like CE
print("\n[*] Creating named events (CE method)...")
print("    Process event: DBKProcList60")
print("    Thread event: DBKThreadList60")

# Create with exact names from CE source
process_event = kernel32.CreateEventW(None, False, False, "DBKProcList60")
thread_event = kernel32.CreateEventW(None, False, False, "DBKThreadList60")

if process_event == 0 or thread_event == 0:
    error = kernel32.GetLastError()
    print(f"[-] Failed to create named events! Error: {error}")
    kernel32.CloseHandle(handle)
    exit(1)

print(f"[+] Process event: {process_event}")
print(f"[+] Thread event: {thread_event}")

# Step 3: Initialize driver with EXACT CE structure
print(f"\n[*] Initializing driver (EXACT CE method)...")
print(f"    IOCTL_CE_INITIALIZE: 0x{IOCTL_CE_INITIALIZE:08X}")

# CE initialization structure (from DBK32functions.pas)
init_struct = struct.pack('<' + 'Q' * 11,
    0,                # address (AddressOfWin32K)
    0,                # size (SizeOfWin32K)
    0,                # NtUserBuildHwndList_callnumber
    0,                # NtUserQueryWindow_callnumber
    0,                # NtUserFindWindowEx_callnumber
    0,                # NtUserGetForegroundWindow_callnumber
    0,                # activelinkoffset
    0,                # processnameoffset
    0,                # debugportoffset
    process_event,    # processevent (driver rev. 10+)
    thread_event      # threadevent
)

print(f"    Structure size: {len(init_struct)} bytes")
print(f"    Process event at offset 80: {process_event}")
print(f"    Thread event at offset 88: {thread_event}")

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
    None  # CE passes nil for overlapped
)

if result:
    print("[+] BREAKTHROUGH! Driver initialized successfully!")
    if bytes_returned.value >= 8:
        sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
        print(f"    SDTShadow: 0x{sdt_shadow:016X}")
        print(f"    Bytes returned: {bytes_returned.value}")
        
        # Test other IOCTLs now that initialization succeeded
        print("\n[*] Testing other IOCTLs after successful initialization...")
        
        # Test GETVERSION
        ver_out = ctypes.create_string_buffer(4)
        ver_bytes = wintypes.DWORD()
        
        ver_result = kernel32.DeviceIoControl(
            handle,
            IOCTL_CE_GETVERSION,
            None, 0,
            ver_out, 4,
            ctypes.byref(ver_bytes),
            None
        )
        
        if ver_result:
            version = struct.unpack('<I', ver_out.raw[:4])[0]
            print(f"[+] IOCTL_CE_GETVERSION SUCCESS! Version: 0x{version:08X}")
        else:
            ver_error = kernel32.GetLastError()
            print(f"[-] IOCTL_CE_GETVERSION failed: Error {ver_error}")
            
        # Test simple TEST IOCTL
        test_result = kernel32.DeviceIoControl(
            handle,
            IOCTL_CE_TEST,
            None, 0,
            None, 0,
            ctypes.byref(ver_bytes),
            None
        )
        
        if test_result:
            print(f"[+] IOCTL_CE_TEST SUCCESS! Bytes: {ver_bytes.value}")
        else:
            test_error = kernel32.GetLastError()
            print(f"[-] IOCTL_CE_TEST failed: Error {test_error}")
        
        print(f"\n[+] PROTOCOL CRACKED! Driver is accepting CE IOCTLs after proper initialization!")
        
else:
    error = kernel32.GetLastError()
    print(f"[-] Initialization failed! Error: {error}")
    if error == 997:
        print("    (ERROR_IO_PENDING - overlapped operation)")
        print("    This might require proper overlapped structure handling")
    elif error == 31:
        print("    (ERROR_GEN_FAILURE - device not functioning)")
        print("    Driver is rejecting the initialization structure")
    elif error == 87:
        print("    (ERROR_INVALID_PARAMETER - bad structure)")
        print("    Structure format or size is incorrect")

# Cleanup
print("\n[*] Cleaning up...")
kernel32.CloseHandle(process_event)
kernel32.CloseHandle(thread_event)
kernel32.CloseHandle(handle)
print("[+] Done!")
