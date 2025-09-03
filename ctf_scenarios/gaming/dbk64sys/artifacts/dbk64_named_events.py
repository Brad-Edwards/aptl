#!/usr/bin/env python3
"""
DBK64 Named Events Test - Use exact registry-configured event names
Based on CE source analysis showing registry C/D point to named events
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

print("=== DBK64 Named Events Test ===\n")

# Step 1: Open device with CE flags
print("[*] Opening \\\\.\\ DBK64 with CE flags...")
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

print(f"[+] Device opened! Handle: {handle}\n")

# Step 2: Create NAMED events using registry values
print("[*] Creating named events from registry...")
print("    Registry C: DBK64ProcessEvent")  
print("    Registry D: DBK64ThreadEvent")

# Create events with the exact names from registry
process_event = kernel32.CreateEventW(None, False, False, "DBK64ProcessEvent")
thread_event = kernel32.CreateEventW(None, False, False, "DBK64ThreadEvent")

if process_event == 0 or thread_event == 0:
    error = kernel32.GetLastError()
    print(f"[-] Failed to create named events! Error: {error}")
    # Try without names as fallback
    print("[*] Falling back to anonymous events...")
    process_event = kernel32.CreateEventW(None, False, False, None)
    thread_event = kernel32.CreateEventW(None, False, False, None)
    
    if process_event == 0 or thread_event == 0:
        print("[-] Failed to create any events!")
        kernel32.CloseHandle(handle)
        exit(1)

print(f"[+] Process event: {process_event}")
print(f"[+] Thread event: {thread_event}\n")

# Step 3: Initialize driver with exact structure
print("[*] Initializing driver...")
print(f"    IOCTL_CE_INITIALIZE: 0x{IOCTL_CE_INITIALIZE:08X}")

# Create exact initialization structure (88 bytes)
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
    None
)

if result:
    print("[+] SUCCESS! Driver initialized!")
    if bytes_returned.value >= 8:
        sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
        print(f"    SDTShadow: 0x{sdt_shadow:016X}")
        print(f"    Bytes returned: {bytes_returned.value}")
        
        # Now test other IOCTLs
        print("\n[*] Testing GETVERSION after successful init...")
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
            print(f"[+] BREAKTHROUGH! Driver version: 0x{version:08X}")
            print(f"    Bytes returned: {ver_bytes.value}")
        else:
            ver_error = kernel32.GetLastError()
            print(f"[-] GETVERSION still failed: Error {ver_error}")
            
        # Test simple TEST IOCTL
        print("\n[*] Testing IOCTL_CE_TEST...")
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
        
else:
    error = kernel32.GetLastError()
    print(f"[-] Initialization failed! Error: {error}")
    if error == 997:
        print("    (ERROR_IO_PENDING - overlapped operation)")
    elif error == 31:
        print("    (ERROR_GEN_FAILURE - device not functioning)")
    elif error == 87:
        print("    (ERROR_INVALID_PARAMETER - bad structure)")

# Cleanup
print("\n[*] Cleaning up...")
kernel32.CloseHandle(process_event)
kernel32.CloseHandle(thread_event)
kernel32.CloseHandle(handle)
print("[+] Done!")
