#!/usr/bin/env python3
"""
DBK64 Raw Test - Try different IOCTL approaches
"""

import ctypes
import struct
from ctypes import wintypes, c_void_p, POINTER, byref

# Windows API
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

# Try opening with different access modes
print("=== DBK64 Raw IOCTL Test ===\n")

# Method 1: Open with GENERIC_READ | GENERIC_WRITE
print("[*] Method 1: Standard CreateFile...")
handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    GENERIC_READ | GENERIC_WRITE,
    0,  # No sharing
    None,
    OPEN_EXISTING,
    0,  # FILE_ATTRIBUTE_NORMAL
    None
)

if handle != INVALID_HANDLE_VALUE:
    print(f"[+] Opened with handle: {handle}")
    
    # Try the simplest possible IOCTL - GETVERSION
    # Using exact value from calculation
    IOCTL_CE_GETVERSION = 0x00222058
    
    print(f"\n[*] Testing IOCTL_CE_GETVERSION (0x{IOCTL_CE_GETVERSION:08X})...")
    
    # Method A: No input, 4-byte output
    print("    Method A: NULL input, DWORD output")
    out_buffer = ctypes.create_string_buffer(4)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        IOCTL_CE_GETVERSION,
        None, 0,  # No input
        out_buffer, 4,  # 4 byte output
        byref(bytes_returned),
        None
    )
    
    if result:
        print(f"    [+] SUCCESS! Bytes returned: {bytes_returned.value}")
        if bytes_returned.value >= 4:
            version = struct.unpack('<I', out_buffer.raw[:4])[0]
            print(f"        Version: 0x{version:08X}")
    else:
        print(f"    [-] Failed, error: {kernel32.GetLastError()}")
    
    # Method B: Empty input buffer, larger output
    print("\n    Method B: Empty input buffer, larger output")
    in_buffer = ctypes.create_string_buffer(8)  # 8 bytes of zeros
    out_buffer = ctypes.create_string_buffer(256)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        IOCTL_CE_GETVERSION,
        in_buffer, 8,
        out_buffer, 256,
        byref(bytes_returned),
        None
    )
    
    if result:
        print(f"    [+] SUCCESS! Bytes returned: {bytes_returned.value}")
    else:
        print(f"    [-] Failed, error: {kernel32.GetLastError()}")
    
    # Try a different IOCTL - TEST
    IOCTL_CE_TEST = 0x00222010
    print(f"\n[*] Testing IOCTL_CE_TEST (0x{IOCTL_CE_TEST:08X})...")
    
    out_buffer = ctypes.create_string_buffer(256)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        IOCTL_CE_TEST,
        None, 0,
        out_buffer, 256,
        byref(bytes_returned),
        None
    )
    
    if result:
        print(f"    [+] SUCCESS! Bytes returned: {bytes_returned.value}")
    else:
        print(f"    [-] Failed, error: {kernel32.GetLastError()}")
    
    kernel32.CloseHandle(handle)
else:
    print(f"[-] Failed to open device, error: {kernel32.GetLastError()}")

# Method 2: Try with different access flags
print("\n[*] Method 2: Open with FILE_ALL_ACCESS...")
FILE_ALL_ACCESS = 0x1F01FF

handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    FILE_ALL_ACCESS,
    0,
    None,
    OPEN_EXISTING,
    0,
    None
)

if handle != INVALID_HANDLE_VALUE:
    print(f"[+] Opened with FILE_ALL_ACCESS, handle: {handle}")
    
    # Quick GETVERSION test
    IOCTL_CE_GETVERSION = 0x00222058
    out_buffer = ctypes.create_string_buffer(4)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        IOCTL_CE_GETVERSION,
        None, 0,
        out_buffer, 4,
        byref(bytes_returned),
        None
    )
    
    if result:
        print(f"    [+] GETVERSION worked with FILE_ALL_ACCESS!")
    else:
        print(f"    [-] Still failed, error: {kernel32.GetLastError()}")
    
    kernel32.CloseHandle(handle)
else:
    error = kernel32.GetLastError()
    print(f"[-] Failed with FILE_ALL_ACCESS, error: {error}")
    if error == 5:
        print("    (Access Denied - might need different privileges)")

print("\n[*] Test complete")