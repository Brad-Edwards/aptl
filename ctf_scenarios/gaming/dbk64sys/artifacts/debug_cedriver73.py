#!/usr/bin/env python3
"""
Debug CEDRIVER73 access
"""

import ctypes
import struct
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

print("=== Debug CEDRIVER73 Access ===\n")

# Test different CreateFile parameters
test_configs = [
    ("Basic", 0xC0000000, 0, 0),
    ("CE Exact", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_OVERLAPPED),
    ("No Share", GENERIC_READ | GENERIC_WRITE, 0, FILE_FLAG_OVERLAPPED),
    ("No Overlapped", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0),
    ("Minimal", GENERIC_READ, 0, 0)
]

for name, access, share, flags in test_configs:
    print(f"[*] Testing {name}:")
    print(f"    Access: 0x{access:08X}, Share: 0x{share:08X}, Flags: 0x{flags:08X}")
    
    handle = kernel32.CreateFileW(
        r'\\.\CEDRIVER73',
        access, share,
        None, OPEN_EXISTING, flags, None
    )
    
    error = kernel32.GetLastError()
    
    if handle == INVALID_HANDLE_VALUE:
        print(f"    FAILED: Error {error}")
        if error == 2:
            print("      ERROR_FILE_NOT_FOUND - device path doesn't exist")
        elif error == 5:
            print("      ERROR_ACCESS_DENIED - permission issue")
        elif error == 6:
            print("      ERROR_INVALID_HANDLE - handle problem")
        elif error == 161:
            print("      ERROR_BAD_PATHNAME - device objects not created")
    else:
        print(f"    SUCCESS: Handle {handle}")
        
        # Quick IOCTL test
        bytes_returned = wintypes.DWORD()
        result = kernel32.DeviceIoControl(
            handle, 0x222058,  # IOCTL_CE_GETVERSION
            None, 0, None, 0,
            ctypes.byref(bytes_returned),
            None
        )
        
        ioctl_error = kernel32.GetLastError()
        print(f"    IOCTL Test: {'SUCCESS' if result else f'Error {ioctl_error}'}")
        
        kernel32.CloseHandle(handle)
    
    print()

print("[*] Summary: Looking for any working CreateFile configuration...")
