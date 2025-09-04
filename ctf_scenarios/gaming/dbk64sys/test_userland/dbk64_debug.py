#!/usr/bin/env python3
"""
DBK64 Debug Client - Minimal test to understand why IOCTLs fail
"""

import ctypes
import struct
from ctypes import wintypes

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

# Open device
print("[*] Opening \\\\.\\ DBK64...")
handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    GENERIC_READ | GENERIC_WRITE,
    0,
    None,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    None
)

if handle == INVALID_HANDLE_VALUE:
    print(f"[-] Failed to open device! Error: {kernel32.GetLastError()}")
    exit(1)

print(f"[+] Device opened! Handle: {handle}\n")

# Try IOCTL_CE_GETVERSION with exact value from source
# CTL_CODE(0x22, 0x816, 0, 0) = 0x00222058
IOCTL_CE_GETVERSION = 0x00222058

print(f"[*] Sending IOCTL_CE_GETVERSION (0x{IOCTL_CE_GETVERSION:08X})...")

# Prepare buffers
in_buffer = None
in_size = 0
out_buffer = ctypes.create_string_buffer(4)  # DWORD for version
bytes_returned = wintypes.DWORD()

# Call DeviceIoControl
result = kernel32.DeviceIoControl(
    handle,                # Device handle
    IOCTL_CE_GETVERSION,  # IOCTL code
    in_buffer,            # Input buffer
    in_size,              # Input size
    out_buffer,           # Output buffer  
    4,                    # Output buffer size
    ctypes.byref(bytes_returned),  # Bytes returned
    None                  # Overlapped
)

if result:
    version = struct.unpack('<I', out_buffer.raw)[0]
    print(f"[+] SUCCESS! Driver version: 0x{version:08X}")
    print(f"    Bytes returned: {bytes_returned.value}")
else:
    error = kernel32.GetLastError()
    print(f"[-] FAILED! Error code: {error}")
    
    # Decode error
    error_messages = {
        1: "ERROR_INVALID_FUNCTION - IOCTL not recognized",
        5: "ERROR_ACCESS_DENIED - Access denied",
        6: "ERROR_INVALID_HANDLE - Invalid handle",
        31: "ERROR_GEN_FAILURE - Device not functioning",
        50: "ERROR_NOT_SUPPORTED - Request not supported",
        87: "ERROR_INVALID_PARAMETER - Invalid parameter",
        998: "ERROR_NOACCESS - Invalid access to memory",
        1784: "ERROR_INVALID_USER_BUFFER - Invalid user buffer"
    }
    
    if error in error_messages:
        print(f"    Meaning: {error_messages[error]}")

# Try a different approach - send IOCTL_CE_TEST
print(f"\n[*] Trying IOCTL_CE_TEST (0x00222010)...")
IOCTL_CE_TEST = 0x00222010

# Test with some input data
test_input = struct.pack('<Q', 0x1234567890ABCDEF)  # 8 bytes
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
    if bytes_returned.value > 0:
        print(f"    Data: {out_buffer.raw[:bytes_returned.value].hex()}")
else:
    error = kernel32.GetLastError()
    print(f"[-] FAILED! Error code: {error}")

# Close handle
kernel32.CloseHandle(handle)
print("\n[*] Device handle closed")