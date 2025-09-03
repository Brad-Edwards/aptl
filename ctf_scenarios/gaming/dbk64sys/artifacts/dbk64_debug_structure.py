#!/usr/bin/env python3
"""
DBK64 Structure Debug - Test different structure sizes and formats
"""

import ctypes
import struct
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)  # 0x00222034
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)  # 0x00222058

print("=== DBK64 Structure Debug ===\n")

# Test 1: Simple device open (no overlapped)
print("[*] Test 1: Simple device open...")
handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    GENERIC_READ | GENERIC_WRITE,
    0,
    None,
    OPEN_EXISTING,
    0,  # No special flags
    None
)

if handle == INVALID_HANDLE_VALUE:
    print(f"[-] Failed to open device! Error: {kernel32.GetLastError()}")
    exit(1)

print(f"[+] Device opened! Handle: {handle}")

# Test 2: Try GETVERSION without initialization
print("\n[*] Test 2: GETVERSION without init...")
out_buffer = ctypes.create_string_buffer(4)
bytes_returned = wintypes.DWORD()

result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_GETVERSION,
    None, 0,
    out_buffer, 4,
    ctypes.byref(bytes_returned),
    None
)

if result:
    version = struct.unpack('<I', out_buffer.raw[:4])[0]
    print(f"[+] SUCCESS! Version: 0x{version:08X}")
else:
    error = kernel32.GetLastError()
    print(f"[-] Failed: Error {error}")

# Test 3: Try different structure sizes for initialization
print("\n[*] Test 3: Testing different init structure sizes...")

test_sizes = [8, 16, 32, 64, 88, 96, 128]

for size in test_sizes:
    print(f"\n  Testing {size}-byte structure...")
    
    # Create structure of specified size, filled with zeros
    if size >= 88:
        # Include event handles at the end for larger structures
        process_event = kernel32.CreateEventW(None, False, False, None)
        thread_event = kernel32.CreateEventW(None, False, False, None)
        
        # Create structure with events at correct offsets
        data = b'\x00' * (size - 16)  # Fill with zeros
        data += struct.pack('<QQ', process_event, thread_event)  # Add events at end
        
        kernel32.CloseHandle(process_event)
        kernel32.CloseHandle(thread_event)
    else:
        data = b'\x00' * size
    
    in_buffer = ctypes.create_string_buffer(data)
    out_buffer = ctypes.create_string_buffer(8)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        IOCTL_CE_INITIALIZE,
        in_buffer, size,
        out_buffer, 8,
        ctypes.byref(bytes_returned),
        None
    )
    
    if result:
        print(f"    [+] SUCCESS with {size} bytes! Returned: {bytes_returned.value}")
        if bytes_returned.value > 0:
            data_out = out_buffer.raw[:bytes_returned.value]
            print(f"    Output: {data_out.hex()}")
        break
    else:
        error = kernel32.GetLastError()
        print(f"    [-] Failed: Error {error}")

# Test 4: Try minimal valid IOCTLs
print("\n[*] Test 4: Testing other IOCTL codes...")

test_ioctls = [
    (0x222010, "IOCTL_CE_TEST"),
    (0x222000, "IOCTL_BASE"),
    (0x222004, "IOCTL_BASE+1"),
    (0x222008, "IOCTL_BASE+2"), 
    (0x22200c, "IOCTL_BASE+3")
]

for ioctl_code, name in test_ioctls:
    result = kernel32.DeviceIoControl(
        handle, ioctl_code,
        None, 0,
        None, 0,
        ctypes.byref(bytes_returned),
        None
    )
    
    error = kernel32.GetLastError()
    status = "SUCCESS" if result else f"Error {error}"
    print(f"  {name} (0x{ioctl_code:08X}): {status}")
    
    if result or error != 31:
        print(f"    [!] Different behavior detected!")

print("\n[*] Cleanup...")
kernel32.CloseHandle(handle)
print("[+] Done!")
