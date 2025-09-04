#!/usr/bin/env python3
"""
DBK64 32-bit Process Test - Test IOCTL communication from 32-bit process
"""

import ctypes
import struct
import platform
from ctypes import wintypes

# Verify we're running 32-bit
print("=== DBK64 32-bit Process Test ===")
print(f"Architecture: {platform.architecture()}")
print(f"Pointer size: {struct.calcsize('P')} bytes")
print(f"Process type: {'32-bit' if struct.calcsize('P') == 4 else '64-bit'}")

if struct.calcsize('P') != 4:
    print("ERROR: Not running in 32-bit process!")
    exit(1)

print("[+] Confirmed 32-bit process context\n")

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# Test both device paths
device_paths = [
    r'\\.\CEDRIVER73',
    r'\\.\DBK64'
]

for device_path in device_paths:
    print(f"[*] Testing {device_path}...")
    
    # Open device with CE exact flags
    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        error = kernel32.GetLastError()
        print(f"  [-] Failed to open: Error {error}")
        continue
    
    print(f"  [+] Device opened! Handle: {handle}")
    
    # Test IOCTLs
    test_ioctls = [
        (0, "Raw index 0"),
        (1, "Raw index 1"),
        (CTL_CODE(0x22, 0x0816, 0, 0), "IOCTL_CE_GETVERSION"),
        (CTL_CODE(0x22, 0x080d, 0, 0), "IOCTL_CE_INITIALIZE"),
        (CTL_CODE(0x22, 0x0804, 0, 0), "IOCTL_CE_TEST"),
        (0x9c402000, "Static analysis pattern 0")
    ]
    
    print(f"  [*] Testing IOCTLs from 32-bit process...")
    breakthrough = False
    
    for ioctl_code, description in test_ioctls:
        # Simple IOCTL test
        bytes_returned = wintypes.DWORD()
        output_buffer = ctypes.create_string_buffer(256)
        
        result = kernel32.DeviceIoControl(
            handle,
            ioctl_code,
            None, 0,
            output_buffer, 256,
            ctypes.byref(bytes_returned),
            None
        )
        
        error = kernel32.GetLastError()
        
        if result:
            print(f"    [+] BREAKTHROUGH! {description} (0x{ioctl_code:X}) SUCCESS!")
            print(f"        Bytes returned: {bytes_returned.value}")
            if bytes_returned.value > 0:
                print(f"        Output: {output_buffer.raw[:bytes_returned.value].hex()}")
            breakthrough = True
        elif error != 31:
            print(f"    [!] CHANGE! {description} (0x{ioctl_code:X}): Error {error} (not 31!)")
            breakthrough = True
        else:
            print(f"    [-] {description} (0x{ioctl_code:X}): Error 31")
    
    if breakthrough:
        print(f"\n  [+] 32-BIT PROCESS BREAKTHROUGH ACHIEVED!")
        
        # Test CE initialization sequence
        print(f"  [*] Testing CE initialization with 32-bit context...")
        
        # Create events
        process_event = kernel32.CreateEventW(None, False, False, "DBKProcList60")
        thread_event = kernel32.CreateEventW(None, False, False, "DBKThreadList60")
        
        if process_event and thread_event:
            # CE initialization structure
            init_struct = struct.pack('<' + 'Q' * 11,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                process_event, thread_event
            )
            
            in_buffer = ctypes.create_string_buffer(init_struct)
            out_buffer = ctypes.create_string_buffer(8)
            
            init_result = kernel32.DeviceIoControl(
                handle,
                CTL_CODE(0x22, 0x080d, 0, 0),  # IOCTL_CE_INITIALIZE
                in_buffer, len(init_struct),
                out_buffer, 8,
                ctypes.byref(bytes_returned),
                None
            )
            
            if init_result:
                print(f"    [+] INITIALIZATION SUCCESS!")
                sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
                print(f"        SDTShadow: 0x{sdt_shadow:016X}")
            else:
                init_error = kernel32.GetLastError()
                print(f"    [-] Initialization failed: Error {init_error}")
            
            kernel32.CloseHandle(process_event)
            kernel32.CloseHandle(thread_event)
    else:
        print(f"  [-] All IOCTLs still return Error 31 from 32-bit process")
    
    kernel32.CloseHandle(handle)
    print()

print("[*] 32-bit process testing complete.")
print("If no breakthrough occurred, the issue is not 32-bit vs 64-bit process context.")
