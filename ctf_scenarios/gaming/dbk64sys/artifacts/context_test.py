#!/usr/bin/env python3
"""
DBK64.sys Context Testing
Test if driver behavior changes based on process context
"""

import ctypes
import os
import sys

def test_basic_device_info():
    """Test basic device information and capabilities"""
    kernel32 = ctypes.windll.kernel32
    
    print("=== DBK64 Context Analysis ===")
    print(f"Current Process ID: {os.getpid()}")
    print(f"Python Architecture: {sys.maxsize > 2**32 and '64-bit' or '32-bit'}")
    print()
    
    # Open device with different access modes
    access_modes = [
        (0x80000000, "GENERIC_READ"),
        (0x40000000, "GENERIC_WRITE"), 
        (0xC0000000, "GENERIC_READ|WRITE"),
        (0x100000, "FILE_READ_DATA"),
        (0x120000, "FILE_READ_DATA|FILE_WRITE_DATA"),
    ]
    
    for access, name in access_modes:
        handle = kernel32.CreateFileW(r"\\.\DBK64", access, 0, None, 3, 0, None)
        if handle != -1:
            print(f"✓ Device opened with {name}: handle {handle}")
            
            # Try a simple IOCTL 0 to see if access mode affects response
            bytes_returned = ctypes.c_ulong(0)
            result = kernel32.DeviceIoControl(handle, 0, None, 0, None, 0, ctypes.byref(bytes_returned), None)
            error = kernel32.GetLastError()
            print(f"  IOCTL 0 result: {result}, error: {error}")
            
            kernel32.CloseHandle(handle)
        else:
            error = kernel32.GetLastError()
            print(f"✗ Failed to open with {name}: error {error}")

def test_process_name_spoofing():
    """Test if driver checks process name/path"""
    kernel32 = ctypes.windll.kernel32
    
    print("\\n=== Process Name Analysis ===")
    
    # Get current process name
    import psutil
    current_process = psutil.Process()
    print(f"Current process name: {current_process.name()}")
    print(f"Current process path: {current_process.exe()}")
    
    # Test if renaming our process helps
    # (Note: This is just informational, can't actually rename running process)
    suspicious_names = [
        "cheatengine.exe",
        "dbk64.exe", 
        "game.exe",
        "target.exe"
    ]
    
    print(f"Driver might be checking for specific process names:")
    for name in suspicious_names:
        print(f"  - {name}")

def test_input_data_patterns():
    """Test specific input data patterns that might unlock functionality"""
    kernel32 = ctypes.windll.kernel32
    
    handle = kernel32.CreateFileW(r"\\.\DBK64", 0xC0000000, 0, None, 3, 0, None)
    if handle == -1:
        print("Cannot open device for input testing")
        return
    
    print(f"\\n=== Input Data Pattern Testing ===")
    print(f"Device handle: {handle}")
    
    # Test patterns based on static analysis findings
    test_patterns = [
        # Magic numbers/signatures
        (b"DBK64\\x00\\x00\\x00", "DBK64 signature"),
        (b"\\x44\\x42\\x4B\\x36\\x34", "DBK64 ASCII"),
        (b"\\xDE\\xAD\\xBE\\xEF", "Deadbeef magic"),
        (b"\\xCA\\xFE\\xBA\\xBE", "Cafebabe magic"),
        
        # Process/memory related structures  
        (b"\\x00" * 4 + b"\\x00\\x10\\x00\\x00", "Memory address pattern"),
        (b"\\xFF" * 8, "All 0xFF pattern"),
        (os.getpid().to_bytes(4, 'little'), "Current PID"),
        
        # Common cheat engine patterns
        (b"\\x01\\x00\\x00\\x00" + b"\\x00" * 12, "Structure header"),
        (b"\\x00\\x00\\x00\\x00" + b"\\x01\\x00\\x00\\x00", "Offset + size"),
    ]
    
    for ioctl in [0, 1, 2, 3]:  # Test with switch indices from static analysis
        print(f"\\nTesting IOCTL {ioctl} with various input patterns:")
        
        for data, description in test_patterns:
            input_buffer = ctypes.create_string_buffer(data)
            bytes_returned = ctypes.c_ulong(0)
            output_buffer = ctypes.create_string_buffer(256)
            
            result = kernel32.DeviceIoControl(
                handle, ioctl, input_buffer, len(data),
                output_buffer, 256, ctypes.byref(bytes_returned), None
            )
            
            error = kernel32.GetLastError()
            
            if result:
                print(f"  ✓ SUCCESS with {description}")
                if bytes_returned.value > 0:
                    print(f"    Output ({bytes_returned.value} bytes): {output_buffer.raw[:bytes_returned.value].hex()}")
                break
            elif error != 31:
                print(f"  ! Different error {error} with {description}")
    
    kernel32.CloseHandle(handle)

def main():
    test_basic_device_info()
    test_process_name_spoofing() 
    test_input_data_patterns()
    
    print("\\n=== Analysis Complete ===")
    print("If still getting Error 31, the driver likely requires:")
    print("1. Specific process context (32-bit vs 64-bit)")
    print("2. Authentication handshake sequence")  
    print("3. Kernel-mode caller context")
    print("4. Specific Windows version/environment")

if __name__ == "__main__":
    main()
