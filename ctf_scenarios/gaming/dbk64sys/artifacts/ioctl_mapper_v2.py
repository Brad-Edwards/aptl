#!/usr/bin/env python3
"""
DBK64.sys IOCTL Mapper V2
Advanced testing based on Error 31 analysis

All simple IOCTL codes return Error 31, suggesting:
1. Driver expects properly formatted CTL_CODE values
2. Driver may need specific input data structures
3. Driver validates IOCTL format before processing
"""

import ctypes
import struct
from ctypes import wintypes

def CTL_CODE(device_type, function, method, access):
    """Generate Windows CTL_CODE IOCTL values"""
    return (device_type << 16) | (access << 14) | (function << 2) | method

def test_device_access():
    """Test if we can access the DBK64 device"""
    kernel32 = ctypes.windll.kernel32
    
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = -1
    
    print("=== DBK64 IOCTL Mapper V2 ===")
    print("Testing proper CTL_CODE formatted IOCTLs")
    print()
    
    device_path = r"\\.\DBK64"
    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        error = kernel32.GetLastError()
        print(f"ERROR: Cannot open {device_path}, error: {error}")
        return None
    
    print(f"SUCCESS: Opened {device_path}, handle: {handle}")
    return handle

def generate_ioctl_candidates():
    """Generate IOCTL candidates using proper CTL_CODE format"""
    
    # Common Windows constants
    FILE_DEVICE_UNKNOWN = 0x00000022
    FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017
    FILE_DEVICE_SECURE = 0x00000039
    
    METHOD_BUFFERED = 0
    METHOD_IN_DIRECT = 1
    METHOD_OUT_DIRECT = 2
    METHOD_NEITHER = 3
    
    FILE_ANY_ACCESS = 0
    FILE_READ_ACCESS = 1
    FILE_WRITE_ACCESS = 2
    
    candidates = []
    
    # Test various device types with common function codes
    device_types = [
        (FILE_DEVICE_UNKNOWN, "FILE_DEVICE_UNKNOWN"),
        (FILE_DEVICE_PHYSICAL_NETCARD, "FILE_DEVICE_PHYSICAL_NETCARD"), 
        (FILE_DEVICE_SECURE, "FILE_DEVICE_SECURE"),
        (0x8000, "Custom device type 0x8000"),
        (0x9000, "Custom device type 0x9000"),
    ]
    
    methods = [
        (METHOD_BUFFERED, "METHOD_BUFFERED"),
        (METHOD_IN_DIRECT, "METHOD_IN_DIRECT"),
        (METHOD_OUT_DIRECT, "METHOD_OUT_DIRECT"),
        (METHOD_NEITHER, "METHOD_NEITHER"),
    ]
    
    access_types = [
        (FILE_ANY_ACCESS, "FILE_ANY_ACCESS"),
        (FILE_READ_ACCESS, "FILE_READ_ACCESS"),
        (FILE_WRITE_ACCESS, "FILE_WRITE_ACCESS"),
    ]
    
    # Generate combinations for function codes 0-20
    for func_code in range(21):
        for dev_type, dev_name in device_types[:2]:  # Limit to avoid too many tests
            for method, method_name in methods[:2]:
                for access, access_name in access_types[:1]:  # Just FILE_ANY_ACCESS
                    ioctl = CTL_CODE(dev_type, func_code, method, access)
                    desc = f"CTL_CODE({dev_name}, {func_code}, {method_name}, {access_name})"
                    candidates.append((ioctl, desc))
    
    # Add some specific patterns that might be used by DBK64
    # Based on common cheat engine / memory manipulation drivers
    dbk_specific = [
        (0x9c402000, "DBK64 specific pattern 1"),
        (0x9c402004, "DBK64 specific pattern 2"), 
        (0x9c402008, "DBK64 specific pattern 3"),
        (0x83044800, "Memory read pattern"),
        (0x83044804, "Memory write pattern"),
        (0x83044808, "Process attach pattern"),
    ]
    
    candidates.extend(dbk_specific)
    return candidates

def test_ioctl_with_data(handle, ioctl_code, description):
    """Test IOCTL with various input data patterns"""
    kernel32 = ctypes.windll.kernel32
    
    # Test cases with different input data
    test_cases = [
        (None, 0, "No input data"),
        (b"\\x00\\x00\\x00\\x00", 4, "4 null bytes"),
        (b"\\x01\\x00\\x00\\x00", 4, "DWORD value 1"),
        (struct.pack("<Q", 0), 8, "QWORD value 0"),
        (struct.pack("<Q", 0x1000), 8, "QWORD value 0x1000"),
        (b"DBK64TEST", 9, "String input"),
    ]
    
    best_result = None
    
    for input_data, input_size, data_desc in test_cases:
        bytes_returned = ctypes.c_ulong(0)
        output_buffer = ctypes.create_string_buffer(1024)  # Buffer for output
        
        if input_data:
            input_buffer = ctypes.create_string_buffer(input_data, input_size)
            input_ptr = input_buffer
        else:
            input_ptr = None
            input_size = 0
        
        result = kernel32.DeviceIoControl(
            handle,
            ioctl_code,
            input_ptr,
            input_size,
            output_buffer,
            1024,
            ctypes.byref(bytes_returned),
            None
        )
        
        error_code = kernel32.GetLastError()
        
        # Track the best result (success or different error)
        if result or (best_result is None) or (error_code != 31):
            best_result = {
                'success': bool(result),
                'error': error_code,
                'bytes_returned': bytes_returned.value,
                'data_desc': data_desc,
                'output': output_buffer.raw[:bytes_returned.value] if bytes_returned.value > 0 else b''
            }
        
        # Stop on first success
        if result:
            break
    
    return best_result

def main():
    handle = test_device_access()
    if not handle:
        return 1
    
    kernel32 = ctypes.windll.kernel32
    
    try:
        candidates = generate_ioctl_candidates()
        print(f"Testing {len(candidates)} IOCTL candidates with proper CTL_CODE format...")
        print("=" * 100)
        
        successful = []
        interesting = []  # Non-31 errors
        
        for ioctl_code, description in candidates:
            result = test_ioctl_with_data(handle, ioctl_code, description)
            
            status = "SUCCESS" if result['success'] else "FAILED"
            error = result['error']
            bytes_ret = result['bytes_returned']
            data_desc = result['data_desc']
            
            print(f"IOCTL 0x{ioctl_code:08X}: {status:7s} | Error: {error:3d} | Bytes: {bytes_ret:3d} | {data_desc} | {description}")
            
            if result['success']:
                successful.append((ioctl_code, description, result))
            elif error != 31:
                interesting.append((ioctl_code, description, result))
        
        print("\n" + "=" * 100)
        print("FINAL ANALYSIS")
        print("=" * 100)
        
        if successful:
            print(f"SUCCESSFUL IOCTLs ({len(successful)}):")
            for ioctl, desc, result in successful:
                print(f"  0x{ioctl:08X} - {desc}")
                if result['output']:
                    print(f"    Output: {result['output'].hex()}")
        
        if interesting:
            print(f"\\nINTERESTING (non-31) errors ({len(interesting)}):")
            for ioctl, desc, result in interesting:
                print(f"  0x{ioctl:08X} - Error {result['error']} - {desc}")
        
        if not successful and not interesting:
            print("All IOCTLs failed with Error 31 - Driver may need specific authentication or setup")
            
    finally:
        kernel32.CloseHandle(handle)
        print(f"\\nDevice handle closed.")

if __name__ == "__main__":
    main()
