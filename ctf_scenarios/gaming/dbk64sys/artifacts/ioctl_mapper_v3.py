#!/usr/bin/env python3
"""
DBK64.sys IOCTL Mapper V3 - Simplified version
Focus on correct CTL_CODE testing without complex data structures
"""

import ctypes

def CTL_CODE(device_type, function, method, access):
    """Generate Windows CTL_CODE IOCTL values"""
    return (device_type << 16) | (access << 14) | (function << 2) | method

def main():
    kernel32 = ctypes.windll.kernel32
    
    print("=== DBK64 IOCTL Mapper V3 ===")
    print("Testing CTL_CODE formatted IOCTLs")
    
    # Open device
    handle = kernel32.CreateFileW(r"\\.\DBK64", 0xC0000000, 0, None, 3, 0, None)
    if handle == -1:
        print("Failed to open device")
        return
    
    print(f"Device opened, handle: {handle}")
    
    # Windows constants
    FILE_DEVICE_UNKNOWN = 0x00000022
    METHOD_BUFFERED = 0
    METHOD_NEITHER = 3
    FILE_ANY_ACCESS = 0
    
    print("Testing CTL_CODE patterns...")
    
    successful = []
    interesting = []
    
    # Test function codes 0-50 with proper CTL_CODE format
    for func in range(51):
        for method in [METHOD_BUFFERED, METHOD_NEITHER]:
            ioctl = CTL_CODE(FILE_DEVICE_UNKNOWN, func, method, FILE_ANY_ACCESS)
            
            bytes_returned = ctypes.c_ulong(0)
            result = kernel32.DeviceIoControl(
                handle, ioctl, None, 0, None, 0, 
                ctypes.byref(bytes_returned), None
            )
            
            error = kernel32.GetLastError()
            method_name = "BUFFERED" if method == METHOD_BUFFERED else "NEITHER"
            
            if result:
                print(f"SUCCESS: IOCTL 0x{ioctl:08X} (func={func}, {method_name})")
                successful.append(ioctl)
            elif error != 31:
                print(f"INTERESTING: IOCTL 0x{ioctl:08X} (func={func}, {method_name}) - Error {error}")
                interesting.append((ioctl, error))
    
    # Test some specific memory manipulation patterns
    specific_tests = [
        0x9c402000, 0x9c402004, 0x9c402008, 0x9c40200c,
        0x83010000, 0x83010004, 0x83010008, 0x8301000c,
        0x22c000, 0x22c004, 0x22c008, 0x22c00c,
    ]
    
    print("\\nTesting specific memory driver patterns...")
    for ioctl in specific_tests:
        bytes_returned = ctypes.c_ulong(0)
        result = kernel32.DeviceIoControl(
            handle, ioctl, None, 0, None, 0,
            ctypes.byref(bytes_returned), None
        )
        error = kernel32.GetLastError()
        
        if result:
            print(f"SUCCESS: Specific IOCTL 0x{ioctl:08X}")
            successful.append(ioctl)
        elif error != 31:
            print(f"INTERESTING: Specific IOCTL 0x{ioctl:08X} - Error {error}")
            interesting.append((ioctl, error))
    
    print("\\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Successful IOCTLs: {len(successful)}")
    for ioctl in successful:
        print(f"  0x{ioctl:08X}")
    
    print(f"\\nInteresting (non-31) errors: {len(interesting)}")
    for ioctl, error in interesting:
        print(f"  0x{ioctl:08X} - Error {error}")
    
    if not successful and not interesting:
        print("All IOCTLs returned Error 31")
        print("Driver may require:")
        print("- Specific authentication/setup sequence")
        print("- Input data validation")
        print("- Process context requirements")
    
    kernel32.CloseHandle(handle)

if __name__ == "__main__":
    main()
