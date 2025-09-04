#!/usr/bin/env python3
"""
DBK64.sys IOCTL Reverse Engineering
Based on static analysis bit manipulation patterns

Key findings from dry_run1.md:
- movzx eax, word [rcx + rax]  ; Extract IOCTL bits  
- shl ecx, 0x10               ; Bit manipulation
- add eax, ecx                ; Combine IOCTL components
- Switch compares against indices 0, 1, 2, 3

Goal: Reverse the bit manipulation to find IOCTLs that map to indices 0-3
"""

import ctypes

def analyze_ioctl_transformation():
    """
    Analyze how the driver transforms IOCTL codes to switch indices
    
    From static analysis:
    1. Extract word from [rcx + rax] (IRP structure offset)
    2. Shift left by 0x10 (16 bits)  
    3. Add to extracted value
    4. Result becomes switch index
    
    Need to find IOCTLs that produce indices 0, 1, 2, 3
    """
    
    print("=== DBK64 IOCTL Transformation Analysis ===")
    print("Reverse engineering bit manipulation from static analysis")
    print()
    
    # The transformation appears to be:
    # 1. Extract specific bits from IOCTL
    # 2. Perform bit manipulation  
    # 3. Map result to switch index
    
    # Common IOCTL patterns that might work
    # Standard Windows IOCTL format: Device(16) | Access(2) | Function(12) | Method(2)
    
    # Try IOCTLs where function code alone might map to indices 0-3
    test_ioctls = []
    
    # Method 1: Try raw indices as IOCTLs
    for i in range(4):
        test_ioctls.append((i, f"Raw index {i}"))
    
    # Method 2: Try function codes in CTL_CODE format that might map to indices
    FILE_DEVICE_UNKNOWN = 0x22
    METHOD_BUFFERED = 0
    FILE_ANY_ACCESS = 0
    
    def CTL_CODE(device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method
    
    # Try function codes that might map to our target indices
    for func in range(4):
        ioctl = CTL_CODE(FILE_DEVICE_UNKNOWN, func, METHOD_BUFFERED, FILE_ANY_ACCESS)
        test_ioctls.append((ioctl, f"CTL_CODE func={func}"))
    
    # Method 3: Try bit patterns that might survive the transformation
    # If transformation is: (value >> 16) & 0xF or similar masking
    for i in range(4):
        # Try patterns that might extract to our indices
        candidates = [
            i << 16,           # Index in high bits
            i << 12,           # Index in function field  
            i << 2,            # Index in method field
            (i << 16) | (FILE_DEVICE_UNKNOWN << 16),  # Combined
        ]
        for candidate in candidates:
            test_ioctls.append((candidate, f"Bit pattern {i} variant"))
    
    return test_ioctls

def test_reverse_engineered_ioctls():
    """Test the reverse engineered IOCTL candidates"""
    
    kernel32 = ctypes.windll.kernel32
    
    # Open device
    handle = kernel32.CreateFileW(r"\\.\DBK64", 0xC0000000, 0, None, 3, 0, None)
    if handle == -1:
        print("Failed to open device")
        return
    
    print(f"Device opened, handle: {handle}")
    
    candidates = analyze_ioctl_transformation()
    
    print(f"Testing {len(candidates)} reverse-engineered IOCTL candidates...")
    print("=" * 80)
    
    successes = []
    interesting = []
    
    for ioctl, description in candidates:
        bytes_returned = ctypes.c_ulong(0)
        
        # Test with and without input data
        for input_data, data_desc in [(None, "no input"), (b"\\x00" * 8, "8 null bytes")]:
            if input_data:
                input_buffer = ctypes.create_string_buffer(input_data)
                input_size = len(input_data)
                input_ptr = input_buffer
            else:
                input_ptr = None
                input_size = 0
            
            result = kernel32.DeviceIoControl(
                handle, ioctl, input_ptr, input_size, None, 0,
                ctypes.byref(bytes_returned), None
            )
            
            error = kernel32.GetLastError()
            
            if result:
                print(f"SUCCESS: 0x{ioctl:08X} ({ioctl:10d}) - {description} ({data_desc})")
                successes.append((ioctl, description, data_desc))
                break  # Found success, no need to test more input variants
            elif error != 31:
                print(f"INTERESTING: 0x{ioctl:08X} - Error {error} - {description} ({data_desc})")
                interesting.append((ioctl, error, description, data_desc))
                break  # Found non-31 error, record it
        
        # Reset error state for next test
        kernel32.SetLastError(0)
    
    print("\\n" + "=" * 80)
    print("REVERSE ENGINEERING RESULTS")
    print("=" * 80)
    
    if successes:
        print(f"SUCCESSFUL IOCTLs ({len(successes)}):")
        for ioctl, desc, data_desc in successes:
            print(f"  0x{ioctl:08X} - {desc} ({data_desc})")
        print("\\n🎯 BREAKTHROUGH: Found working IOCTL codes!")
    
    if interesting:
        print(f"\\nINTERESTING (non-31) errors ({len(interesting)}):")
        for ioctl, error, desc, data_desc in interesting:
            print(f"  0x{ioctl:08X} - Error {error} - {desc} ({data_desc})")
        print("\\n🔍 PROGRESS: Found IOCTLs with different behavior!")
    
    if not successes and not interesting:
        print("All tests still return Error 31")
        print("\\nNext steps:")
        print("- Analyze IRP structure offsets more carefully")
        print("- Check for process context requirements") 
        print("- Test with specific input data patterns")
        print("- Use kernel debugger to trace IOCTL processing")
    
    kernel32.CloseHandle(handle)

def main():
    test_reverse_engineered_ioctls()

if __name__ == "__main__":
    main()
