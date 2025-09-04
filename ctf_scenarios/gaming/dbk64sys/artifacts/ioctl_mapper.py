#!/usr/bin/env python3
"""
DBK64.sys IOCTL Mapper
Based on static analysis findings from dry_run1.md

Key findings from static analysis:
- Driver uses fcn.140003900 as main dispatcher
- IOCTL codes extracted via bit manipulation from IRP structure  
- Uses switch/case with sequential comparisons: cmp dword [var_40h], 0/1/2/3...
- Found hex patterns 83f8XX indicating cmp eax, XX instructions
"""

import ctypes
import sys
from ctypes import wintypes

def test_device_access():
    """Test if we can access the DBK64 device"""
    kernel32 = ctypes.windll.kernel32
    
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = -1
    
    print("=== DBK64 IOCTL Mapper ===")
    print("Based on static analysis of fcn.140003900 dispatcher")
    print()
    
    # Open device
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

def test_ioctl_codes(handle):
    """Test IOCTL codes based on static analysis patterns"""
    kernel32 = ctypes.windll.kernel32
    
    # From static analysis: dispatcher uses sequential comparisons 0,1,2,3...
    # Test both simple indices and common IOCTL patterns
    test_cases = [
        # Sequential values from switch/case analysis
        (0, "Case 0 from dispatcher switch"),
        (1, "Case 1 from dispatcher switch"), 
        (2, "Case 2 from dispatcher switch"),
        (3, "Case 3 from dispatcher switch"),
        (4, "Case 4 from dispatcher switch"),
        (5, "Case 5 from dispatcher switch"),
        (6, "Case 6 from dispatcher switch"),
        (7, "Case 7 from dispatcher switch"),
        (8, "Case 8 from dispatcher switch"),
        (9, "Case 9 from dispatcher switch"),
        (10, "Case 10 from dispatcher switch"),
        
        # Common Windows IOCTL patterns
        (0x222000, "Common driver IOCTL base"),
        (0x222004, "Common driver IOCTL +4"),
        (0x222008, "Common driver IOCTL +8"),
        (0x22200C, "Common driver IOCTL +12"),
        
        # CTL_CODE patterns (FILE_DEVICE_UNKNOWN = 0x22)
        (0x00222000, "CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)"),
        (0x00222004, "CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)"),
        
        # Test some hex patterns found in static analysis
        (0x83f8, "Hex pattern from cmp eax analysis"),
    ]
    
    print(f"\nTesting {len(test_cases)} IOCTL codes...")
    print("=" * 80)
    
    results = []
    
    for ioctl_code, description in test_cases:
        bytes_returned = ctypes.c_ulong(0)
        
        # Call DeviceIoControl
        result = kernel32.DeviceIoControl(
            handle,
            ioctl_code,
            None,  # Input buffer
            0,     # Input buffer size
            None,  # Output buffer  
            0,     # Output buffer size
            ctypes.byref(bytes_returned),
            None   # Overlapped
        )
        
        error_code = kernel32.GetLastError()
        
        status = "SUCCESS" if result else "FAILED"
        print(f"IOCTL 0x{ioctl_code:08X} ({ioctl_code:5d}): {status:7s} | Error: {error_code:3d} | Bytes: {bytes_returned.value:3d} | {description}")
        
        results.append({
            'ioctl': ioctl_code,
            'success': bool(result),
            'error': error_code,
            'bytes_returned': bytes_returned.value,
            'description': description
        })
    
    return results

def analyze_results(results):
    """Analyze IOCTL test results"""
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    
    successful = [r for r in results if r['success']]
    failed = [r for r in results if not r['success']]
    
    print(f"Total IOCTLs tested: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")
    
    if successful:
        print(f"\nSUCCESSFUL IOCTLs:")
        for r in successful:
            print(f"  0x{r['ioctl']:08X} - {r['description']}")
    
    # Group by error codes
    error_groups = {}
    for r in failed:
        error = r['error']
        if error not in error_groups:
            error_groups[error] = []
        error_groups[error].append(r)
    
    print(f"\nERROR CODE ANALYSIS:")
    for error_code, items in error_groups.items():
        print(f"  Error {error_code}: {len(items)} IOCTLs")
        # Show first few examples
        for item in items[:3]:
            print(f"    0x{item['ioctl']:08X} - {item['description']}")
        if len(items) > 3:
            print(f"    ... and {len(items)-3} more")

def main():
    # Test device access
    handle = test_device_access()
    if not handle:
        return 1
    
    try:
        # Test IOCTL codes
        results = test_ioctl_codes(handle)
        
        # Analyze results
        analyze_results(results)
        
        print(f"\nIOCTL mapping complete! Based on static analysis of DBK64.sys fcn.140003900")
        
    finally:
        # Clean up
        kernel32 = ctypes.windll.kernel32
        kernel32.CloseHandle(handle)
        print(f"Device handle closed.")

if __name__ == "__main__":
    main()
