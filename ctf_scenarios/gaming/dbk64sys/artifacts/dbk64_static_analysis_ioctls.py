#!/usr/bin/env python3
"""
DBK64 Static Analysis IOCTLs - Test the actual patterns found in static analysis
"""

import ctypes
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

print("=== DBK64 Static Analysis IOCTL Test ===\n")

# Open device
handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    GENERIC_READ | GENERIC_WRITE,
    0, None, OPEN_EXISTING, 0, None
)

if handle == INVALID_HANDLE_VALUE:
    print(f"[-] Failed to open device! Error: {kernel32.GetLastError()}")
    exit(1)

print(f"[+] Device opened! Handle: {handle}\n")

# Test the actual patterns from static analysis
print("[*] Testing static analysis patterns...")
print("Based on dispatcher function analysis:")
print("  Found: cmp eax, 0/1/2/3 patterns")
print("  Suggests raw index values, not complex IOCTL codes")

# Test 1: Raw indices (what we found in static analysis)
print("\n[*] Test 1: Raw index values...")
raw_indices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

for index in raw_indices:
    bytes_returned = wintypes.DWORD()
    result = kernel32.DeviceIoControl(
        handle, index,  # Raw index as IOCTL
        None, 0, None, 0,
        ctypes.byref(bytes_returned),
        None
    )
    
    error = kernel32.GetLastError()
    status = "SUCCESS" if result else f"Error {error}"
    print(f"  Index {index}: {status}")
    
    if result or error != 31:
        print(f"    [!] BREAKTHROUGH! Different behavior on index {index}!")

# Test 2: Our original patterns from bit manipulation analysis  
print("\n[*] Test 2: Calculated bit manipulation patterns...")
print("Based on: movzx eax, word [rcx + rax]; shl ecx, 0x10; add eax, ecx")

# These were our calculated patterns that should map to indices 0,1,2,3
calculated_patterns = [
    0x9c402000,  # Should map to index 0
    0x9c402004,  # Should map to index 1  
    0x9c402008,  # Should map to index 2
    0x9c40200c,  # Should map to index 3
]

for i, ioctl in enumerate(calculated_patterns):
    bytes_returned = wintypes.DWORD()
    result = kernel32.DeviceIoControl(
        handle, ioctl,
        None, 0, None, 0,
        ctypes.byref(bytes_returned),
        None
    )
    
    error = kernel32.GetLastError()
    status = "SUCCESS" if result else f"Error {error}"
    print(f"  Pattern 0x{ioctl:08X} (index {i}): {status}")
    
    if result or error != 31:
        print(f"    [!] BREAKTHROUGH! Different behavior!")

# Test 3: Test with simple input data for index 0
print("\n[*] Test 3: Testing with input data...")
test_data = ctypes.create_string_buffer(b"test", 4)
out_buffer = ctypes.create_string_buffer(256)
bytes_returned = wintypes.DWORD()

result = kernel32.DeviceIoControl(
    handle, 0,  # Index 0
    test_data, 4,
    out_buffer, 256,
    ctypes.byref(bytes_returned),
    None
)

error = kernel32.GetLastError()
if result:
    print(f"  [+] SUCCESS with input data! Bytes returned: {bytes_returned.value}")
    if bytes_returned.value > 0:
        print(f"  Output: {out_buffer.raw[:bytes_returned.value]}")
else:
    print(f"  [-] Failed with input data: Error {error}")

# Test 4: Cheat Engine IOCTLs for comparison
print("\n[*] Test 4: Cheat Engine IOCTLs (for comparison)...")
ce_ioctls = [
    (0x222034, "IOCTL_CE_INITIALIZE"),
    (0x222058, "IOCTL_CE_GETVERSION"), 
    (0x222010, "IOCTL_CE_TEST")
]

for ioctl, name in ce_ioctls:
    bytes_returned = wintypes.DWORD()
    result = kernel32.DeviceIoControl(
        handle, ioctl,
        None, 0, None, 0,
        ctypes.byref(bytes_returned),
        None
    )
    
    error = kernel32.GetLastError()
    status = "SUCCESS" if result else f"Error {error}"
    print(f"  {name} (0x{ioctl:08X}): {status}")

print("\n[*] Summary:")
print("If all tests show Error 31, the issue is likely:")
print("1. Process privilege validation (SeDebugPrivilege)")
print("2. Process context validation (32-bit, specific names)")  
print("3. Advanced authentication beyond IOCTL codes")

kernel32.CloseHandle(handle)
print("\n[+] Done!")
