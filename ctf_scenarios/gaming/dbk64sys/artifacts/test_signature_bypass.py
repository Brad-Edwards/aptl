#!/usr/bin/env python3
"""
Test signature bypass by creating dummy .sig file
"""

import ctypes
import os
import sys
from ctypes import wintypes

print("=== DBK64 Signature Bypass Test ===")

# Get current executable path
executable_path = sys.executable
sig_path = executable_path + ".sig"

print(f"Executable: {executable_path}")
print(f"Signature file: {sig_path}")

# Create dummy signature file if it doesn't exist
if not os.path.exists(sig_path):
    print("[*] Creating dummy signature file...")
    try:
        # Create a dummy signature file (this won't be valid, but tests the theory)
        with open(sig_path, 'wb') as f:
            f.write(b'\x00' * 256)  # 256 bytes of zeros as dummy signature
        print(f"[+] Created {sig_path}")
    except Exception as e:
        print(f"[-] Failed to create signature file: {e}")
        exit(1)
else:
    print(f"[+] Signature file already exists")

# Test IOCTL communication
kernel32 = ctypes.windll.kernel32

# Open device
handle = kernel32.CreateFileW(
    r'\\.\CEDRIVER73',
    0xC0000000,  # GENERIC_READ | GENERIC_WRITE
    3,           # FILE_SHARE_READ | FILE_SHARE_WRITE  
    None, 3, 0x40000000, None  # FILE_FLAG_OVERLAPPED
)

if handle == -1:
    error = kernel32.GetLastError()
    print(f"[-] Device open failed: Error {error}")
    exit(1)

print(f"[+] Device opened: Handle {handle}")

# Test simple IOCTL
bytes_returned = wintypes.DWORD()
result = kernel32.DeviceIoControl(
    handle, 0x222058,  # IOCTL_CE_GETVERSION
    None, 0, None, 0,
    ctypes.byref(bytes_returned),
    None
)

error = kernel32.GetLastError()

if result:
    print("[+] BREAKTHROUGH! IOCTL succeeded with dummy signature file!")
    print("This confirms the signature validation theory")
elif error != 31:
    print(f"[!] Different error: {error} (not 31)")
    print("This suggests signature file detection is working")
else:
    print(f"[-] Still Error 31")
    print("Driver may require valid signature, not just presence of .sig file")

kernel32.CloseHandle(handle)

print("\n[*] Test complete.")
print("Next steps if Error 31 persists:")
print("1. Need valid signature from Dark Byte's private key")
print("2. Or find unsigned version of driver")
print("3. Or patch signature check in driver")
