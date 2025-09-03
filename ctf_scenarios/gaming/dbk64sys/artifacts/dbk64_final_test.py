#!/usr/bin/env python3
"""
DBK64 Final Test - Comprehensive test of all remaining theories
"""

import ctypes
import sys
import os
from ctypes import wintypes

# Windows API
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

# Privilege structures
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def enable_privilege(privilege_name):
    """Enable a specific privilege"""
    print(f"[*] Enabling {privilege_name}...")
    
    token = ctypes.c_void_p()
    process_handle = kernel32.GetCurrentProcess()
    
    if not advapi32.OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        print(f"[-] Failed to open token: {kernel32.GetLastError()}")
        return False
    
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
        print(f"[-] Failed to lookup privilege: {kernel32.GetLastError()}")
        kernel32.CloseHandle(token)
        return False
    
    token_privileges = TOKEN_PRIVILEGES()
    token_privileges.PrivilegeCount = 1
    token_privileges.Privileges[0].Luid = luid
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(token_privileges), 0, None, None):
        print(f"[-] Failed to adjust privileges: {kernel32.GetLastError()}")
        kernel32.CloseHandle(token)
        return False
    
    error = kernel32.GetLastError()
    if error == 1300:  # ERROR_NOT_ALL_ASSIGNED
        print(f"[-] Privilege not assigned (insufficient rights)")
        kernel32.CloseHandle(token)
        return False
    elif error == 0:
        print(f"[+] {privilege_name} enabled successfully!")
        kernel32.CloseHandle(token)
        return True
    else:
        print(f"[-] Unknown error: {error}")
        kernel32.CloseHandle(token)
        return False

def test_device_with_privileges():
    """Test device communication after enabling all relevant privileges"""
    print("\n=== DBK64 Final Privilege Test ===")
    
    # Enable multiple privileges that could be relevant
    privileges = [
        "SeDebugPrivilege",
        "SeLoadDriverPrivilege", 
        "SeTcbPrivilege",
        "SeSystemtimePrivilege",
        "SeProfileSingleProcessPrivilege"
    ]
    
    enabled_count = 0
    for priv in privileges:
        if enable_privilege(priv):
            enabled_count += 1
    
    print(f"\n[*] Enabled {enabled_count}/{len(privileges)} privileges")
    
    # Test device communication
    print(f"\n[*] Testing device communication...")
    print(f"    Process: {os.path.basename(sys.executable)}")
    print(f"    PID: {os.getpid()}")
    
    handle = kernel32.CreateFileW(
        r'\\.\DBK64',
        GENERIC_READ | GENERIC_WRITE,
        0, None, OPEN_EXISTING, 0, None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        print(f"[-] Device open failed: {kernel32.GetLastError()}")
        return
    
    print(f"[+] Device opened: {handle}")
    
    # Test multiple IOCTL approaches
    test_ioctls = [
        (0, "Raw index 0"),
        (1, "Raw index 1"),
        (0x222034, "CE_INITIALIZE"),
        (0x222058, "CE_GETVERSION"),
        (0x9c402000, "Static analysis pattern 0")
    ]
    
    print(f"\n[*] Testing IOCTLs with elevated privileges...")
    breakthrough = False
    
    for ioctl_code, description in test_ioctls:
        bytes_returned = wintypes.DWORD()
        result = kernel32.DeviceIoControl(
            handle, ioctl_code,
            None, 0, None, 0,
            ctypes.byref(bytes_returned),
            None
        )
        
        error = kernel32.GetLastError()
        if result:
            print(f"[+] BREAKTHROUGH! {description} (0x{ioctl_code:X}) SUCCESS!")
            breakthrough = True
            break
        elif error != 31:
            print(f"[!] CHANGE! {description} (0x{ioctl_code:X}): Error {error} (not 31)")
            breakthrough = True
        else:
            print(f"[-] {description} (0x{ioctl_code:X}): Error 31")
    
    if not breakthrough:
        print(f"\n[-] All IOCTLs still return Error 31")
        print(f"    This suggests the validation barrier is beyond privilege checks")
        print(f"    Possible remaining barriers:")
        print(f"    1. Process architecture (32-bit vs 64-bit)")
        print(f"    2. Specific process name validation") 
        print(f"    3. Advanced anti-analysis techniques")
        print(f"    4. Driver requires specific initialization sequence from userland")
    else:
        print(f"\n[+] BREAKTHROUGH ACHIEVED!")
    
    kernel32.CloseHandle(handle)

def main():
    print("=== DBK64 Comprehensive Final Test ===")
    print("Testing all remaining validation theories...")
    
    # Check if running as administrator
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        print(f"Running as administrator: {bool(is_admin)}")
    except:
        print("Could not determine admin status")
    
    test_device_with_privileges()

if __name__ == "__main__":
    main()
