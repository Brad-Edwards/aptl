#!/usr/bin/env python3
"""
Test proper SeDebugPrivilege enablement in process token
Based on source analysis showing SeSinglePrivilegeCheck requirement
"""

import ctypes
import sys
from ctypes import wintypes

# Windows API definitions
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Constants
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000

# Structures
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def enable_sedebug_privilege():
    """Enable SeDebugPrivilege in current process token"""
    print("[*] Enabling SeDebugPrivilege in process token...")
    
    # Get current process token
    token = ctypes.c_void_p()
    process_handle = kernel32.GetCurrentProcess()
    
    if not advapi32.OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        error = kernel32.GetLastError()
        print(f"[-] Failed to open process token: Error {error}")
        return False
    
    print(f"[+] Process token opened")
    
    # Look up SeDebugPrivilege LUID
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        error = kernel32.GetLastError()
        print(f"[-] Failed to lookup SeDebugPrivilege: Error {error}")
        kernel32.CloseHandle(token)
        return False
    
    print(f"[+] SeDebugPrivilege LUID: {luid.LowPart}:{luid.HighPart}")
    
    # Enable the privilege
    token_privileges = TOKEN_PRIVILEGES()
    token_privileges.PrivilegeCount = 1
    token_privileges.Privileges[0].Luid = luid
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(token_privileges), 0, None, None):
        error = kernel32.GetLastError()
        print(f"[-] Failed to adjust token privileges: Error {error}")
        kernel32.CloseHandle(token)
        return False
    
    # Check if adjustment succeeded
    error = kernel32.GetLastError()
    if error == 1300:  # ERROR_NOT_ALL_ASSIGNED
        print(f"[-] SeDebugPrivilege not assigned (insufficient rights)")
        kernel32.CloseHandle(token)
        return False
    elif error == 0:
        print(f"[+] SeDebugPrivilege enabled in process token")
        kernel32.CloseHandle(token)
        return True
    else:
        print(f"[-] Unknown error: {error}")
        kernel32.CloseHandle(token)
        return False

def test_ioctl_with_sedebug():
    """Test IOCTL after enabling SeDebugPrivilege"""
    print("\n[*] Testing IOCTL with SeDebugPrivilege enabled...")
    
    # Open device
    handle = kernel32.CreateFileW(
        r'\\.\CEDRIVER73',
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None
    )
    
    if handle == -1:
        error = kernel32.GetLastError()
        print(f"[-] Device open failed: Error {error}")
        return False
    
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
        print(f"[+] BREAKTHROUGH! IOCTL succeeded after SeDebugPrivilege fix!")
        return True
    elif error != 31:
        print(f"[!] Different error: {error} (not 31) - progress!")
        return False
    else:
        print(f"[-] Still Error 31 - SeDebugPrivilege not the complete solution")
        return False
    
    kernel32.CloseHandle(handle)

def main():
    print("=== SeDebugPrivilege Proper Test ===")
    print("Testing driver source analysis theory:")
    print("  SeSinglePrivilegeCheck(sedebugprivUID, UserMode)")
    
    # Enable SeDebugPrivilege
    if not enable_sedebug_privilege():
        print("[-] Failed to enable SeDebugPrivilege - test inconclusive")
        return
    
    # Test IOCTL
    if test_ioctl_with_sedebug():
        print("\n[+] SUCCESS: SeDebugPrivilege was the missing piece!")
        print("Now can proceed to test signature validation if TOBESIGNED build")
    else:
        print("\n[-] SeDebugPrivilege alone not sufficient")
        print("Likely needs BOTH SeDebugPrivilege AND valid signature")
        print("Next: Test with legitimate Cheat Engine signature file")

if __name__ == "__main__":
    main()
