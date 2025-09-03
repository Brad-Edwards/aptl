#!/usr/bin/env python3
"""
Verify SeDebugPrivilege status in current process
"""

import ctypes
from ctypes import wintypes
import sys

# Constants
SE_DEBUG_NAME = "SeDebugPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

# Structures
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", ctypes.c_long),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]

def main():
    print("=== SeDebugPrivilege Verification ===")
    
    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32
    
    # Get current process token
    token = wintypes.HANDLE()
    current_process = kernel32.GetCurrentProcess()
    
    result = advapi32.OpenProcessToken(
        current_process,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token)
    )
    
    if not result:
        error = kernel32.GetLastError()
        print(f"[-] OpenProcessToken failed: Error {error}")
        return 1
    
    print(f"[+] Process token opened: {token.value}")
    
    # Look up SeDebugPrivilege LUID
    luid = LUID()
    result = advapi32.LookupPrivilegeValueW(
        None,
        SE_DEBUG_NAME,
        ctypes.byref(luid)
    )
    
    if not result:
        error = kernel32.GetLastError()
        print(f"[-] LookupPrivilegeValue failed: Error {error}")
        kernel32.CloseHandle(token)
        return 1
    
    print(f"[+] SeDebugPrivilege LUID: {luid.LowPart}:{luid.HighPart}")
    
    # Enable the privilege
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    result = advapi32.AdjustTokenPrivileges(
        token,
        False,
        ctypes.byref(tp),
        0,
        None,
        None
    )
    
    if not result:
        error = kernel32.GetLastError()
        print(f"[-] AdjustTokenPrivileges failed: Error {error}")
        kernel32.CloseHandle(token)
        return 1
    
    print("[+] SeDebugPrivilege enabled successfully!")
    
    # Now test the driver
    print("\n[*] Testing DBK64 driver communication...")
    
    # Open device
    handle = kernel32.CreateFileW(
        r'\\.\CEDRIVER73',
        0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
        None,
        3,  # OPEN_EXISTING
        0x40000000,  # FILE_FLAG_OVERLAPPED
        None
    )
    
    if handle == -1:
        error = kernel32.GetLastError()
        print(f"[-] CreateFileW failed: Error {error}")
        kernel32.CloseHandle(token)
        return 1
    
    print(f"[+] Device opened successfully: Handle {handle}")
    
    # Test IOCTL_CE_INITIALIZE
    IOCTL_CE_INITIALIZE = 0x00222034
    
    # Create named events (like CE does)
    process_event = kernel32.CreateEventW(None, True, False, "DBKProcList60")
    thread_event = kernel32.CreateEventW(None, True, False, "DBKThreadList60")
    
    if process_event == 0 or thread_event == 0:
        error = kernel32.GetLastError()
        print(f"[-] CreateEvent failed: Error {error}")
        kernel32.CloseHandle(handle)
        kernel32.CloseHandle(token)
        return 1
    
    print(f"[+] Events created: Process={process_event}, Thread={thread_event}")
    
    # Build initialization structure (88 bytes as per CE source)
    init_struct = bytearray(88)
    
    # Fill with CE's initialization data
    struct.pack_into('<I', init_struct, 0, 0x00000001)  # Some flag
    struct.pack_into('<Q', init_struct, 80, process_event)  # Process event at offset 80
    struct.pack_into('<Q', init_struct, 88-8, thread_event)  # Thread event at offset 80 (88-8)
    
    print("[*] Sending IOCTL_CE_INITIALIZE...")
    
    bytes_returned = wintypes.DWORD()
    result = kernel32.DeviceIoControl(
        handle,
        IOCTL_CE_INITIALIZE,
        init_struct,
        len(init_struct),
        None,
        0,
        ctypes.byref(bytes_returned),
        None
    )
    
    if result:
        print("[+] SUCCESS! IOCTL_CE_INITIALIZE succeeded!")
        print(f"[+] Bytes returned: {bytes_returned.value}")
    else:
        error = kernel32.GetLastError()
        print(f"[-] IOCTL_CE_INITIALIZE failed: Error {error}")
    
    # Cleanup
    kernel32.CloseHandle(process_event)
    kernel32.CloseHandle(thread_event)
    kernel32.CloseHandle(handle)
    kernel32.CloseHandle(token)
    
    return 0 if result else 1

if __name__ == "__main__":
    sys.exit(main())
