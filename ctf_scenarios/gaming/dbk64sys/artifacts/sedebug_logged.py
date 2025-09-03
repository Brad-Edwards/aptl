#!/usr/bin/env python3
"""
Test SeDebugPrivilege with file logging
"""

import ctypes
from ctypes import wintypes

# Open log file
log = open("C:\\Analysis\\sedebug_test_log.txt", "w")

def log_print(msg):
    print(msg)
    log.write(msg + "\n")
    log.flush()

# Windows API definitions
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

log_print("=== SeDebugPrivilege Test ===")

try:
    # Check if running as admin
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    log_print(f"Running as admin: {bool(is_admin)}")
    
    # Get current process token
    token = ctypes.c_void_p()
    process_handle = kernel32.GetCurrentProcess()
    
    if not advapi32.OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        error = kernel32.GetLastError()
        log_print(f"Failed to open process token: Error {error}")
    else:
        log_print("Process token opened successfully")
        
        # Look up SeDebugPrivilege
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            error = kernel32.GetLastError()
            log_print(f"Failed to lookup SeDebugPrivilege: Error {error}")
        else:
            log_print(f"SeDebugPrivilege LUID: {luid.LowPart}:{luid.HighPart}")
            
            # Enable privilege
            token_privileges = TOKEN_PRIVILEGES()
            token_privileges.PrivilegeCount = 1
            token_privileges.Privileges[0].Luid = luid
            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            
            if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(token_privileges), 0, None, None):
                error = kernel32.GetLastError()
                log_print(f"Failed to adjust privileges: Error {error}")
            else:
                error = kernel32.GetLastError()
                if error == 1300:
                    log_print("ERROR_NOT_ALL_ASSIGNED - insufficient rights")
                elif error == 0:
                    log_print("SUCCESS: SeDebugPrivilege enabled!")
                    
                    # Test IOCTL
                    log_print("Testing IOCTL...")
                    handle = kernel32.CreateFileW(
                        r'\\.\CEDRIVER73',
                        0xC0000000, 3, None, 3, 0x40000000, None
                    )
                    
                    if handle == -1:
                        error = kernel32.GetLastError()
                        log_print(f"Device open failed: Error {error}")
                    else:
                        log_print(f"Device opened: Handle {handle}")
                        
                        bytes_returned = wintypes.DWORD()
                        result = kernel32.DeviceIoControl(
                            handle, 0x222058,
                            None, 0, None, 0,
                            ctypes.byref(bytes_returned), None
                        )
                        
                        error = kernel32.GetLastError()
                        if result:
                            log_print("BREAKTHROUGH! IOCTL SUCCESS!")
                        else:
                            log_print(f"IOCTL failed: Error {error}")
                        
                        kernel32.CloseHandle(handle)
                else:
                    log_print(f"Unknown adjustment error: {error}")
        
        kernel32.CloseHandle(token)

except Exception as e:
    log_print(f"Exception: {e}")

log_print("Test complete")
log.close()
