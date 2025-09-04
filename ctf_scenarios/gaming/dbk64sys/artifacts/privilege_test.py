import ctypes
import sys
import os

# Windows API definitions
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
SE_DEBUG_NAME = "SeDebugPrivilege"

# Structures
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong),
                ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID),
                ("Attributes", ctypes.c_ulong)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def enable_debug_privilege():
    """Enable SeDebugPrivilege for the current process"""
    print("=== Enabling SeDebugPrivilege ===")
    
    # Get current process token
    token = ctypes.c_void_p()
    process_handle = kernel32.GetCurrentProcess()
    
    if not advapi32.OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        error = kernel32.GetLastError()
        print(f"Failed to open process token, error: {error}")
        return False
    
    print(f"Process token opened: {token.value}")
    
    # Look up the LUID for SeDebugPrivilege
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        error = kernel32.GetLastError()
        print(f"Failed to lookup privilege value, error: {error}")
        kernel32.CloseHandle(token)
        return False
    
    print(f"SeDebugPrivilege LUID: {luid.LowPart}:{luid.HighPart}")
    
    # Enable the privilege
    token_privileges = TOKEN_PRIVILEGES()
    token_privileges.PrivilegeCount = 1
    token_privileges.Privileges[0].Luid = luid
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(token_privileges), 0, None, None):
        error = kernel32.GetLastError()
        print(f"Failed to adjust token privileges, error: {error}")
        kernel32.CloseHandle(token)
        return False
    
    # Check if privilege was actually enabled
    error = kernel32.GetLastError()
    if error == 1300:  # ERROR_NOT_ALL_ASSIGNED
        print("WARNING: Not all privileges were assigned (need admin rights)")
        kernel32.CloseHandle(token)
        return False
    
    print("SeDebugPrivilege enabled successfully")
    kernel32.CloseHandle(token)
    return True

def test_ioctl_with_privilege():
    """Test IOCTL communication after enabling SeDebugPrivilege"""
    print("\n=== Testing DBK64 Communication ===")
    
    device_path = r'\\\\.\\DBK64'
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
        print(f"Device failed to open, error: {error}")
        return

    print(f"Device opened, handle: {handle}")
    
    # Test a simple IOCTL (index 0 based on static analysis)
    ioctl_code = 0x9c402000  # CTL_CODE format for index 0
    input_buffer = ctypes.create_string_buffer(b"test", 4)
    output_buffer = ctypes.create_string_buffer(256)
    bytes_returned = ctypes.c_ulong()

    success = kernel32.DeviceIoControl(
        handle,
        ioctl_code,
        input_buffer,
        len(input_buffer),
        output_buffer,
        len(output_buffer),
        ctypes.byref(bytes_returned),
        None
    )

    error_code = kernel32.GetLastError()
    
    if success:
        print(f"SUCCESS! IOCTL {hex(ioctl_code)} worked! Bytes returned: {bytes_returned.value}")
        if bytes_returned.value > 0:
            print(f"Output data: {output_buffer.raw[:bytes_returned.value]}")
    else:
        print(f"IOCTL {hex(ioctl_code)}: ERROR {error_code}")
        if error_code != 31:
            print(f"DIFFERENT ERROR CODE! Not Error 31 anymore!")

    # Test a few more IOCTLs to see if the pattern changes
    test_ioctls = [0x9c402004, 0x9c402008, 0x9c40200c]  # indices 1, 2, 3
    
    for ioctl in test_ioctls:
        success = kernel32.DeviceIoControl(
            handle,
            ioctl,
            input_buffer,
            len(input_buffer),
            output_buffer,
            len(output_buffer),
            ctypes.byref(bytes_returned),
            None
        )
        error = kernel32.GetLastError()
        status = "SUCCESS" if success else f"ERROR {error}"
        print(f"IOCTL {hex(ioctl)}: {status}")
        
        if success or error != 31:
            print(f"BREAKTHROUGH! Different behavior detected!")

    kernel32.CloseHandle(handle)
    print("Device handle closed.")

def main():
    print("=== DBK64 Privilege Test ===")
    print("Testing SeDebugPrivilege theory for Error 31 issue")
    
    # First, try to enable SeDebugPrivilege
    if not enable_debug_privilege():
        print("\nFailed to enable SeDebugPrivilege")
        print("   This may require administrator privileges")
        print("   Current test will proceed without privilege")
    
    # Test IOCTL communication
    test_ioctl_with_privilege()

if __name__ == "__main__":
    main()
