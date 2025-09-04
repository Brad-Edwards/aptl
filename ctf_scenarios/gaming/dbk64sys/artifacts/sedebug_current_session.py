import ctypes
import sys

# Windows API definitions  
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Constants
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
    """Enable SeDebugPrivilege in current Administrator session"""
    print("=== Attempting SeDebugPrivilege in current session ===")
    
    # Get current process token
    token = ctypes.c_void_p()
    process_handle = kernel32.GetCurrentProcess()
    
    print(f"Current process handle: {process_handle}")
    
    if not advapi32.OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        error = kernel32.GetLastError()
        print(f"Failed to open process token, error: {error}")
        if error == 6:
            print("Error 6 = ACCESS_DENIED - need elevated privileges")
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
        print("WARNING: Not all privileges were assigned")
        kernel32.CloseHandle(token)
        return False
    elif error == 0:
        print("SUCCESS: SeDebugPrivilege enabled!")
        kernel32.CloseHandle(token)
        return True
    else:
        print(f"Unknown error: {error}")
        kernel32.CloseHandle(token)
        return False

def test_device_access():
    """Test device access after privilege change"""
    print("\n=== Testing Device Access ===")
    
    device_path = r'\\\\.\\DBK64'
    handle = kernel32.CreateFileW(
        device_path,
        0xC0000000,  # GENERIC_READ | GENERIC_WRITE
        0,
        None,
        3,  # OPEN_EXISTING
        0,
        None
    )
    
    error = kernel32.GetLastError()
    
    if handle == -1:
        print(f"Device access FAILED: Handle={handle}, Error={error}")
        if error == 161:
            print("Error 161 = ERROR_BAD_PATHNAME - device path not found")
        elif error == 5:
            print("Error 5 = ACCESS_DENIED - insufficient privileges")
        elif error == 31:
            print("Error 31 = ERROR_GEN_FAILURE - device not functioning")
        return None
    else:
        print(f"Device access SUCCESS: Handle={handle}")
        return handle

def test_ioctl_with_sedebug(handle):
    """Test IOCTL after SeDebugPrivilege enabled"""
    if not handle:
        return
    
    print("\n=== Testing IOCTL with SeDebugPrivilege ===")
    
    # Test the same IOCTL as before
    ioctl_code = 0x9c402000
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
    
    error = kernel32.GetLastError()
    
    if success:
        print(f"BREAKTHROUGH! IOCTL {hex(ioctl_code)} SUCCESS!")
        print(f"Bytes returned: {bytes_returned.value}")
        if bytes_returned.value > 0:
            print(f"Output: {output_buffer.raw[:bytes_returned.value]}")
    else:
        print(f"IOCTL {hex(ioctl_code)}: ERROR {error}")
        if error != 31:
            print(f"CHANGE DETECTED! Error changed from 31 to {error}")

def main():
    print("=== SeDebugPrivilege Test in Current Session ===")
    
    # First test device access without SeDebugPrivilege
    print("Testing device access WITHOUT SeDebugPrivilege...")
    handle_before = test_device_access()
    
    if handle_before:
        print("Testing IOCTL WITHOUT SeDebugPrivilege...")
        test_ioctl_with_sedebug(handle_before)
        kernel32.CloseHandle(handle_before)
    
    # Try to enable SeDebugPrivilege
    sedebug_enabled = enable_debug_privilege()
    
    # Test device access after attempting SeDebugPrivilege
    print("\nTesting device access WITH SeDebugPrivilege attempt...")
    handle_after = test_device_access()
    
    if handle_after:
        test_ioctl_with_sedebug(handle_after)
        kernel32.CloseHandle(handle_after)
    
    print(f"\nSUMMARY:")
    print(f"SeDebugPrivilege enabled: {sedebug_enabled}")
    print(f"Device accessible before: {handle_before is not None}")
    print(f"Device accessible after: {handle_after is not None}")

if __name__ == "__main__":
    main()
