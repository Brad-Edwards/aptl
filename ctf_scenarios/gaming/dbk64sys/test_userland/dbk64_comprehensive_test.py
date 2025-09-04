#!/usr/bin/env python3
"""
DBK64 Comprehensive Test - Tests all discovered requirements
Run this on the Windows machine to see what actually works
"""

import ctypes
import struct
from ctypes import wintypes
import sys

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1

# Token privileges
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# LUID structure
class LUID(ctypes.Structure):
    _fields_ = [
        ('LowPart', wintypes.DWORD),
        ('HighPart', ctypes.c_long)
    ]

# LUID_AND_ATTRIBUTES structure
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', wintypes.DWORD)
    ]

# TOKEN_PRIVILEGES structure
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', wintypes.DWORD),
        ('Privileges', LUID_AND_ATTRIBUTES * 1)
    ]

def CTL_CODE(DeviceType, Function, Method, Access):
    """Create Windows IOCTL code"""
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# IOCTL codes
IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)  # 0x00222034
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)  # 0x00222058
IOCTL_CE_TEST = CTL_CODE(0x22, 0x0804, 0, 0)       # 0x00222010

def enable_debug_privilege():
    """Enable SeDebugPrivilege"""
    h_token = wintypes.HANDLE()
    
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        ctypes.byref(h_token)
    ):
        return False, f"Failed to open token: {kernel32.GetLastError()}"
    
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(
        None,
        SE_DEBUG_NAME,
        ctypes.byref(luid)
    ):
        kernel32.CloseHandle(h_token)
        return False, f"Failed to lookup privilege: {kernel32.GetLastError()}"
    
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    if not advapi32.AdjustTokenPrivileges(
        h_token,
        False,
        ctypes.byref(tp),
        ctypes.sizeof(tp),
        None,
        None
    ):
        kernel32.CloseHandle(h_token)
        return False, f"Failed to adjust: {kernel32.GetLastError()}"
    
    error = kernel32.GetLastError()
    kernel32.CloseHandle(h_token)
    
    if error == 1300:
        return False, "Not all privileges assigned (need admin?)"
    return True, "Success"

def test_open_device(flags_desc, desired_access, share_mode, flags):
    """Test opening device with specific flags"""
    handle = kernel32.CreateFileW(
        r'\\.\DBK64',
        desired_access,
        share_mode,
        None,
        OPEN_EXISTING,
        flags,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        return None, kernel32.GetLastError()
    return handle, 0

def test_ioctl(handle, ioctl_code, ioctl_name, in_data=None, out_size=256):
    """Test an IOCTL"""
    if in_data:
        in_buffer = ctypes.create_string_buffer(in_data)
        in_size = len(in_data)
    else:
        in_buffer = None
        in_size = 0
    
    out_buffer = ctypes.create_string_buffer(out_size)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        ioctl_code,
        in_buffer,
        in_size,
        out_buffer,
        out_size,
        ctypes.byref(bytes_returned),
        None
    )
    
    if result:
        return True, bytes_returned.value, out_buffer.raw[:bytes_returned.value]
    else:
        return False, kernel32.GetLastError(), None

print("=== DBK64 Comprehensive Test ===\n")

# Test 1: Try without privileges first
print("[TEST 1] Opening device WITHOUT SeDebugPrivilege...")
handle, error = test_open_device(
    "No privileges, basic flags",
    GENERIC_READ | GENERIC_WRITE,
    0,
    FILE_ATTRIBUTE_NORMAL
)

if handle:
    print(f"  [+] Opened! Handle: {handle}")
    success, error, _ = test_ioctl(handle, IOCTL_CE_GETVERSION, "GETVERSION", None, 4)
    if success:
        print(f"  [+] GETVERSION worked WITHOUT privileges!")
    else:
        print(f"  [-] GETVERSION failed: Error {error}")
    kernel32.CloseHandle(handle)
else:
    print(f"  [-] Failed to open: Error {error}")

print()

# Test 2: Enable privileges and try again
print("[TEST 2] Enabling SeDebugPrivilege...")
success, msg = enable_debug_privilege()
if success:
    print(f"  [+] {msg}")
else:
    print(f"  [-] {msg}")
    print("  [!] Continuing anyway...")

print()

# Test 3: Try different CreateFile combinations
test_configs = [
    ("Basic", GENERIC_READ | GENERIC_WRITE, 0, FILE_ATTRIBUTE_NORMAL),
    ("With Overlapped", GENERIC_READ | GENERIC_WRITE, 0, FILE_FLAG_OVERLAPPED),
    ("With Sharing", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL),
    ("CE Exact", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_OVERLAPPED),
]

working_config = None
for i, (desc, access, share, flags) in enumerate(test_configs, 3):
    print(f"[TEST {i}] Opening with {desc}...")
    handle, error = test_open_device(desc, access, share, flags)
    
    if handle:
        print(f"  [+] Opened! Handle: {handle}")
        
        # Test GETVERSION
        success, err_or_bytes, data = test_ioctl(handle, IOCTL_CE_GETVERSION, "GETVERSION", None, 4)
        if success:
            if err_or_bytes >= 4:
                version = struct.unpack('<I', data[:4])[0]
                print(f"  [+] GETVERSION SUCCESS! Version: 0x{version:08X}")
                working_config = (desc, access, share, flags, handle)
                break  # Found working config!
            else:
                print(f"  [?] GETVERSION returned but only {err_or_bytes} bytes")
        else:
            print(f"  [-] GETVERSION failed: Error {err_or_bytes}")
        
        if not working_config:
            kernel32.CloseHandle(handle)
    else:
        print(f"  [-] Failed to open: Error {error}")
    print()

# Test 4: If we found a working config, test more IOCTLs
if working_config:
    desc, access, share, flags, handle = working_config
    print(f"[SUCCESS] Found working configuration: {desc}")
    print("Testing additional IOCTLs...\n")
    
    # Create events for initialization
    process_event = kernel32.CreateEventW(None, False, False, None)
    thread_event = kernel32.CreateEventW(None, False, False, None)
    print(f"Created events - Process: {process_event}, Thread: {thread_event}")
    
    # Test INITIALIZE
    print("[*] Testing INITIALIZE...")
    init_struct = struct.pack('<' + 'Q' * 11,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        process_event,
        thread_event
    )
    
    success, err_or_bytes, data = test_ioctl(handle, IOCTL_CE_INITIALIZE, "INITIALIZE", init_struct, 8)
    if success:
        print(f"  [+] INITIALIZE worked! Bytes: {err_or_bytes}")
        if err_or_bytes >= 8:
            sdt = struct.unpack('<Q', data[:8])[0]
            print(f"      SDTShadow: 0x{sdt:016X}")
    else:
        print(f"  [-] INITIALIZE failed: Error {err_or_bytes}")
    
    # Test TEST IOCTL
    print("\n[*] Testing TEST IOCTL...")
    test_data = struct.pack('<Q', 0x1234567890ABCDEF)
    success, err_or_bytes, data = test_ioctl(handle, IOCTL_CE_TEST, "TEST", test_data, 256)
    if success:
        print(f"  [+] TEST worked! Bytes: {err_or_bytes}")
    else:
        print(f"  [-] TEST failed: Error {err_or_bytes}")
    
    # Cleanup
    kernel32.CloseHandle(process_event)
    kernel32.CloseHandle(thread_event)
    kernel32.CloseHandle(handle)
    
    print(f"\n[RESULT] Driver IS WORKING with configuration: {desc}")
    print(f"  Access: 0x{access:08X}")
    print(f"  Share:  0x{share:08X}")
    print(f"  Flags:  0x{flags:08X}")
    if not success:
        print("  SeDebugPrivilege: May be required")
else:
    print("[RESULT] Could not get driver to work with any configuration tested")
    print("Possible issues:")
    print("  1. Need to run as Administrator")
    print("  2. Driver not properly loaded")
    print("  3. Registry values missing")
    print("  4. Binary/source mismatch")