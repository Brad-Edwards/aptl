import ctypes
import sys

kernel32 = ctypes.windll.kernel32

# Test multiple possible device paths
test_paths = [
    r'\\.\DBK64',
    r'\Device\DBK64', 
    r'\\?\DBK64',
    r'\\?\GLOBALROOT\Device\DBK64',
    r'\\.\GLOBALROOT\Device\DBK64'
]

print("=== Testing Multiple Device Paths ===")

for path in test_paths:
    handle = kernel32.CreateFileW(
        path,
        0xC0000000,
        0,
        None,
        3,
        0,
        None
    )
    
    error = kernel32.GetLastError()
    
    if handle == -1:
        print(f"FAILED: {path} -> Error {error}")
    else:
        print(f"SUCCESS: {path} -> Handle {handle}")
        kernel32.CloseHandle(handle)

print("\n=== Testing Process Context ===")
print(f"Current PID: {kernel32.GetCurrentProcessId()}")

# Check if we're running elevated
try:
    import ctypes.wintypes
    from ctypes import byref
    
    advapi32 = ctypes.windll.advapi32
    
    TOKEN_QUERY = 0x0008
    TokenElevation = 20  # TokenElevationType enum
    
    token = ctypes.c_void_p()
    process_handle = kernel32.GetCurrentProcess()
    
    if advapi32.OpenProcessToken(process_handle, TOKEN_QUERY, byref(token)):
        elevation = ctypes.c_ulong()
        size = ctypes.c_ulong()
        
        if advapi32.GetTokenInformation(token, TokenElevation, byref(elevation), 4, byref(size)):
            print(f"Process elevated: {bool(elevation.value)}")
        else:
            print(f"Failed to get token elevation: {kernel32.GetLastError()}")
        
        kernel32.CloseHandle(token)
    else:
        print(f"Failed to open process token: {kernel32.GetLastError()}")
        
except Exception as e:
    print(f"Elevation check failed: {e}")

print("\nIf all paths fail with Error 161, the driver isn't creating device objects properly.")
print("This could be due to:")
print("1. Driver DriverEntry failing silently")  
print("2. Missing dependencies or imports")
print("3. Registry parameters being read incorrectly")
print("4. Security policy blocking device creation")
