#include <windows.h>
#include <stdio.h>

#define IOCTL_CE_INITIALIZE 0x00222034

// Exact structure from IOPLDispatcher.c
struct input {
    UINT64 AddressOfWin32K;
    UINT64 SizeOfWin32K;
    UINT64 NtUserBuildHwndList_callnumber;
    UINT64 NtUserQueryWindow_callnumber;
    UINT64 NtUserFindWindowEx_callnumber;
    UINT64 NtUserGetForegroundWindow_callnumber;
    UINT64 ActiveLinkOffset;
    UINT64 ProcessNameOffset;
    UINT64 DebugportOffset;
    UINT64 ProcessEvent;
    UINT64 ThreadEvent;
};

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("LookupPrivilegeValue failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        printf("AdjustTokenPrivileges failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("SeDebugPrivilege not assigned to token\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    printf("SeDebugPrivilege enabled successfully\n");
    return TRUE;
}

int main() {
    printf("=== DBK64 Exact CE Call Test ===\n");
    
    // Enable SeDebugPrivilege
    if (!EnableDebugPrivilege()) {
        printf("Failed to enable SeDebugPrivilege\n");
        return 1;
    }

    // Open device
    HANDLE hDevice = CreateFileW(L"\\\\.\\CEDRIVER73",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %d\n", GetLastError());
        return 1;
    }

    printf("Device opened successfully: Handle %p\n", hDevice);

    // Create events
    HANDLE hProcEvent = CreateEventW(NULL, TRUE, FALSE, L"DBKProcList60");
    HANDLE hThreadEvent = CreateEventW(NULL, TRUE, FALSE, L"DBKThreadList60");

    if (!hProcEvent || !hThreadEvent) {
        printf("CreateEvent failed: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("Events created: Process=%p, Thread=%p\n", hProcEvent, hThreadEvent);

    // Build initialization structure - EXACTLY like CE
    struct input buf = {0};
    
    // Zero everything first (like CE does with zeromemory)
    memset(&buf, 0, sizeof(buf));
    
    // Fill with CE's exact pattern
    buf.AddressOfWin32K = 0;  // CE loads this later
    buf.SizeOfWin32K = 0;
    buf.NtUserBuildHwndList_callnumber = 0;
    buf.NtUserQueryWindow_callnumber = 0;
    buf.NtUserFindWindowEx_callnumber = 0;
    buf.NtUserGetForegroundWindow_callnumber = 0;
    buf.ActiveLinkOffset = 0;
    buf.ProcessNameOffset = 0;
    buf.DebugportOffset = 0;
    buf.ProcessEvent = (UINT64)(ULONG_PTR)hProcEvent;
    buf.ThreadEvent = (UINT64)(ULONG_PTR)hThreadEvent;

    printf("Structure size: %zu bytes\n", sizeof(buf));
    printf("IOCTL code: 0x%08X\n", IOCTL_CE_INITIALIZE);
    printf("Input buffer: %p, size: %zu\n", &buf, sizeof(buf));
    printf("Output buffer: %p, size: 8\n", &buf);

    // Test IOCTL - EXACTLY like CE: same buffer for in/out, output size = 8
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDevice,
        IOCTL_CE_INITIALIZE,
        &buf,                // Input buffer (same as CE: @buf)
        sizeof(buf),         // Input size (same as CE: sizeof(tinput))
        &buf,                // Output buffer (same as CE: @buf) 
        8,                   // Output size (same as CE: 8)
        &bytesReturned,
        NULL);

    if (result) {
        printf("SUCCESS! IOCTL_CE_INITIALIZE worked!\n");
        printf("Bytes returned: %d\n", bytesReturned);
        printf("Result value: %llx\n", *(UINT64*)&buf);
    } else {
        DWORD error = GetLastError();
        printf("IOCTL failed: Error %d (0x%08X)\n", error, error);
        
        // Additional debug info
        if (error == 31) {
            printf("Error 31 = ERROR_GEN_FAILURE (device not functioning)\n");
            printf("This suggests driver is rejecting the request\n");
        }
    }

    // Cleanup
    CloseHandle(hProcEvent);
    CloseHandle(hThreadEvent);
    CloseHandle(hDevice);

    return result ? 0 : 1;
}
