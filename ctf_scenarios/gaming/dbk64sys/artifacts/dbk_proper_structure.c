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
    printf("=== DBK64 Proper Structure Test ===\n");
    
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

    // Build proper initialization structure
    struct input initStruct = {0};
    
    // Fill with reasonable defaults (based on CE source)
    initStruct.AddressOfWin32K = 0;  // CE loads this from Win32K
    initStruct.SizeOfWin32K = 0;
    initStruct.NtUserBuildHwndList_callnumber = 0;
    initStruct.NtUserQueryWindow_callnumber = 0;
    initStruct.NtUserFindWindowEx_callnumber = 0;
    initStruct.NtUserGetForegroundWindow_callnumber = 0;
    initStruct.ActiveLinkOffset = 0;
    initStruct.ProcessNameOffset = 0;
    initStruct.DebugportOffset = 0;
    initStruct.ProcessEvent = (UINT64)(ULONG_PTR)hProcEvent;
    initStruct.ThreadEvent = (UINT64)(ULONG_PTR)hThreadEvent;

    printf("Structure size: %zu bytes\n", sizeof(initStruct));
    printf("ProcessEvent at offset %zu: %llx\n", offsetof(struct input, ProcessEvent), initStruct.ProcessEvent);
    printf("ThreadEvent at offset %zu: %llx\n", offsetof(struct input, ThreadEvent), initStruct.ThreadEvent);

    // Test IOCTL
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice,
        IOCTL_CE_INITIALIZE,
        &initStruct,
        sizeof(initStruct),
        &initStruct,  // Output buffer (driver writes result here)
        sizeof(UINT_PTR),  // Driver returns a UINT_PTR
        &bytesReturned,
        NULL);

    if (result) {
        printf("SUCCESS! IOCTL_CE_INITIALIZE worked!\n");
        printf("Bytes returned: %d\n", bytesReturned);
        printf("Result value: %llx\n", *(UINT_PTR*)&initStruct);
    } else {
        printf("IOCTL failed: Error %d\n", GetLastError());
    }

    // Cleanup
    CloseHandle(hProcEvent);
    CloseHandle(hThreadEvent);
    CloseHandle(hDevice);

    return result ? 0 : 1;
}
