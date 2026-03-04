#define WIN32_LEAN_AND_MEAN
#include <initguid.h>
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>
#include <wchar.h>
#include <limits.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#define ETL_FILE L"trace.etl" // this is a TEMPORARY file, used to log temporarily and print, and to later be deleted
DWORD gVictimPID = 0;
int gFileCount = 0;
int gRegCount = 0;

typedef struct _LogNode {
    WCHAR Message[1024];
    struct _LogNode* Next;
} LogNode;

LogNode* gFileLogs = NULL;
LogNode* gRegLogs = NULL;

void PrintBanner() {
    // useless but sure because im old school
    printf(
"__        __    _       _     ____\n"
"\\ \\      / /_ _| |_ ___| |__ |  _ \\  __ ___      ____ _\n"
" \\ \\ /\\ / / _` | __/ __| '_ \\| | | |/ _` \\ \\ /\\ / / _` |\n"
"  \\ V  V / (_| | || (__| | | | |_| | (_| |\\ V  V / (_| |\n"
"   \\_/\\_/ \\__,_|\\__\\___|_| |_|____/ \\__,_| \\_/\\_/ \\__, |\n"
"                                                  |___/\n"
"\n"
"\t- made by @miiichaelllduzzit (miiichaelll) -\n"
"\t-        Long Live The Real Ones        -\n"
"\n"
    );
}

void AddLog(LogNode** head, const WCHAR* action, const WCHAR* path, int* counter) {
    // tiny heap allocation, pray to the fragmentation gods
    LogNode* newNode = (LogNode*)malloc(sizeof(LogNode));
    if (!newNode) return;

    swprintf(newNode->Message, 1024, L"[PID %lu][%s] %s", gVictimPID, action, path);

    // newest events first because chronology is overrated
    newNode->Next = *head;
    *head = newNode;

    (*counter)++; // do you really expect a explanation? learn to code bro
}

void ResolveAndSavePath(const WCHAR* ntPath, const char* action) {
    if (!ntPath || wcslen(ntPath) == 0) return;

    // ignore system noise that nobody asked for
    if (wcsstr(ntPath, L"Session Manager") || wcsstr(ntPath, L"Nls\\Sorting")) return;

    WCHAR drive[3] = L"A:";
    WCHAR deviceName[MAX_PATH];
    WCHAR finalPath[MAX_PATH] = { 0 };
    WCHAR wAction[32];

    MultiByteToWideChar(CP_ACP, 0, action, -1, wAction, 32);

    // translating scary nt device paths into human language
    for (int i = 0; i < 26; i++) {
        drive[0] = L'A' + i;

        if (QueryDosDeviceW(drive, deviceName, MAX_PATH)) {
            size_t len = wcslen(deviceName);

            if (_wcsnicmp(ntPath, deviceName, len) == 0) {
                swprintf(finalPath, MAX_PATH, L"%s%s", drive, ntPath + len);
                AddLog(&gFileLogs, wAction, finalPath, &gFileCount);
                return;
            }
        }
    }

    // if we can't translate it, we expose it rawdogged and move on
    AddLog(&gFileLogs, wAction, ntPath, &gFileCount);
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {

    // only stalk the chosen process
    if (pEvent->EventHeader.ProcessId != gVictimPID) return;

    const char* action = NULL;
    BOOL isReg = FALSE;

    // decoding kernel opcodes like we totally memorized them (psps, i didn't)
    switch (pEvent->EventHeader.EventDescriptor.Opcode) {
        case 64: action = "FILE_OPEN"; break;
        case 68: action = "FILE_WRITE"; break;
        case 69: action = "FILE_SETINFO"; break;
        case 65: case 70: action = "FILE_DELETE"; break;
        case 10: case 11: action = "REG_ACCESS"; isReg = TRUE; break;
        default: return; // so basically the rest here, is just garbage OR unrelated lol
    }

    PTRACE_EVENT_INFO pInfo = NULL;
    ULONG bufferSize = 0;

    // first call: windows asking how big the buffer should be
    TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);

    pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!pInfo) return;

    TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);

    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {

        LPWSTR propName =
            (LPWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);

        PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)propName, ULONG_MAX };
        ULONG propSize = 0;

        if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &propSize) == ERROR_SUCCESS && propSize > 0) {

            PBYTE pData = (PBYTE)malloc(propSize);

            if (pData &&
                TdhGetProperty(pEvent, 0, NULL, 1, &desc, propSize, pData) == ERROR_SUCCESS) {

                if (isReg && wcscmp(propName, L"KeyName") == 0) {

                    if (!wcsstr((WCHAR*)pData, L"Session Manager")) {
                        WCHAR wAction[32];
                        MultiByteToWideChar(CP_ACP, 0, action, -1, wAction, 32);

                        // registry snooping engaged
                        AddLog(&gRegLogs, wAction, (WCHAR*)pData, &gRegCount);
                    }

                } else if (!isReg &&
                          (wcscmp(propName, L"OpenPath") == 0 ||
                           wcscmp(propName, L"FileName") == 0)) {

                    ResolveAndSavePath((WCHAR*)pData, action);
                }
            }

            if (pData) free(pData); // free it before it frees you
        }
    }

    free(pInfo);
}

void PrintStoredLogs(LogNode* head, const char* title) {
    if (!head) return;

    printf("\n--- %s ---\n", title);

    while (head) {
        wprintf(L"%s\n", head->Message);

        LogNode* temp = head;
        head = head->Next;
        free(temp); // goodbye little log node
    }
}

int main(int argc, char** argv) {

    PrintBanner();

    if (argc < 2) {
        printf("Usage: WatchDawg.exe <exe>\n");
        return 1;
    }

    const wchar_t* sessionName = KERNEL_LOGGER_NAMEW;

    ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;

    // oversized struct allocation because etw likes extra room
    EVENT_TRACE_PROPERTIES* pProps =
        (EVENT_TRACE_PROPERTIES*)malloc(propsSize);

    if (!pProps) return 1;

    ZeroMemory(pProps, propsSize);

    pProps->Wnode.BufferSize = propsSize;
    pProps->Wnode.Guid = SystemTraceControlGuid;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

    // enable kernel file and registry telemetry
    pProps->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    pProps->EnableFlags =
        EVENT_TRACE_FLAG_FILE_IO |
        EVENT_TRACE_FLAG_FILE_IO_INIT |
        EVENT_TRACE_FLAG_REGISTRY;

    pProps->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy((WCHAR*)((PCHAR)pProps + pProps->LogFileNameOffset), ETL_FILE);

    // stop any previous session because we dont share traces
    ControlTraceW(0, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);

    TRACEHANDLE sessionHandle = 0;

    if (StartTraceW(&sessionHandle, sessionName, pProps) != ERROR_SUCCESS) {
        printf("Error: Run as Admin!\n");
        free(pProps);
        return 1;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // launch target suspended so we can spy responsibly
    if (CreateProcessA(NULL, argv[1], NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        gVictimPID = pi.dwProcessId;

        ResumeThread(pi.hThread);

        printf("[*] Monitoring PID %lu. Waiting for exit...\n", gVictimPID);

        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // stop the trace and prepare the report
    ControlTraceW(sessionHandle, sessionName, pProps,
                  EVENT_TRACE_CONTROL_STOP);

    printf("\n[*] Extracting Kernel Events...");

    EVENT_TRACE_LOGFILEW logFile = { (LPWSTR)ETL_FILE };
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;

    TRACEHANDLE hTrace = OpenTraceW(&logFile);

    ProcessTrace(&hTrace, 1, NULL, NULL);
    CloseTrace(hTrace);

    // summarize
    PrintStoredLogs(gFileLogs, "FILE I/O ACTIONS");
    printf("----------------------------------");
    PrintStoredLogs(gRegLogs, "REGISTRY ACTIONS");

    printf("\n\n================ SUMMARY ================\n");
    printf("Total File Events Captured: %d\n", gFileCount);
    printf("Total Registry Events Captured: %d\n", gRegCount);
    printf("=========================================\n");

    free(pProps);
    DeleteFileW(ETL_FILE); // clean up the mess eh

    return 0;
}