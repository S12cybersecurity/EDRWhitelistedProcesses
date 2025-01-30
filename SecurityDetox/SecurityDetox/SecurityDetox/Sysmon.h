#include <Windows.h>
#include <stdio.h>
#include <tdh.h>
#include <pla.h>
#include <oleauto.h>
#include <Tlhelp32.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")

#define MAX_GUID_SIZE 39
#define MAX_DATA_LENGTH 65000

class SysmonDetox {
private:
    char* wcharToChar(const wchar_t* wStr) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wStr, -1, nullptr, 0, nullptr, nullptr);
        char* cStr = new char[size_needed];
        WideCharToMultiByte(CP_UTF8, 0, wStr, -1, cStr, size_needed, nullptr, nullptr);
        return cStr;
    }

public:
    char* FindProcName(int pid) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;

        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            return 0;
        }

        while (Process32Next(hProcSnap, &pe32)) {
            if (pid == pe32.th32ProcessID) {
                // Convert from wchar to char
                char* Nasme = wcharToChar(pe32.szExeFile);
                return Nasme;
            }
        }
        CloseHandle(hProcSnap);

        return NULL;
    }


    int PrintSysmonPID(wchar_t* guid) {
        HRESULT hr = S_OK;
        ITraceDataProvider* itdProvider = NULL;

        hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (hr == S_OK) {
            hr = CoCreateInstance(CLSID_TraceDataProvider,
                0,
                CLSCTX_INPROC_SERVER,
                IID_ITraceDataProvider,
                (LPVOID*)&itdProvider);
        }

        // query for provider with given GUID
        hr = itdProvider->Query(guid, NULL);

        // get all processes registered to the provider
        IValueMap* ivmProcesses = NULL;
        hr = itdProvider->GetRegisteredProcesses(&ivmProcesses);
        if (hr == S_OK) {

            long count = 0;
            hr = ivmProcesses->get_Count(&count);

            // there are some, let's parse them
            if (count > 0) {

                IUnknown* pUnk = NULL;
                hr = ivmProcesses->get__NewEnum(&pUnk);
                IEnumVARIANT* pItems = NULL;
                hr = pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pItems);
                pUnk->Release();

                VARIANT vItem;
                VARIANT vPID;
                VariantInit(&vItem);
                VariantInit(&vPID);

                IValueMapItem* pProc = NULL;
                // parse the enumerator
                while ((hr = pItems->Next(1, &vItem, NULL)) == S_OK) {
                    // get one element
                    vItem.punkVal->QueryInterface(__uuidof(IValueMapItem), (void**)&pProc);

                    // extract PID
                    pProc->get_Value(&vPID);

                    if (vPID.ulVal)
                        printf("Process ID:\t%d\nProcess Name:\t%s\n", vPID.ulVal, FindProcName(vPID.ulVal));

                    VariantClear(&vPID);
                    pProc->Release();
                    VariantClear(&vItem);
                }
            }
            else
                printf("No PIDs found\n");
        }

        // clean up
        ivmProcesses->Release();
        itdProvider->Release();
        CoUninitialize();

        return 0;
    }

    int FindSysmon(wchar_t* guid) {
        DWORD status = ERROR_SUCCESS;
        PROVIDER_ENUMERATION_INFO* penum = NULL;    // Buffer that contains provider information
        PROVIDER_ENUMERATION_INFO* ptemp = NULL;
        DWORD BufferSize = 0;                       // Size of the penum buffer
        HRESULT hr = S_OK;                          // Return value for StringFromGUID2
        WCHAR StringGuid[MAX_GUID_SIZE];

        // Retrieve the required buffer size.
        status = TdhEnumerateProviders(penum, &BufferSize);

        // Allocate the required buffer and call TdhEnumerateProviders. The list of 
        // providers can change between the time you retrieved the required buffer 
        // size and the time you enumerated the providers, so call TdhEnumerateProviders
        // in a loop until the function does not return ERROR_INSUFFICIENT_BUFFER.

        while (status == ERROR_INSUFFICIENT_BUFFER) {
            ptemp = (PROVIDER_ENUMERATION_INFO*)realloc(penum, BufferSize);
            if (ptemp == NULL) {
                wprintf(L"Allocation failed (size=%lu).\n", BufferSize);
                return -1;
            }

            penum = ptemp;
            ptemp = NULL;

            status = TdhEnumerateProviders(penum, &BufferSize);
        }

        if (status != ERROR_SUCCESS)
            wprintf(L"TdhEnumerateProviders failed with %lu.\n", status);
        else {
            // search for Sysmon guid
            for (DWORD i = 0; i < penum->NumberOfProviders; i++) {
                hr = StringFromGUID2(penum->TraceProviderInfoArray[i].ProviderGuid, StringGuid, ARRAYSIZE(StringGuid));

                if (FAILED(hr)) {
                    wprintf(L"StringFromGUID2 failed with 0x%x\n", hr);
                    return -1;
                }
                if (!_wcsicmp(StringGuid, (wchar_t*)guid)) {
                    wprintf(L"Warning! SYSMON is watching here!\n\n");
                    wprintf(L"Provider name:\t%s\nProvider GUID:\t%s\n",
                        (LPWSTR)((PBYTE)(penum)+penum->TraceProviderInfoArray[i].ProviderNameOffset),
                        StringGuid);
                    PrintSysmonPID(guid);
                }
            }
        }

        if (penum) {
            free(penum);
            penum = NULL;
        }
        return 0;
    }


    int SysmonDetector() {
        HKEY hKey;
        BYTE RegData[MAX_DATA_LENGTH];
        DWORD cbLength = MAX_DATA_LENGTH;
        DWORD dwType;
        wchar_t SysmonGuid[MAX_DATA_LENGTH];
        int result;

        // get WINEVT channels key
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational"),
            0,
            KEY_READ,
            &hKey) == ERROR_SUCCESS) {

            RegGetValueA(hKey, NULL, "OwningPublisher", RRF_RT_ANY, &dwType, (PVOID)&RegData, &cbLength);

            if (strlen((char*)RegData) != 0) {
                // convert BYTE[] array to wchar string
                mbstowcs(SysmonGuid, (char*)&RegData, cbLength * 2);
                result = FindSysmon(SysmonGuid);
				return result;
            }
        }
        else

        RegCloseKey(hKey);

        return 0;
    }

};