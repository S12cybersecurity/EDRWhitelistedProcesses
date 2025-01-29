# EDR Process Whitelist Enumeration

Modern Endpoint Detection and Response (EDR) and antivirus (AV) solutions rely on DLL injection to monitor processes, detect malicious behavior, and enforce security policies. However, to optimize performance and prevent conflicts, these security products maintain a whitelist of trusted processes where their monitoring components do not inject.

**EDR Process Whitelist Enumeration** is a technique used to identify these trusted processes by scanning the system for processes without security monitoring DLLs injected. Once a process is confirmed to be in the EDR/AV whitelist, it can be used as a stealthy execution vector to bypass security detection and inject malicious payloads.

This README outlines the enumeration process, practical attack methods, and provides a simple implementation for leveraging whitelisted processes.

---

## **Table of Contents**

- [Overview](#overview)
- [Technique](#technique)
- [Implementation](#implementation)
  - [Code Explanation](#code-explanation)
  - [Libraries](#libraries)
- [Attack Scenario](#attack-scenario)
- [Countermeasures](#countermeasures)

---

## **Overview**

Many security solutions, including EDR and AV products, rely on injecting their monitoring DLLs into running processes. These injected DLLs enable the security software to monitor and control the actions of the processes. However, to avoid performance bottlenecks and interference, security products typically exclude trusted processes from this injection. The **EDR Process Whitelist Enumeration** technique enables an attacker to enumerate those trusted processes and exploit them to bypass security measures.

In this method:
1. **Identify Whitelisted Processes**: The attacker scans running processes to detect which ones are **missing security monitoring DLLs**.
2. **Leverage Trusted Processes**: These processes, marked as "whitelisted", can now serve as vectors for code execution.

Once the trusted processes are identified, attackers may inject malicious code into them while avoiding detection by the EDR/AV product.

---

## **Technique**

The **EDR Process Whitelist Enumeration** technique works by scanning the loaded modules within running processes. The goal is to identify processes that do **not** have security monitoring DLLs loaded. Here are the basic steps:

1. Enumerate all active processes on the system.
2. For each process, examine the loaded modules (DLLs).
3. Check if a known EDR/AV DLL is missing from the process.
4. Identify the process as "trusted" or "whitelisted".
5. Use these whitelisted processes to inject malicious payloads for stealthy execution.

---

## **Implementation**

The following C++ code demonstrates the implementation of EDR Process Whitelist Enumeration. The code checks all running processes, examines the loaded modules for EDR-related DLLs, and lists processes that are not injecting the security product's DLL.

### **Code Explanation**

- **`getPIDbyProcName`**: This function retrieves the Process ID (PID) by searching the process list for a given process name.
- **`getProcessNameByPID`**: Given a PID, it returns the process's executable file name.
- **`ListModulesByProcess`**: This function enumerates all modules (DLLs) loaded by a specific process and returns them in a deque (list).
- **`getWhiteListedProcesses`**: This function checks all running processes and identifies which ones do not have any known EDR/AV security product DLLs loaded. These processes are considered "whitelisted".

### **Libraries**

The code utilizes several Windows APIs to interact with the system:
- **Toolhelp32 API**: Used to enumerate processes and modules.
- **PSAPI API**: Provides functions to enumerate process modules.
- **Windows API**: Includes core functions like `OpenProcess`, `EnumProcessModules`, and `GetModuleFileNameEx`.

### **Complete Code**

```cpp
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <psapi.h>
#include <unordered_map>
#include <deque>

using namespace std;

unordered_map<string, string> Products = {
    {"Amsi", "amsi.dll"},
    {"Bitdefender", "atcuf64.dll"},
    {"Bitdefender", "atcuf32.dll"},
    {"Bitdefender", "bdhkm64.dll"},
};

struct ProcessInfo {
    string processName;
    DWORD pid;
};

int getPIDbyProcName(const string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32NextW(hSnap, &pe32) != FALSE) {
            wstring wideProcName(procName.begin(), procName.end());
            if (wcscmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return pid;
}

string getProcessNameByPID(int pid) {
    wchar_t szProcessName[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return "";
    }

    if (GetModuleFileNameExW(hProcess, NULL, szProcessName, MAX_PATH) != 0) {
        wstring wideProcessName(szProcessName);
        CloseHandle(hProcess);
        return string(wideProcessName.begin(), wideProcessName.end()).substr(wideProcessName.find_last_of(L'\\') + 1);
    }

    CloseHandle(hProcess);
    return "";
}

deque<string> ListModulesByProcess(HANDLE hProcess) {
    deque<string> modules = {};
    modules.begin();
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                std::string modName;
                wstring ws(szModName);
                modName.assign(ws.begin(), ws.end());
                modules.push_back(modName);
            }
        }
    }
    return modules;
}

deque<ProcessInfo> getWhiteListedProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    deque<ProcessInfo> result;

    if (hSnap == INVALID_HANDLE_VALUE) {
        cout << "Failed to create snapshot" << endl;
        return result;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe32) == FALSE) {
        cout << "Failed to get first process" << endl;
        CloseHandle(hSnap);
        return result;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL) {
            continue;
        }

        bool containsWhitelistedDLL = false;
        deque<string> modules = ListModulesByProcess(hProcess);
        if (modules.size() == 0) {
            continue;
        }
        for (auto& module : modules) {
            for (auto& product : Products) {
                if (module.find(product.second) != string::npos) {
                    containsWhitelistedDLL = true;
                    cout << "DLL found: " << product.first << " in process: " << getProcessNameByPID(pe32.th32ProcessID) << endl;
                    break;
                }
            }
            if (containsWhitelistedDLL) break;
        }

        if (!containsWhitelistedDLL) {
            ProcessInfo info = { getProcessNameByPID(pe32.th32ProcessID), pe32.th32ProcessID };
            result.push_back(info);
        }

        CloseHandle(hProcess);
    } while (Process32NextW(hSnap, &pe32));

    CloseHandle(hSnap);
    return result;
}

int main() {
    deque<ProcessInfo> result = getWhiteListedProcesses();
    for (auto& process : result) {
        cout << "Whitelisted process: " << process.processName << " " << process.pid << endl;
    }
    return 0;
}

```
---
# Countermeasures

- Dynamic Process Monitoring: Instead of relying on static whitelisting, dynamically analyze process behavior and modules.
- Kernel-Mode Monitoring: Use kernel-level techniques to catch DLL injection and other techniques often missed by user-mode security components.
- Behavioral Anomaly Detection: Implement advanced anomaly detection to flag suspicious actions from "whitelisted" processes.
- Application Control Policies: Enforce strict application control policies that prevent any process from loading suspicious or unapproved DLLs.
