#include <windows.h>
#include <string>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

void get_pid(string process_name, DWORD& pid)
{
	//converting string to char*
	const char* str = process_name.c_str();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		cout << "Error creating handle snapshot";
		exit(GetLastError());
	}

	PROCESSENTRY32 pe_temp;
	pe_temp.dwSize = sizeof(pe_temp);

	if(Process32First(hSnapshot, &pe_temp))
	{
		while (Process32Next(hSnapshot, &pe_temp))
		{
			if (!_stricmp(str, pe_temp.szExeFile))
			{
				pid = pe_temp.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(hSnapshot);
}

int main()
{
	//r_variablenamehere denotes user requested item

	cout << "Enter the name of the process: ";
	string process_name; 
	getline(cin, process_name);
	cout << endl;


	cout << "Enter in the path to the .dll: ";
	string dll_path;
	getline(cin, dll_path);
	const char* r_dll_path = dll_path.c_str();
	cout << endl;

	cout << "Getting pid of requested process..." << endl;
	DWORD r_pid;
	get_pid(process_name, r_pid);
	cout << "Pid is: " << r_pid << endl;

	cout << "Press INSERT to inject the specified dll into the desired process " << endl;
	while (!GetAsyncKeyState(VK_INSERT))
	{
		Sleep(200);
	}

	cout << "attempting to get a handle to the process..." << endl;
	HANDLE r_handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, r_pid);
	if (!r_handle)
	{
		cout << "ERROR OPENING HANDLE TO PROCESS" << endl;
		exit(GetLastError());
	}

	cout << "attempting to allocate memory for the dll path..." << endl;
	LPVOID r_memory_location = VirtualAllocEx(r_handle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	cout << "Attempting to write dll path to memory..." << endl;
	BOOL write_result = WriteProcessMemory(r_handle, r_memory_location, r_dll_path, strlen(r_dll_path) + 1, NULL);
	if (!write_result)
	{
		cout << "ERROR WRITING TO TARGET PROCESS" << endl;
		exit(GetLastError());
	}

	cout << "Attempting to create a thread in the target process and load the dll..." << endl;
	HANDLE remote_thread_handle = CreateRemoteThread(r_handle, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), r_memory_location, NULL, NULL);
	if (!remote_thread_handle)
	{
		cout << "ERROR CREATING REMOTE THREAD" << endl;
		exit(GetLastError());
	}

	cout << "Closing Handles..." << endl;
	CloseHandle(remote_thread_handle);
	CloseHandle(r_handle);


	cout << "!!!!!  INJECTION SUCCESSFULL  !!!!!" << endl;

}