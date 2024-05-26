#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <vector>
#include <wchar.h>
#include <psapi.h>



int checkCore(int argc, char* argv[]) {
	int minProcessors = 2;
	if (argc > 1) {
		minProcessors = atoi(argv[1]);
	}

	SYSTEM_INFO systemInfo;
	(GetSystemInfo)(&systemInfo);
	int numProcessors = systemInfo.dwNumberOfProcessors;

	if (numProcessors >= minProcessors) {
		return 1;
	}
	else {
		return 0;
	}

	return 0;
}
int checkMem() {
	MEMORYSTATUSEX memStat;

	memStat.dwLength = sizeof(memStat);
	(GlobalMemoryStatusEx)(&memStat);

	if ((float)memStat.ullTotalPhys / 1073741824 > 1) {
		return 1;
	}
	else {
		return 0;
	}

}
int checkUsb(int argc, char* argv[]) {
	HKEY hKey;
	int MinimumUsbHistory = 2;
	DWORD numUsbDevices = 0;

	if (argc > 1) {
		MinimumUsbHistory = atoi(argv[1]);
	}
	
	unsigned char tem[] = { 'S','Y','S','T','E','M','\\','\\','C','o','n','t','r','o','l','S','e','t','0','0','1','\\','\\','E','n','u','m','\\','\\','U','S','B','S','T','O','R','\0' };
	if ((RegOpenKeyExA)(HKEY_LOCAL_MACHINE, (LPCSTR)tem, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &numUsbDevices, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}


	if (numUsbDevices >= MinimumUsbHistory) {
		return 1;
	}
	else {
		return 0;
	}
}
int checkUserName() {
	char username[200];
	DWORD usersize = sizeof(username);
	(GetUserNameA)(username, &usersize);

	const char* forbiddenUsernames[] = { "JOHN-PC", "VIRUS", "ADMIN", "IVANOV", "ROMAN", "ABBY","ADMIN-PC","ALEKSSEV","ALEKSEY","ANDREEV","PHIL-PC","FEDOROV","BELOUSOV","AZURE","AZURE_PC","BARANOV","SOBOL" };

	char upperCaseUsername[256];
	strcpy_s(upperCaseUsername, username);
	for (int i = 0; upperCaseUsername[i] != '\0'; i++) {
		upperCaseUsername[i] = toupper(upperCaseUsername[i]);
	}

	for (int i = 0; i < sizeof(forbiddenUsernames) / sizeof(forbiddenUsernames[0]); i++) {
		if (strstr(upperCaseUsername, forbiddenUsernames[i]) != NULL) {
			return 0;
		}
	}
	return 1;
}
int checkProcesses(int argc, char* argv[]) {
	int minNumProcesses = 40;
	if (argc > 1) {
		minNumProcesses = atoi(argv[1]);
	}

	DWORD loadedProcesses[1024];
	DWORD cbNeeded;
	DWORD runningProcesses;

	if (!EnumProcesses(loadedProcesses, sizeof(loadedProcesses), &cbNeeded)) {
		return 0;
	}
	runningProcesses = cbNeeded / sizeof(DWORD);

	if (runningProcesses >= minNumProcesses) {
		return 1;
	}
	else {
		return 0;
	}

	return 0;
}
int checkUptime() {
	DWORD uptime = (GetTickCount)();
	if (uptime < 3600000)
		return 0;
	else
		return 1;
}
bool checkVM(int argc, char* argv[]) {
	int res = 0;
	res += checkMem();

	res += checkUsb(argc, argv);

	printf("%d\n", res);

	res += checkUserName();
	res += checkProcesses(argc, argv);
	res += checkCore(argc, argv);
	res += checkUptime();
	printf("%d", res);

	if (res == 6) {
		return TRUE;
	}
	return FALSE;
}

