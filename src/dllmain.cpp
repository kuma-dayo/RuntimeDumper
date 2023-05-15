#include "pch.h"
#include "il2cpp-init.hpp"

#include "config.hpp"
#include "hook.hpp"
#include "util.hpp"

DWORD WINAPI Thread(LPVOID lpParam)
{
	config::Load();
	util::DisableLogReport();
	util::Log("Disabled log report.");

	while (GetModuleHandle("UserAssembly.dll") == nullptr)
	{
		util::Log("UserAssembly.dll isn't loaded, waiting for a sec.");
		Sleep(1000);
	}
	util::Log("Waiting 5 sec for game initialize.");
	Sleep(5000);
	util::DisableVMProtect();
	util::Log("Disabled vm protect.");

	init_il2cpp();
	util::Log("Loaded il2cpp functions.");

	hook::Load();
	util::Log("Loaded hooks.");
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		if (HANDLE hThread = CreateThread(NULL, 0, Thread, NULL, 0, NULL))
			CloseHandle(hThread);
	return TRUE;
}
