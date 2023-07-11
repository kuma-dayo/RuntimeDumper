#pragma once

#include "pch.h"
#include "il2cpp-type.hpp"

namespace util
{
	const char* client_version;

	void Log(const char *text)
	{
		std::cout << "[RuntimeDumper] " << text << std::endl;
	}

	void Logf(const char *fmt, ...)
	{
		char text[1024];

		va_list args;
		va_start(args, fmt);
		vsprintf_s(text, fmt, args);
		va_end(args);

		Log(text);
	}

	std::map<std::string, std::ofstream> foutMap;

	void Flogf(const char* name, const char* fmt, ...)
	{
		std::ofstream& fout = foutMap[name];
		
		if (!fout.is_open())
			fout.open(std::format("RuntimeDumper-{}-{}Dump.log", client_version, name).c_str());

		char text[1024];

		va_list args;
		va_start(args, fmt);
		vsprintf_s(text, fmt, args);
		va_end(args);

		fout << text << std::endl;
		fout.flush();
	}

	HMODULE GetSelfModuleHandle()
	{
		MEMORY_BASIC_INFORMATION mbi;
		return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
	}

	std::string GetConfigPath()
	{
		char filename[MAX_PATH] = {};
		GetModuleFileName(GetSelfModuleHandle(), filename, MAX_PATH);
		auto path = std::filesystem::path(filename).parent_path() / "RuntimeDumper.ini";
		return path.string();
	}

	std::string ConvertToString(VOID *ptr)
	{
		auto bytePtr = reinterpret_cast<unsigned char *>(ptr);
		auto lengthPtr = reinterpret_cast<unsigned int *>(bytePtr + 0x10);
		auto charPtr = reinterpret_cast<char16_t *>(bytePtr + 0x14);
		auto size = lengthPtr[0];
		std::u16string u16;
		u16.resize(size);
		memcpy((char *)&u16[0], (char *)charPtr, size * sizeof(char16_t));
		std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter;
		return converter.to_bytes(u16);
	}

	void InitConsole()
	{
		AllocConsole();

		freopen_s((FILE **)stdin, "CONIN$", "r", stdin);
		freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
		freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);

		auto consoleWindow = GetConsoleWindow();
		SetForegroundWindow(consoleWindow);
		ShowWindow(consoleWindow, SW_RESTORE);
		ShowWindow(consoleWindow, SW_SHOW);

		SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),
					   ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
						   ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE |
						   ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
	}

	void DisableLogReport()
	{
		char filename[MAX_PATH] = {};
		GetModuleFileName(NULL, filename, MAX_PATH);

		auto path = std::filesystem::path(filename);
		path = path.parent_path() / (path.stem().string() + "_Data") / "Plugins";

		CreateFileW((path / "Astrolabe.dll").c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		CreateFileW((path / "MiHoYoMTRSDK.dll").c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	// https://github.com/yubie-re/vmp-virtualprotect-bypass/blob/main/src/vp-patch.hpp
	void DisableVMProtect()
	{
		DWORD old_protect = 0;
		auto ntdll = GetModuleHandleA("ntdll.dll");
		BYTE callcode = ((BYTE *)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;
		BYTE restore[] = {0x4C, 0x8B, 0xD1, 0xB8, callcode};
		auto nt_vp = (BYTE *)GetProcAddress(ntdll, "NtProtectVirtualMemory");
		VirtualProtect(nt_vp, sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(nt_vp, restore, sizeof(restore));
		VirtualProtect(nt_vp, sizeof(restore), old_protect, &old_protect);
	}

	// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/Utils.cpp
	uintptr_t FindEntry(uintptr_t addr)
	{
		__try
		{
			while (true)
			{
				// walk back until we find function entry
				uint32_t code = *(uint32_t *)addr;
				code &= ~0xFF000000;
				if (_byteswap_ulong(code) == 0x4883EC00) // sub rsp, ??
					return addr;
				addr--;
			}
		}
		__except (1)
		{
		}
		return 0;
	}

	// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/Utils.cpp
	uintptr_t PatternScan(LPCSTR module, LPCSTR pattern)
	{
		static auto pattern_to_byte = [](const char *pattern)
		{
			auto bytes = std::vector<int>{};
			auto start = const_cast<char *>(pattern);
			auto end = const_cast<char *>(pattern) + strlen(pattern);
			for (auto current = start; current < end; ++current)
			{
				if (*current == '?')
				{
					++current;
					if (*current == '?')
						++current;
					bytes.push_back(-1);
				}
				else
				{
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

		auto mod = GetModuleHandle(module);
		if (!mod)
			return 0;

		auto dosHeader = (PIMAGE_DOS_HEADER)mod;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t *)mod + dosHeader->e_lfanew);
		auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		auto patternBytes = pattern_to_byte(pattern);
		auto scanBytes = reinterpret_cast<std::uint8_t *>(mod);
		auto s = patternBytes.size();
		auto d = patternBytes.data();

		for (auto i = 0ul; i < sizeOfImage - s; ++i)
		{
			bool found = true;
			for (auto j = 0ul; j < s; ++j)
			{
				if (scanBytes[i + j] != d[j] && d[j] != -1)
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				return (uintptr_t)&scanBytes[i];
			}
		}
		return 0;
	}

	std::vector<std::string> split(const std::string &s, char delim)
	{
		std::vector<std::string> result;
		std::stringstream ss(s);
		std::string item;

		while (std::getline(ss, item, delim))
		{
			if (!item.empty())
				result.push_back(item);
		}

		return result;
	}

	void ReplaceAll(std::string& stringreplace, const std::string& origin, const std::string& dest)
	{
		size_t pos = 0;
		size_t offset = 0;
		size_t len = origin.length();
		while ((pos = stringreplace.find(origin, offset)) != std::string::npos) {
			stringreplace.replace(pos, len, dest);
			offset = pos + dest.length();
		}
	}

	bool IsValidName(const char *name)
	{
		if (name == nullptr)
			return false;

		for (size_t i = 0; name[i] != '\0'; ++i)
		{
			if (name[i] < 0 || name[i] > 127)
				return false;
		}

		return true;
	}

	void DumpField(uint32_t start, long byval_arg_magic) {
		uintptr_t baseAddress = (uintptr_t)GetModuleHandle("UserAssembly.dll");
		for (uint32_t i = start;; i++)
		{
			auto klass = il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex(i);
			// &reinterpret_cast<uintptr_t*>(klass)[?] is a magic for klass->byval_arg
			std::string class_name = il2cpp__vm__Type__GetName(&reinterpret_cast<uintptr_t*>(klass)[byval_arg_magic], 0);

			util::Flogf("Field", "TypedefIndex: %d", i);

			void* iter = 0;
			while (const LPVOID field = il2cpp__vm__Class_GetFields(klass, (LPVOID)&iter))
			{
				auto field_name_ptr = Marshal__PtrToStringAnsi(il2cpp__vm__Field__GetName(klass));
				auto field_name = reinterpret_cast<String*>(IntPtr__ToPointer(field_name_ptr));
				std::cout << field_name->c_str() << std::endl;
				Marshal__FreeHGlobal(field_name_ptr);

			}
			util::Flogf("Field", "");
		}
	}
	void CheckByvalArgMagic(long byval_arg_magic, const char* clientVersion)
	{
		auto klass = il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex(0);
		
		std::string class_name = il2cpp__vm__Type__GetName(&reinterpret_cast<uintptr_t *>(klass)[byval_arg_magic], 0);

		if (strcmp(class_name.c_str(), "<Module>") == 0) {
			auto text = std::format("{} {}\n{} {}", "Succeeded in finding magic_a in version", clientVersion, "byval_arg_magic:", byval_arg_magic);
			MessageBoxA(nullptr, text.c_str(), "RuntimeDumper", MB_ICONASTERISK);
		} 
	}

	void DumpMethod(uint32_t start, long byval_arg_magic, long method_pointer_magic)
	{
		uintptr_t baseAddress = (uintptr_t)GetModuleHandle("UserAssembly.dll");
		for (uint32_t i = start;; i++)
		{
			auto klass = il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex(i);
			// &reinterpret_cast<uintptr_t*>(klass)[?] is a magic for klass->byval_arg
			std::string class_name = il2cpp__vm__Type__GetName(&reinterpret_cast<uintptr_t *>(klass)[byval_arg_magic], 0);
			
			util::Flogf("Method","TypedefIndex: %d", i);

			void *iter = 0;
			
			while (const LPVOID method = il2cpp__vm__Class__GetMethods(klass, (LPVOID)&iter))
			{
				// &reinterpret_cast<uintptr_t*>(method)[?] is a magic for method->methodPointer
				auto method_address = reinterpret_cast<uintptr_t *>(method)[method_pointer_magic];
				if (method_address)
					method_address -= baseAddress;
				std::string method_name = il2cpp__vm__Method__GetNameWithGenericTypes(method);
				util::ReplaceAll(class_name, ".", "::");
				
				util::Flogf("Method","\t0x%08X: %s", method_address, std::format("{}::{}", class_name.c_str(), method_name.c_str()).c_str());
			}
			util::Flogf("Method", "");
		}
	}


}
