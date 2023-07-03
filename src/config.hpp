#pragma once

#include "pch.h"
#include <SimpleIni.h>

#include "util.hpp"

namespace config
{
	static CSimpleIni ini;

	static const char* client_version;
	static long magic_a;
	static long magic_b;
	static long magic_c;
	bool GetEnableValue(const char* a_pKey, bool a_nDefault)
	{
		return ini.GetBoolValue("Basic", a_pKey, a_nDefault);
	}

	long GetLongValue(const char* a_pKey, long a_nDefault)
	{
		return ini.GetLongValue("Basic", a_pKey, a_nDefault);
	}

	long GetMagicA()
	{
		return magic_a;
	}

	long GetMagicB()
	{
		return magic_b;
	}

	long GetMagicC()
	{
		return magic_c;
	}
	long GetOffsetValue(const char* a_pKey, long a_nDefault)
	{
		return ini.GetLongValue(client_version, a_pKey, a_nDefault);
	}

	uintptr_t GetAddress(uintptr_t baseAddress, const char* a_pKey, long a_nDefault)
	{
		auto offset = GetOffsetValue(a_pKey, a_nDefault);
		if (offset == 0)
		{
			auto patternKey = std::string(a_pKey) + "_Pattern";
			auto pattern = ini.GetValue("Offset", patternKey.c_str(), nullptr);
			if (pattern != nullptr && strlen(pattern) > 0)
			{
				if (*pattern == '+')
				{
					pattern = pattern + 1;
					auto value = util::FindEntry(util::PatternScan("UserAssembly.dll", pattern));
					if (value)
						offset = value - baseAddress;
				}
				else
				{
					auto value = util::PatternScan("UserAssembly.dll", pattern);
					if (value)
						offset = value - baseAddress;
				}
			}
		}
		if (offset) {
			util::Logf("[%s] %s = 0x%08X", client_version, a_pKey, offset);
		}
		return baseAddress + offset;
	}

	void Load()
	{
		ini.SetUnicode();
		ini.LoadFile(util::GetConfigPath().c_str());
		if (GetEnableValue("EnableConsole", false))
		{
			util::InitConsole();
		}
		client_version = ini.GetValue("Offset", "ClientVersion", nullptr);
		if (client_version == nullptr)
		{
			char filename[MAX_PATH] = {};
			GetModuleFileName(NULL, filename, MAX_PATH);
			auto path = std::filesystem::path(filename).parent_path() / "pkg_version";
			std::ifstream infile(path);
			std::string line;
			std::regex str_expr = std::regex("UserAssembly.dll.*\"([0-9a-f]{32})\"");
			auto match = std::smatch();
			while (std::getline(infile, line))
			{
				std::regex_search(line, match, str_expr);
				if (match.size() == 2)
				{
					auto str_match = match[1].str();
					client_version = ini.GetValue("MD5ClientVersion", str_match.c_str(), nullptr);
					if (client_version == nullptr)
					{
						client_version = "Offset";
					}
					util::Logf("Version detected %s MD5: %s", client_version, str_match.c_str());
					break;
				}
			}
		}
		magic_a = ini.GetLongValue(client_version, "magic_a", 0);
		magic_b = ini.GetLongValue(client_version, "magic_b", 0);
		magic_c = ini.GetLongValue(client_version, "magic_c", 0);
	}
}
