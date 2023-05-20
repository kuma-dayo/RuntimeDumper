#pragma once

#include "pch.h"
#include "hook-manager.h"
#include "il2cpp-appdata.h"

#include "config.hpp"
#include "util.hpp"

namespace hook
{
	std::string uint64_to_hex_string(uint64_t value)
	{
		std::ostringstream os;
		os << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << value;
		return os.str();
	}

	void Load()
	{
		util::DumpCharp();

		auto start = config::GetLongValue("TypeIndexStart", -1);
		if (start > -1 && il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex != 0 &&
			il2cpp__vm__Type__GetName != 0 && il2cpp__vm__Class__GetMethods != 0 && il2cpp__vm__Method__GetNameWithGenericTypes != 0)
		{
			util::DumpAddress(start, config::GetMagicA(), config::GetMagicB());
		}
	}
}
