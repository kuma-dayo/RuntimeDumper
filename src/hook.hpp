#pragma once

#include "pch.h"
#include "hook-manager.h"
#include "il2cpp-appdata.h"
#include "Shellapi.h"
#include "config.hpp"
#include "util.hpp"
#include <string>

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
		int nArgs;
		auto args = CommandLineToArgvW(GetCommandLineW(), &nArgs);

		if (!args[1]) {
			util::Log("Type 'method' to RVA Dump\n");
			util::Log("Type 'property' to property Dump\n");
			std::cout << config::GetMagicC() << std::endl;

			while (true)
			{
				std::string input;
				std::getline(std::cin, input);
				auto cmd = util::split(input, ' ');
				if (cmd.empty())
					continue;
				auto nargs = cmd.size() - 1;

				if (cmd[0] == "method")
				{
					auto start = config::GetLongValue("TypeIndexStart", -1);
					if (start > -1 && il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex != 0 && il2cpp__vm__Type__GetName != 0 && il2cpp__vm__Class__GetMethods != 0 && il2cpp__vm__Method__GetNameWithGenericTypes != 0)
					{
						util::DumpMethodAddress(start, config::GetMagicA(), config::GetMagicB());
					}
				}
				else if (cmd[0] == "property")
				{
					auto start = config::GetLongValue("TypeIndexStart", -1);
					if (start > -1 && il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex != 0 && il2cpp__vm__Property__GetName != 0 && il2cpp__vm__Class__GetProperties != 0)
					{
						util::DumpPropertyAddress(start, config::GetMagicA(), config::GetMagicB(), config::GetMagicC());
					}
				}
				else if (cmd[0] == "check") {
					if (il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex != 0 && il2cpp__vm__Property__GetName != 0 && il2cpp__vm__Class__GetProperties != 0)
					{
						util::checkPropertyName(config::GetMagicA(), config::GetMagicC());
					}
				}
				else
					util::Log("Invalid command!\n");
			}
		}
		else {
			printf("magic_a = %ws\n", args[2]);
			util::DumpMethodAddressTest(std::stol(args[2]));
		}
	}
}
