DO_API(0, LPVOID, il2cpp_string_new, (const char* str));

DO_API(0, LPVOID, il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex, (uint32_t index));
DO_API(0, std::string, il2cpp__vm__Type__GetName, (LPVOID type, uint32_t format));
DO_API(0, LPVOID, il2cpp__vm__Class__GetMethods, (LPVOID klass, LPVOID iter));
DO_API(0, std::string, il2cpp__vm__Method__GetNameWithGenericTypes, (LPVOID method));

DO_API(0, LPVOID, il2cpp__vm__Class__GetProperties, (LPVOID klass, LPVOID iter));
DO_API(0, std::string, il2cpp__vm__Property__GetName, (LPVOID prop));