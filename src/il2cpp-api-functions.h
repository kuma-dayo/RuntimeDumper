DO_API(0, LPVOID, il2cpp_string_new, (const char *str));

// MetadataCache
DO_API(0, LPVOID, il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex, (uint32_t index));

// Type
DO_API(0, std::string, il2cpp__vm__Type__GetName, (LPVOID type, uint32_t format));

// Class
DO_API(0, LPVOID, il2cpp__vm__Class__GetMethods, (LPVOID klass, LPVOID iter));
DO_API(0, LPVOID, il2cpp__vm__Class_GetFields, (LPVOID klass, LPVOID iter));
DO_API(0, LPVOID, il2cpp__vm__Class_FromType, (LPVOID type));

// Method
DO_API(0, std::string, il2cpp__vm__Method__GetNameWithGenericTypes, (LPVOID method));

// Field
DO_API(0, char*, il2cpp__vm__Field__GetName, (LPVOID field));