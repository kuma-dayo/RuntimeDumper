#pragma once

#define DO_API(a, r, n, p) extern r(*n) p
#include "il2cpp-api-functions.h"
#undef DO_API
