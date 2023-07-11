#include "pch.h"

#ifndef   C_HPP
#define   C_HPP

class String
{
public:
    LPVOID klass;
    LPVOID monitor;
    uint32_t length;
    char chars[];

    char* c_str() {
        return chars;
    };

    uint32_t size() {
        return length;
    };
};
#endif // C_HPP
