#pragma once
#include <windows.h>

// given a char, return the lowercase
#define toLower(c) ((c >= 0x41 && c <= 0x5a) ? c - ('A'-'a') : c)


// like wcscmp, but case insensitive
int strcmpLowerW(LPWSTR str1, LPWSTR str2) {
    if (!str1 && !str2)
        return 0;
    if (!str1)
        return -1;
    if (!str2)
        return 1;

    while (*str1 && toLower(*str1) == toLower(*str2)) {
        str1++;
        str2++;
    }
    return toLower(*str1) - toLower(*str2);
}