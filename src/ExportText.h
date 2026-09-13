#pragma once
#include <string>
#include <string_view>

inline std::string IdaLabel(std::string_view value)
{
    std::string result;
    for (unsigned char c : value) {
        result += ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == ':' || c == '_')
                      ? static_cast<char>(c) : '_';
    }
    return result.empty() ? "unnamed" : result;
}

inline std::string PythonString(std::string_view value)
{
    constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : value) {
        if (c == '\\' || c == '"') {
            result += '\\';
            result += static_cast<char>(c);
        } else if (c < 32 || c == 127) {
            result += "\\x";
            result += hex[c >> 4];
            result += hex[c & 15];
        } else {
            result += static_cast<char>(c);
        }
    }
    result += '"';
    return result;
}
