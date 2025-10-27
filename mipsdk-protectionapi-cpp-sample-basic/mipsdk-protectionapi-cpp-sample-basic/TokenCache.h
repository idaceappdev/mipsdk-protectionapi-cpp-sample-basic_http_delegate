#pragma once
#include <string>
#include <unordered_map>
#include <chrono>

struct TokenInfo {
    std::wstring token;
    std::chrono::system_clock::time_point expiry;
};

class TokenCache {
public:
    // Check if token exists and is valid for a given scope
    bool isTokenValid(const std::wstring& scope) const;

    // Retrieve token if valid; returns empty wstring otherwise
    std::wstring getToken(const std::wstring& scope) const;

    // Add or update token for a given scope
    void updateToken(const std::wstring& scope, const std::wstring& token, std::chrono::system_clock::time_point expiry);

    bool loadFromFile(const std::wstring& filename);

    bool saveToFile() const;

    TokenCache(const std::wstring& filename);

    TokenCache();

private:
    std::unordered_map<std::wstring, TokenInfo> tokenMap;
    std::wstring mCacheFile;
};
