#include "TokenCache.h"
#include<fstream>

bool TokenCache::isTokenValid(const std::wstring& scope) const {
    auto it = tokenMap.find(scope);
    if (it != tokenMap.end()) {
        auto now = std::chrono::system_clock::now();
        return now < it->second.expiry;
    }
    return false;
}

std::wstring TokenCache::getToken(const std::wstring& scope) const {
    if (isTokenValid(scope)) {
        return tokenMap.at(scope).token;
    }
    return L"";
}

void TokenCache::updateToken(const std::wstring& scope, const std::wstring& token, std::chrono::system_clock::time_point expiry) {
    tokenMap[scope] = { token, expiry };
    saveToFile();
}

bool TokenCache::loadFromFile(const std::wstring& filename)
{
    std::wifstream inFile(filename);
    if (!inFile.is_open()) return false;

    std::wstring scope, token, expiryLine;
    while (std::getline(inFile, scope) &&
        std::getline(inFile, token) &&
        std::getline(inFile, expiryLine)) {

        try {
            long long seconds = std::stoll(expiryLine);
            auto expiry = std::chrono::system_clock::time_point{
                std::chrono::seconds{seconds}
            };
            tokenMap[scope] = { token, expiry };
        }
        catch (...) {
            // skip malformed entry
            continue;
        }
    }

    return true;
}

bool TokenCache::saveToFile() const
{
    if (!mCacheFile.empty())
    {
        std::wofstream outFile(mCacheFile);
        if (!outFile.is_open()) return false;

        for (const auto& pair : tokenMap) {
            const std::wstring& scope = pair.first;
            const TokenInfo& info = pair.second;

            outFile << scope << L'\n'
                << info.token << L'\n'
                << std::chrono::duration_cast<std::chrono::seconds>(
                    info.expiry.time_since_epoch()).count()
                << L'\n';
        }
        return true;
    }

    return false;
}

TokenCache::TokenCache(const std::wstring& filename): mCacheFile(filename)
{
    loadFromFile(mCacheFile);
}

TokenCache::TokenCache()
{
    mCacheFile = L"token_cache.txt";
    loadFromFile(mCacheFile);
}
