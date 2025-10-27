#pragma once

#include <string>
#include <chrono>
#include "TokenCache.h"

class AuthClient {
public:
    AuthClient(const std::string& clientId,
        const std::string& tenantId,
        const std::string& redirectUri);
    void startLoginFlow();
    std::wstring getAccessToken();

    std::wstring getAccessToken(std::string scope);

private:
    std::wstring clientId_, tenantId_, redirectUri_, scope_;
    std::wstring accessToken_, refreshToken_;
    std::chrono::system_clock::time_point expiry_;
    std::wstring codeVerifier_;


    void openBrowserForLogin();
    std::wstring listenForCode();
    std::string httpPost(const std::wstring& host, const std::wstring& path, const std::wstring& postData);
    std::wstring extractJsonField(const std::wstring& json, const std::wstring& field);
    bool exchangeCodeForToken(const std::wstring& code);
    std::wstring convertToWString(const std::string& str);
    TokenCache mTokenCache;
};