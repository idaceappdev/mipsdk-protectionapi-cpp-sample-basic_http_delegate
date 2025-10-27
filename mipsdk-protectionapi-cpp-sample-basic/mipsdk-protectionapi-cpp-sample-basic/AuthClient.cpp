#include "AuthClient.h"
#include <winsock2.h>

#include "AuthClient.h"
#include <winsock2.h>
#include <Windows.h>
#include <winhttp.h>
#include <fstream>
#include <thread>
#include <iostream>
#include <sstream>

#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

#include <locale>
#include <codecvt> // OK if you're using C++11–C++17
#include <algorithm> // Required for std::replace
#include <string>
#include <random>
#include <vector>
#include <iomanip>
#pragma comment(lib, "Crypt32.lib")

////////////////////////////////////////////////////////////

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// Helper: Base64 URL-safe encoding (no padding)
std::string base64UrlEncode(const BYTE* data, DWORD length) {
    DWORD base64Len = 0;
    if (!CryptBinaryToStringA(data, length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Len)) {
        throw std::runtime_error("Failed to calculate base64 length.");
    }

    std::string base64(base64Len, '\0');
    if (!CryptBinaryToStringA(data, length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64[0], &base64Len)) {
        throw std::runtime_error("Base64 encoding failed.");
    }

    // Make it URL-safe
    base64.erase(std::remove(base64.begin(), base64.end(), '\n'), base64.end());
    base64.erase(std::remove(base64.begin(), base64.end(), '\r'), base64.end());
    base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());
    std::replace(base64.begin(), base64.end(), '+', '-');
    std::replace(base64.begin(), base64.end(), '/', '_');
    return base64;
}

// Generate random string
std::string generateRandomString(size_t length) {
    std::vector<BYTE> buffer(length);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer.data(), buffer.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        throw std::runtime_error("Random generation failed.");
    }

    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[buffer[i] % (sizeof(charset) - 1)];
    }
    return result;
}

// SHA256 hash using bcrypt
std::string sha256Base64Url(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashObjectSize = 0, dataLen = 0;
    std::vector<BYTE> hashObject;
    std::vector<BYTE> hash(32);

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed.");
    }

    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(DWORD), &dataLen, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGetProperty failed.");
    }

    hashObject.resize(hashObjectSize);

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize,
        NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptCreateHash failed.");
    }

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptHashData failed.");
    }

    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptFinishHash failed.");
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return base64UrlEncode(hash.data(), static_cast<DWORD>(hash.size()));
}







////////////////////////////////////////////////////////////

AuthClient::AuthClient(const std::string& clientId, const std::string& tenantId,
                       const std::string& redirectUri)
    : clientId_(convertToWString(clientId)), tenantId_(convertToWString(tenantId)), redirectUri_(convertToWString(redirectUri)) {
    
}



void AuthClient::openBrowserForLogin() {
    std::string state = generateRandomString(16);                // Random state
    std::string codeVerifier = generateRandomString(64);         // RFC recommends 43-128 chars
    std::string codeChallenge = sha256Base64Url(codeVerifier);   // S256 method

    std::wstring url = L"https://login.microsoftonline.com/" + tenantId_ +
        L"/oauth2/v2.0/authorize?client_id=" + clientId_ +
        L"&response_type=code&redirect_uri=" + redirectUri_ +
        L"&response_mode=query&scope=" + scope_ +
        L"&state=" + std::wstring(state.begin(), state.end()) +
        L"code_challenge =" + std::wstring(codeChallenge.begin(), codeChallenge.end()) +// = YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmEyZGRhOGYyM2IzNjdmZWFhMTQ1ODg3NDcxY2Nl" +
        L"code_challenge_method = S256" + 
        L"&prompt=select_account";

    ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

std::wstring AuthClient::listenForCode() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::wcerr << L"Socket creation failed: " << WSAGetLastError() << std::endl;
        return L"";
    }

    sockaddr_in service{};
    service.sin_family = AF_INET;
    //service.sin_addr.s_addr = inet_addr("127.0.0.1");
    InetPton(AF_INET, L"127.0.0.1", &service.sin_addr);
    service.sin_port = htons(8080);  // Match this to your redirect URI!

    if (bind(serverSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        std::wcerr << L"Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        return L"";
    }

    if (listen(serverSocket, 1) == SOCKET_ERROR) {
        std::wcerr << L"Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        return L"";
    }

    std::wcout << L"Waiting for browser redirect with auth code..." << std::endl;

    SOCKET clientSocket = accept(serverSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        std::wcerr << L"Accept failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        return L"";
    }

    char buffer[4096];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';

    std::string reqStr(buffer);
    std::wcout << L"HTTP request: " << std::wstring(reqStr.begin(), reqStr.end()) << std::endl;

    // Simple code parser from GET /?code=XYZ
    std::string prefix = "GET /?code=";
    size_t codeStart = reqStr.find(prefix);
    std::wstring code;
    if (codeStart != std::string::npos) {
        size_t codeEnd = reqStr.find(' ', codeStart);
        std::string codeStr = reqStr.substr(codeStart + prefix.length(), codeEnd - (codeStart + prefix.length()));
        code = std::wstring(codeStr.begin(), codeStr.end());
    }

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                           "<html><body>Login complete. You may close this window.</body></html>";
    send(clientSocket, response.c_str(), response.size(), 0);

    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();

    return code;
}


std::string convertToUtf8(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

std::string AuthClient::httpPost(const std::wstring& host, const std::wstring& path, const std::wstring& postData) {
    HINTERNET hSession = WinHttpOpen(L"AuthClient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    std::wstring headers = L"Content-Type: application/x-www-form-urlencoded";
    std::string utf8Data = convertToUtf8(postData);

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1,
        (LPVOID)utf8Data.c_str(), (DWORD)(utf8Data.size()),
        (DWORD)(utf8Data.size()), 0);

    WinHttpReceiveResponse(hRequest, NULL);
    std::string response;
    DWORD dwSize = 0;
    do {
        DWORD dwDownloaded = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize == 0) break;
        char* buffer = new char[dwSize + 1];
        ZeroMemory(buffer, dwSize + 1);
        WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded);
        response.append(buffer, dwDownloaded);
        delete[] buffer;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}


std::wstring AuthClient::extractJsonField(const std::wstring& json, const std::wstring& field) {
    std::wstring keyQuoted = L"\"" + field + L"\":";
    auto pos = json.find(keyQuoted);
    if (pos == std::wstring::npos) return L"";

    pos += keyQuoted.length();

    // Skip whitespace
    while (pos < json.length() && iswspace(json[pos])) ++pos;

    // Check if it's quoted
    if (json[pos] == L'"') {
        ++pos;
        auto end = json.find(L"\"", pos);
        if (end == std::wstring::npos) return L"";
        return json.substr(pos, end - pos);
    }
    else {
        // Parse until comma or closing brace
        auto end = json.find_first_of(L",}", pos);
        if (end == std::wstring::npos) return L"";
        return json.substr(pos, end - pos);
    }
}


// Helper to convert std::string (UTF-8) to std::wstring
std::wstring AuthClient::convertToWString(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.from_bytes(str);
}

bool AuthClient::exchangeCodeForToken(const std::wstring& code) {
    std::wstring host = L"login.microsoftonline.com";
    std::wstring path = L"/" + tenantId_ + L"/oauth2/v2.0/token";
    std::wstring data = L"client_id=" + clientId_ +
        L"&scope=" + scope_ +
        L"&code=" + code +
        L"&redirect_uri=" + redirectUri_ +
        L"&grant_type=authorization_code";

    std::string rawResponse = httpPost(host, path, data); // std::string
    std::wstring response = convertToWString(rawResponse); // 🔁 Convert to std::wstring

    accessToken_ = extractJsonField(response, L"access_token");
    refreshToken_ = extractJsonField(response, L"refresh_token");
    int expiresIn = std::stoi(extractJsonField(response, L"expires_in"));
    expiry_ = std::chrono::system_clock::now() + std::chrono::seconds(expiresIn);
    mTokenCache.updateToken(scope_, accessToken_, expiry_);
    //saveTokenToFile();
    return !accessToken_.empty();
}
/*
void AuthClient::saveTokenToFile() {
    std::wofstream out("token_cache.txt");
    out << accessToken_ << std::endl
        << refreshToken_ << std::endl
        << std::chrono::duration_cast<std::chrono::seconds>(expiry_.time_since_epoch()).count();
}

void AuthClient::loadTokenFromFile() {
    std::wifstream in("token_cache.txt");
    if (!in) return;
    std::wstring line;
    std::getline(in, accessToken_);
    std::getline(in, refreshToken_);
    std::getline(in, line);
    if (!line.empty()) {
        long long secs = std::stoll(line);
        expiry_ = std::chrono::system_clock::time_point(std::chrono::seconds(secs));
    }
}

bool AuthClient::isTokenExpired() {
    return std::chrono::system_clock::now() >= expiry_;
}
*/

void AuthClient::startLoginFlow() {
    openBrowserForLogin();
    std::wstring code = listenForCode();
    exchangeCodeForToken(code);
}

std::wstring AuthClient::getAccessToken() {

    startLoginFlow();
    return accessToken_;
}


std::wstring AuthClient::getAccessToken (std::string scope) {

    scope_ = convertToWString(scope);
    std::wstring waccessToken;

    if (mTokenCache.isTokenValid(scope_))
    {
        waccessToken = mTokenCache.getToken(scope_);
    }
    else
    {        
        waccessToken = getAccessToken();
       
    } 

    return waccessToken;
    
}

