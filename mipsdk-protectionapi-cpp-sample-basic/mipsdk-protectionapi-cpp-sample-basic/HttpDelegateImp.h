#ifndef _HTTP_DELEGATE_IMPL_H
#define _HTTP_DELEGATE_IMPL_H
#endif

#pragma once
#define CURL_STATICLIB
#include "mip/http_delegate.h"
#include <iostream>
#include <curl/curl.h>
#include <mutex>

#define MIP_SDK_USER_AGENT "User-Agent: Microsoft.MIP.SDK/1.15.104"

class MipCreds
{

};
class HttpResponseImp : public mip::HttpResponse {

    int32_t m_statusCode;
    std::vector<uint8_t> m_Body;
    std::string m_id;
    std::map<std::string, std::string, mip::CaseInsensitiveComparator> m_mapObj; /*not in use*/

public:

    void setId(std::string id) { m_id = id; }
    void setBody(const std::vector<uint8_t> pBody) { m_Body = pBody; }
    void setStatusCode(int32_t sCode) { m_statusCode = sCode; }

    const std::string& GetId() const { return m_id; }
    int32_t GetStatusCode() const { return m_statusCode; }
    const std::vector<uint8_t>& GetBody() const { return m_Body; }
    const std::map<std::string, std::string, mip::CaseInsensitiveComparator>& GetHeaders() const { return m_mapObj; }
};

class HttpOperationImp : public mip::HttpOperation {
    std::shared_ptr<mip::HttpResponse> m_response;
    std::string m_id;
public:
    void setResponse(std::shared_ptr<mip::HttpResponse>& res) { m_response = res; }
    void setId(std::string id) { m_id = id; }
    const std::string& GetId() const { return m_id; }
    std::shared_ptr<mip::HttpResponse> GetResponse() { return m_response; }
    bool IsCancelled() { return false; }
};

class HttpDelegateImp : public mip::HttpDelegate {

    std::mutex m_tokenMutex;
    std::shared_ptr<MipCreds> m_mipCreds;
    std::shared_ptr<mip::HttpOperation>
        sendRequest(const std::shared_ptr<mip::HttpRequest>& request);
public:
    HttpDelegateImp(std::shared_ptr<MipCreds>& mipCreds) : m_mipCreds(mipCreds) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    HttpDelegateImp() {
        m_mipCreds = std::make_shared<MipCreds>();
        curl_global_init(CURL_GLOBAL_ALL);
    }


    ~HttpDelegateImp() {
        curl_global_cleanup();
    }

    std::shared_ptr<mip::HttpOperation> Send(
        const std::shared_ptr<mip::HttpRequest>& request,
        const std::shared_ptr<void>& context);

    std::shared_ptr<mip::HttpOperation> SendAsync(
        const std::shared_ptr<mip::HttpRequest>& request,
        const std::shared_ptr<void>& context,
        const std::function<void(std::shared_ptr<mip::HttpOperation>)>& callbackFn);

    void CancelOperation(const std::string& requestId) {/*not using*/ }
    void CancelAllOperations() {/*not using*/ }

};

