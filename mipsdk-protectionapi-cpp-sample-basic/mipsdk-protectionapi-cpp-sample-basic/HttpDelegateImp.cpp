#include "HttpDelegateImp.h"

size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*)ptr, size * nmemb);
    return size * nmemb;
}
std::shared_ptr<mip::HttpOperation>
HttpDelegateImp::Send(const std::shared_ptr<mip::HttpRequest>& request, const std::shared_ptr<void>& context) {
    return sendRequest(request);
}


std::shared_ptr<mip::HttpOperation>
HttpDelegateImp::sendRequest(const std::shared_ptr<mip::HttpRequest>& request) {

    auto operation = std::make_shared<HttpOperationImp>();
    auto response = std::make_shared<HttpResponseImp>();
    bool isAuthHeaderMissing = true;
    std::string responseBody;
    long responseCode = 0;
    CURLcode res = CURLE_OK;
    struct curl_slist* headers = nullptr;
    CURL* curl = nullptr;
    std::string requestbody(request->GetBody().begin(), request->GetBody().end());
    mip::HttpRequestType rType = request->GetRequestType();
    std::string sUrl = request->GetUrl();

    response->setId(request->GetId());
    operation->setId(request->GetId());

    curl = curl_easy_init();
    if (curl == NULL) {
        return operation;
    }
    if (rType == mip::HttpRequestType::Post) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestbody.c_str());
    }
    else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }

    curl_easy_setopt(curl, CURLOPT_URL, sUrl.c_str());

    for (const auto& header : request->GetHeaders()) {
        headers = curl_slist_append(headers, (header.first + ": " + header.second).c_str());
    }
    /*We don't see Authorization Header when it throws 401 error */
    headers = curl_slist_append(headers, MIP_SDK_USER_AGENT);   //--> "User-Agent: Microsoft.MIP.SDK/1.15.104"
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANY);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 1L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        /*logs*/
    }
    else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
        response->setStatusCode(responseCode);
        std::vector<uint8_t> resBody(responseBody.begin(), responseBody.end());
        response->setBody(resBody);
        std::shared_ptr<mipns::HttpResponse> basePtr = std::static_pointer_cast<mipns::HttpResponse>(response);
        operation->setResponse(basePtr);

        return operation;
    }
}


std::shared_ptr<mip::HttpOperation>
HttpDelegateImp::SendAsync(
    const std::shared_ptr<mip::HttpRequest>& request,
    const std::shared_ptr<void>& context,
    const std::function<void(std::shared_ptr<mip::HttpOperation>)>& callbackFn) {


    auto resOps = sendRequest(request);
    if (resOps->GetResponse()) {
        callbackFn(resOps);
    }
    else {
        exit(1);
    }

    return resOps;

}
