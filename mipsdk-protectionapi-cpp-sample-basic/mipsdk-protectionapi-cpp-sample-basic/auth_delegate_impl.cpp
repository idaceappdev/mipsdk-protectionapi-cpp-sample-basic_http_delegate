/**
*
* Copyright (c) Microsoft Corporation.
* All rights reserved.
*
* This code is licensed under the MIT License.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*/


#include "auth_delegate_impl.h"
#include "auth.h"
#include <windows.h>

#include <stdexcept>
using namespace std;

using std::runtime_error;
using std::string;

namespace sample {
	namespace auth {

		AuthDelegateImpl::AuthDelegateImpl(
			const mip::ApplicationInfo& applicationInfo)
			: mApplicationInfo(applicationInfo) {
		}

		AuthDelegateImpl::AuthDelegateImpl(const mip::ApplicationInfo& applicationInfo, const std::string& username, const std::string& clientId, const std::string& tenantId, const std::string& redirectUri/*, const std::string& scope*/) : mApplicationInfo(applicationInfo), mUserName(username)
		{

			mptrAuthClient = new AuthClient(clientId, tenantId, redirectUri);

		}

		AuthDelegateImpl::AuthDelegateImpl(
			const mip::ApplicationInfo& applicationInfo,
			const std::string& username,
			const std::string& password)
			: mApplicationInfo(applicationInfo),
			mUserName(username),
			mPassword(password) {
		}

		std::string  AuthDelegateImpl::WStringToString(const std::wstring& wstr) {
			if (wstr.empty()) return std::string();

			int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string result(size_needed, 0);
			WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size_needed, nullptr, nullptr);
			result.pop_back(); // remove null terminator
			return result;
		}

		bool AuthDelegateImpl::AcquireOAuth2Token(
			const mip::Identity& /*identity*/,
			const OAuth2Challenge& challenge,
			OAuth2Token& token) {

			string accessToken;
			string resource = challenge.GetResource();

			std::string scope;

			if (!resource.empty() && resource.back() == '/') {
				scope = resource + ".default";
			}
			else {
				scope = resource + "/.default";
			}

			//string authority = challenge.GetAuthority();



			if (mptrAuthClient)
			{
				//accessToken = mptrAuthClient->getAccessToken(scope);
				std::wstring waccesstoken = mptrAuthClient->getAccessToken(scope);
				accessToken = WStringToString(waccesstoken);
			}
			else
			{
				accessToken = sample::auth::AcquireToken(mUserName, mPassword, mApplicationInfo.applicationId, challenge.GetResource(), challenge.GetAuthority());
			}

			//call our AcquireToken function, passing in username, password, clientId, and getting the resource/authority from the OAuth2Challenge object

			token.SetAccessToken(accessToken);

			return true;
		}

	} // namespace sample
} // namespace auth