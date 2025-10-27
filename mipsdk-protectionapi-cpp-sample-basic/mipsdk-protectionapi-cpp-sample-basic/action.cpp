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

#include "action.h"

#include "mip/common_types.h"
#include "mip/protection/protection_profile.h"
#include "mip/protection/protection_engine.h"
#include "mip/protection/protection_handler.h"
#include "mip/protection_descriptor.h"
#include "mip/protection/protection_descriptor_builder.h"
#include "mip/protection/roles.h"
#include "mip/protection/rights.h"

#include "mip/file/file_profile.h"
#include "mip/file/file_engine.h"
#include "mip/file/file_handler.h"
#include "mip/file/labeling_options.h"


#include "auth_delegate_impl.h"
#include "consent_delegate_impl.h"
#include "protection_observers.h"
#include "file_profile_observer_impl.h"
#include "file_handler_observer_impl.h"
#include "utils.h"

#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include "AuthClient.h"


#ifdef _WIN32
	#define FREAD(buffer, elementSize, count, stream) fread_s(buffer, count, elementSize, count, stream)
#else
	#define FREAD fread
#endif

using std::cout;
using std::endl;

using mip::ProtectionProfile;
using mip::ProtectionEngine;
using mip::ProtectionHandler;

using mip::FileProfile;
using mip::FileEngine;
using mip::FileHandler;

namespace sample {
	namespace protection {

		// Constructor accepts mip::ApplicationInfo object and uses it to initialize AuthDelegateImpl.
		// Specifically, AuthDelegateInfo uses mAppInfo.ApplicationId for AAD client_id value.		
		Action::Action(const mip::ApplicationInfo appInfo,
			const std::string& username,
			const std::string& password)
			: mAppInfo(appInfo),
			mUsername(username),
			mPassword(password) {
			mAuthDelegate = std::make_shared<sample::auth::AuthDelegateImpl>(mAppInfo, mUsername, mPassword);
			bmipInitialized = false;
		}

		Action::Action(const mip::ApplicationInfo appInfo, const std::string& username, const std::string& clientID, const std::string& tenantID, const std::string& redirectURI, const bool generateAuditEvents)
			: mAppInfo(appInfo), mUsername(username),
			mGenerateAuditEvents(generateAuditEvents)
		{
			mAuthDelegate = std::make_shared<sample::auth::AuthDelegateImpl>(mAppInfo, username, clientID, tenantID, redirectURI);
			bmipInitialized = false;
		}
		
		Action::~Action()
		{
			mEngine = nullptr;
			mProfile = nullptr;
			mMipContext->ShutDown();
			mMipContext = nullptr;

			mFileProfile = nullptr;
			mFileEngine = nullptr;
		}

		void sample::protection::Action::AddNewProtectionProfile()
		{	
			if (bmipInitialized == false)
			{
				// Initialize MipConfiguration
				std::shared_ptr<mip::MipConfiguration> mipConfiguration =
					std::make_shared<mip::MipConfiguration>(
						mAppInfo,                    // ApplicationInfo
						"mip_data",                  // Working directory for cache/logs
						mip::LogLevel::Trace,        // Log level
						false,                       // Allow network (false = offline mode)
						mip::CacheStorageType::OnDisk  // Cache storage type (new parameter)
					);

				// Initialize MipContext. MipContext can be set to null at shutdown and will automatically release all resources.
				mMipContext = mip::MipContext::Create(mipConfiguration);

				bmipInitialized = true;

			}
			// Initialize ProtectionProfileSettings using MipContext
			ProtectionProfile::Settings profileSettings(mMipContext,
				mip::CacheStorageType::OnDiskEncrypted,
				std::make_shared<sample::consent::ConsentDelegateImpl>(),
				std::make_shared<ProtectionProfileObserverImpl>()
			);

			auto httpDelegate = std::make_shared<HttpDelegateImp>();
			profileSettings.SetHttpDelegate(httpDelegate);

			auto profilePromise = std::make_shared<std::promise<std::shared_ptr<ProtectionProfile>>>();
			auto profileFuture = profilePromise->get_future();			
			ProtectionProfile::LoadAsync(profileSettings, profilePromise);			
			mProfile = profileFuture.get();
		}
		
		void Action::AddNewProtectionEngine()
		{			
			if (!mProfile)
			{
				AddNewProtectionProfile();
			}
		
			// Set the engine identity to the provided username. This username is used for service discovery.
			ProtectionEngine::Settings engineSettings(mip::Identity(mUsername), mAuthDelegate, "");
			
			// Set the engine Id to the username of the authenticated user. This will ensure that the same engine is loaded and the cache utilized properly. 
			engineSettings.SetEngineId(mUsername);

			auto enginePromise = std::make_shared<std::promise<std::shared_ptr<ProtectionEngine>>>();
			auto engineFuture = enginePromise->get_future();
			mProfile->AddEngineAsync(engineSettings, enginePromise);
			mEngine = engineFuture.get();	

			// Output the engine id to the console. 
			cout << "Engine Id: " << mEngine->GetSettings().GetEngineId() << endl;
		}
		
		std::shared_ptr<mip::ProtectionHandler> Action::CreateProtectionHandlerForPublishing(const std::shared_ptr<mip::ProtectionDescriptor>& descriptor)
		{
			auto handlerPromise = std::make_shared<std::promise<std::shared_ptr<ProtectionHandler>>>();
			auto handlerFuture = handlerPromise->get_future();

			auto handlerObserver = std::make_shared<ProtectionHandlerObserverImpl>();

			mip::ProtectionHandler::PublishingSettings publishingSettings = mip::ProtectionHandler::PublishingSettings(descriptor);
			mEngine->CreateProtectionHandlerForPublishingAsync(publishingSettings, handlerObserver, handlerPromise);
			
			auto handler = handlerFuture.get();			
			
			return handler;
		}

		std::shared_ptr<mip::ProtectionHandler> Action::CreateProtectionHandlerForConsumption(const std::vector<uint8_t>& serializedPublishingLicense) {
			// Note: Applications can optionally require user consent to acquire a protection handler by implementing the
			//  ConsentDelegate interfaces and passing the object when creating a ProtectionProfile

			auto handlerPromise = std::make_shared<std::promise<std::shared_ptr<ProtectionHandler>>>();
			auto handlerFuture = handlerPromise->get_future();
			shared_ptr<ProtectionHandlerObserverImpl> handlerObserver = std::make_shared<ProtectionHandlerObserverImpl>();

			mip::ProtectionHandler::ConsumptionSettings consumptionSettings = mip::ProtectionHandler::ConsumptionSettings(serializedPublishingLicense);
			mEngine->CreateProtectionHandlerForConsumptionAsync(consumptionSettings, handlerObserver, handlerPromise);
			
			auto h = handlerFuture.get();						
			return h;
		}
	

		std::shared_ptr<mip::ProtectionDescriptor> Action::CreateProtectionDescriptor(const ProtectionOptions protectionOptions)
		{
			if (!protectionOptions.templateId.empty())
			{
				auto descriptorBuilder = mip::ProtectionDescriptorBuilder::CreateFromTemplate(protectionOptions.templateId);				
				return descriptorBuilder->Build();
			}
			return nullptr;
		}


		// Function recursively lists all labels available for a user to	std::cout.
		void Action::ListTemplates() {

			// If mEngine hasn't been set, call AddNewFileEngine() to load the engine.
			if (!mEngine) {			
				AddNewProtectionEngine();
			}

			const shared_ptr<ProtectionEngineObserverImpl> engineObserver = std::make_shared<ProtectionEngineObserverImpl>();

			// Create a context to pass to 'ProtectionEngine::GetTemplateListAsync'. That context will be forwarded to the
			// corresponding ProtectionEngine::Observer methods. In this case, we use promises/futures as a simple way to detect 
			// the async operation completes synchronously.
			auto loadPromise = std::make_shared<std::promise<vector<shared_ptr<mip::TemplateDescriptor>>>>();
			std::future<vector<shared_ptr<mip::TemplateDescriptor>>> loadFuture = loadPromise->get_future();
			mEngine->GetTemplatesAsync(engineObserver, loadPromise);


			auto templates = loadFuture.get();
			
			for (const auto& protectionTemplate: templates) {
				cout << "Name: " << protectionTemplate->GetName() << " : " << protectionTemplate->GetId() << endl;				
			}
		}

		std::vector<uint8_t> Action::ProtectString(const std::string& plaintext, std::string& ciphertext, const std::string& templateId)
		{
			if (!mEngine) {
				AddNewProtectionEngine();
			}

			ProtectionOptions protectionOptions;
			protectionOptions.templateId = templateId;

			auto descriptor = CreateProtectionDescriptor(protectionOptions);

			auto handler = CreateProtectionHandlerForPublishing(descriptor);
			std::vector<uint8_t> outputBuffer;
			// std::vector<uint8_t> inputBuffer(static_cast<size_t>(plaintext.size()));
			std::vector<uint8_t> inputBuffer(plaintext.begin(), plaintext.end());

			outputBuffer.resize(static_cast<size_t>(handler->GetProtectedContentLength(plaintext.size(), true)));
			
			handler->EncryptBuffer(0,
				&inputBuffer[0],
				static_cast<int64_t>(inputBuffer.size()),
				&outputBuffer[0],
				static_cast<int64_t>(outputBuffer.size()),
				true);
			
			std::string output(outputBuffer.begin(), outputBuffer.end());
			ciphertext = output;

			return handler->GetSerializedPublishingLicense();
		}

		void Action::DecryptString(std::string& plaintext, const std::string& ciphertext, const std::vector<uint8_t>& serializedLicense)
		{
			if (!mEngine) {
				AddNewProtectionEngine();
			}

			auto handler = CreateProtectionHandlerForConsumption(serializedLicense);
			std::vector<uint8_t> outputBuffer(static_cast<size_t>(ciphertext.size()));

				
			// std::vector<uint8_t> inputBuffer(static_cast<size_t>(plaintext.size()));
			std::vector<uint8_t> inputBuffer(ciphertext.begin(), ciphertext.end());
			
			int64_t decryptedSize = handler->DecryptBuffer(
				0,
				&inputBuffer[0],
				static_cast<int64_t>(inputBuffer.size()),
				&outputBuffer[0],
				static_cast<int64_t>(outputBuffer.size()),
				true);
			outputBuffer.resize(static_cast<size_t>(decryptedSize));
						
			std::string output(outputBuffer.begin(), outputBuffer.end());
			plaintext = output;
		}
	

		//File API

		// Method illustrates how to create a new mip::FileProfile using promise/future
		// Result is stored in private mProfile variable and referenced throughout lifetime of Action.
		void sample::protection::Action::AddNewFileProfile()
		{
			// Initialize MipConfiguration.
			/*std::shared_ptr<mip::MipConfiguration> mipConfiguration = std::make_shared<mip::MipConfiguration>(mAppInfo,
				"mip_data",
				mip::LogLevel::Trace,
				false);*/

			if (bmipInitialized == false) {

				std::shared_ptr<mip::MipConfiguration> mipConfiguration =
					std::make_shared<mip::MipConfiguration>(
						mAppInfo,                    // ApplicationInfo
						"mip_data",                  // Working directory for cache/logs
						mip::LogLevel::Trace,        // Log level
						false,                       // Allow network (false = offline mode)
						mip::CacheStorageType::OnDisk  // Cache storage type (new parameter)
					);


				// This section can be uncommented to enable CBC mode publishing for testing. 			
				std::map<mip::FlightingFeature, bool> featureSettings = std::map<mip::FlightingFeature, bool>();
				featureSettings.emplace(mip::PrioritizeHtmlInMsgs, true);
				mipConfiguration->SetFeatureSettings(featureSettings);

				// This section can be uncommented to enable CBC mode publishing for testing. 			
				//std::map<mip::FlightingFeature, bool> featureSettings = std::map<mip::FlightingFeature, bool>();
				//featureSettings.emplace(mip::UseCbcForOfficeFileEncryption, true);
				//mipConfiguration->SetFeatureSettings(featureSettings);

				// Initialize MipContext. MipContext can be set to null at shutdown and will automatically release all resources.
				mMipContext = mip::MipContext::Create(mipConfiguration);
				bmipInitialized = true;

			}

		
			// Initialize the FileProfile::Settings Object.  
			// Accepts MipContext, AuthDelegate, new ConsentDelegate, new FileProfile::Observer object as last parameters.
			FileProfile::Settings profileSettings(mMipContext,
				mip::CacheStorageType::OnDiskEncrypted,
				std::make_shared<sample::consent::ConsentDelegateImpl>(),
				std::make_shared<FileProfileObserver>());


			// Register your HTTP delegate at the configuration level
			auto httpDelegate = std::make_shared<HttpDelegateImp>();
			profileSettings.SetHttpDelegate(httpDelegate);

			// Create promise and future for mip::FileProfile object.
			std::shared_ptr<std::promise<std::shared_ptr<mip::FileProfile>>> profilePromise = std::make_shared<std::promise<std::shared_ptr<FileProfile>>>();
			std::future<std::shared_ptr<mip::FileProfile>> profileFuture = profilePromise->get_future();

			// Call static function LoadAsync providing the settings and promise. This will make the profile available to use.
			FileProfile::LoadAsync(profileSettings, profilePromise);

			// Get the future value and store in mProfile. mProfile is used throughout Action for profile operations.
			mFileProfile = profileFuture.get();
		}

		// Action::AddNewFileEngine adds an engine for a specific user. 		
		void Action::AddNewFileEngine()
		{
			// If mProfile hasn't been set, use AddNewFileProfile() to set it.
			if (!mProfile)
			{
				AddNewFileProfile();
			}

			string id = mUsername + std::to_string(rand());

			// FileEngine requires a FileEngine::Settings object. The first parameter is the user identity or engine ID. 
			FileEngine::Settings engineSettings(mip::Identity(mUsername),
				mAuthDelegate,
				"",
				"en-US",
				false);

			// Set the engineId to the username. This ensures that the same engine is loaded across sessions.
			//engineSettings.SetEngineId(id);

			//auto httpDelegate = std::make_shared<HttpDelegateImp>();
			//engineSettings.SetHttpDelegate(httpDelegate);

			// Create promise and future for mip::FileEngine object
			std::shared_ptr<std::promise<std::shared_ptr<mip::FileEngine>>> enginePromise = std::make_shared<std::promise<std::shared_ptr<FileEngine>>>();
			std::future<std::shared_ptr<mip::FileEngine>> engineFuture = enginePromise->get_future();

			// Engines are added to profiles. Call AddEngineAsync on mProfile, providing settings and promise
			// then get the future value and set in mEngine. mEngine will be used throughout Action for engine operations.
			mFileProfile->AddEngineAsync(engineSettings, enginePromise);
			mFileEngine = engineFuture.get();
		}

		// Creates a mip::FileHandler and returns to the caller. 
		// FileHandlers obtain a handle to a specific file, then perform any File API operations on the file.
		std::shared_ptr<mip::FileHandler> Action::CreateFileHandler(const std::string& filepath)
		{
			// Create promise/future for mip::FileHandler
			std::shared_ptr<std::promise<std::shared_ptr<mip::FileHandler>>> handlerPromise = std::make_shared<std::promise<std::shared_ptr<FileHandler>>>();
			std::future<std::shared_ptr<mip::FileHandler>> handlerFuture = handlerPromise->get_future();

			// Use mEngine::CreateFileHandlerAsync to create the handler
			// Filepath, the mip::FileHandler::Observer implementation, and the promise are required. 
			// Event notification will be provided to the appropriate function in the observer.
			// isAuditDiscoveryEnabled is set to true. This will generate discovery audits in AIP Analytics
			mFileEngine->CreateFileHandlerAsync(filepath, filepath, mGenerateAuditEvents, std::static_pointer_cast<FileHandler::Observer>(std::make_shared<FileHandlerObserver>()), handlerPromise);

			// Get the value and store in a mip::FileHandler object.
			// auto resolves to std::shared_ptr<mip::FileHandler>
			auto handler = handlerFuture.get();

			// return the pointer to mip::FileHandler to the caller
			return handler;
		}


		// Function recursively lists all labels available for a user to	std::cout.
		void Action::ListLabels() {

			// If mEngine hasn't been set, call AddNewFileEngine() to load the engine.
			if (!mFileEngine) {
				AddNewFileEngine();
			}

			// Use mip::FileEngine to list all labels
			auto labels = mFileEngine->ListSensitivityLabels();

			// Iterate through each label, first listing details
			for (const auto& label : labels) {
				cout << label->GetName() << " : " << label->GetId() << endl;

				// get all children for mip::Label and list details
				for (const auto& child : label->GetChildren()) {
					cout << "->  " << child->GetName() << " : " << child->GetId() << endl;
				}
			}
		}

		// Reads a label from the file at filepath, the displays.
		// Reading a label from a protected file will trigger consent flow, as implemented in mip::ConsentDelegate or derived classes.
		// In this sample, simple consent flow is implemented in consent_delegate_impl.h/cpp.
		void Action::ReadLabel(const std::string& filepath)
		{
			cout << "Attempting to read label from output file." << endl;

			// Call private CreateFileHandler function, passing in file path. 
			// Returns a std::shared_ptr<mip::FileHandler> that will be used to read the label.
			auto handler = CreateFileHandler(filepath);

			// call mip::FileHandler::GetLabelAsync, passing in the promise.
			// The handler has the rest of the details it needs (file path and policy data via FileEngine) to display result.

			auto label = handler->GetLabel();

			// Output results
			if (nullptr != label)
			{
				// Attempt to fetch parent label.
				auto parentLabel = std::shared_ptr<mip::Label>(label->GetLabel()->GetParent());

				// If parent exists, output parent \ child.
				if (nullptr != parentLabel)
				{
					cout << "Name: " + parentLabel->GetName() + "\\" + label->GetLabel()->GetName() << endl;
					cout << "Id: " + label->GetLabel()->GetId() << endl;
				}
				// Else, output label info
				else
				{
					cout << "Name: " + label->GetLabel()->GetName() << endl;
					cout << "Id: " + label->GetLabel()->GetId() << endl;
				}
			}
			else
			{
				cout << "No label found." << endl;
			}
		}


		// Implements the code to assign a label to a file
		// Creates a file handler for filepath, sets the label with labelId, and writes the result to outputfile
		void Action::SetLabel(const std::string& filepath, const std::string& outputfile, const std::string& labelId)
		{
			// Call private CreateFileHandler function, passing in file path. 
			// Returns a std::shared_ptr<mip::FileHandler> that will be used to read the label.
			auto handler = CreateFileHandler(filepath);

			// Labeling requires a mip::LabelingOptions object. 
			// Review API ref for more details. The sample implies that the file was labeled manually by a user.
			mip::LabelingOptions labelingOptions(mip::AssignmentMethod::PRIVILEGED);

			// use the mip::FileHandler to set label with labelId and labelOptions created above
			handler->SetLabel(mFileEngine->GetLabelById(labelId), labelingOptions, mip::ProtectionSettings());

			// Changes to the file held by mip::FileHandler aren't committed until CommitAsync is called.						
			// Call Action::CommitChanges to write changes. Commit logic is implemented there.
			bool result = CommitChanges(handler, outputfile);

			// Write result to console.
			if (result) {
				cout << "Labeled: " + outputfile << endl;
			}
			else {
				cout << "Failed to label: " + outputfile << endl;
			}
		}

		// Implements code to commit changes made via mip::FileHandler
		// Accepts pointer to the mip::FileHandler and output file path
		bool Action::CommitChanges(const std::shared_ptr<mip::FileHandler>& fileHandler, const std::string& outputFile)
		{
			bool result = false;

			// Commit only if handler has been modified. Otherwise, return false.
			if (fileHandler->IsModified())
			{
				// CommitAsync is implemented similar to other async patterns via promise/future
				// In this instance, rather than a mip related object, we create the promise for a bool
				// The result provided will be true if the file was written, false if it failed.
				auto commitPromise = std::make_shared<std::promise<bool>>();
				auto commitFuture = commitPromise->get_future();

				// Commit changes to file referenced by fileHandler, writing to output file.
				fileHandler->CommitAsync(outputFile, commitPromise);
				result = commitFuture.get();

				// If flag is set to generate audit events, call mip::FileHandler::NotifyCommitSuccessful() to generate audit entry.
				if (mGenerateAuditEvents && result)
				{
					fileHandler->NotifyCommitSuccessful(outputFile);
				}
			}

			// Get value from future and return to caller. Will be true if operation succeeded, false otherwise.
			return result;
		}




	}
}
