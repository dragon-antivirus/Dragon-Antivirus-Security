/*++
===============================================================================
 Dragon-Drivers / DragonRegistryGuard.c

 注册表防护（CmRegisterCallbackEx）。

 关注的通知类：
   RegNtPreCreateKey / RegNtPreCreateKeyEx
   RegNtPreOpenKey   / RegNtPreOpenKeyEx   —— 仅当请求写权限时检查
   RegNtPreDeleteKey
   RegNtPreSetValueKey
   RegNtPreDeleteValueKey

 结构体说明：
   WDK 中 REG_OPEN_KEY_INFORMATION 是 REG_CREATE_KEY_INFORMATION 的别名；
   RegNtPre*Ex 系列实际传入 _V1 变体，但其 CompleteName / RootObject /
   DesiredAccess 三个字段在两种布局中的偏移完全一致（依次 0 / 8 / 56 字节），
   因此这里统一按 REG_CREATE_KEY_INFORMATION 访问是安全的。

 路径拼接：
   通过 CmCallbackGetKeyObjectIDEx 取得根键完整路径，再按需拼接相对名 /
   值名，得到「注册表键全路径」。所有分配都走 DragonAllocate，
   失败分支统一 goto 释放，不存在泄漏路径。
===============================================================================
--*/

#include "DragonCommon.h"

static LARGE_INTEGER g_RegistryCookie;
static BOOLEAN       g_RegistryCookieValid = FALSE;

/*++
@IRQL: <= APC_LEVEL
@brief 判断访问掩码是否包含写入语义。
--*/
static
BOOLEAN
DragonIsRegistryWriteAccess(
    _In_ ACCESS_MASK Access
    )
{
    if ((Access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
                   DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE)) != 0) {
        return TRUE;
    }

    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 由「根键对象 + 相对名」拼出全路径。

@param  OutPath  成功时 Buffer 由 DragonAllocate 分配，调用方负责 DragonFree。
--*/
static
BOOLEAN
DragonBuildKeyPath(
    _In_opt_ PVOID RootObject,
    _In_opt_ PCUNICODE_STRING RelativeName,
    _Out_ PUNICODE_STRING OutPath
    )
{
    PCUNICODE_STRING RootName;
    BOOLEAN RootNameAcquired;
    ULONG RootBytes;
    ULONG RelativeBytes;
    ULONG TotalBytes;
    PWCHAR Buffer;
    PWCHAR Current;
    NTSTATUS Status;

    OutPath->Buffer = NULL;
    OutPath->Length = 0;
    OutPath->MaximumLength = 0;

    RootName = NULL;
    RootNameAcquired = FALSE;

    if (RootObject != NULL && g_RegistryCookieValid == TRUE) {
        Status = CmCallbackGetKeyObjectIDEx(
                     &g_RegistryCookie,
                     RootObject,
                     NULL,
                     &RootName,
                     0);
        if (NT_SUCCESS(Status) && RootName != NULL) {
            RootNameAcquired = TRUE;
        }
    }

    RootBytes = (RootNameAcquired && RootName->Buffer != NULL) ? RootName->Length : 0;
    RelativeBytes = (RelativeName != NULL && RelativeName->Buffer != NULL) ? RelativeName->Length : 0;

    TotalBytes = RootBytes + sizeof(WCHAR) + RelativeBytes + sizeof(WCHAR);

    Buffer = (PWCHAR)DragonAllocate(TotalBytes);
    if (Buffer == NULL) {
        if (RootNameAcquired == TRUE) {
            CmCallbackReleaseKeyObjectIDEx(RootName);
        }
        return FALSE;
    }

    RtlZeroMemory(Buffer, TotalBytes);
    Current = Buffer;

    if (RootBytes > 0) {
        RtlCopyMemory(Current, RootName->Buffer, RootBytes);
        Current += (RootBytes / sizeof(WCHAR));
        if (Current > Buffer && *(Current - 1) != L'\\') {
            *Current = L'\\';
            Current++;
        }
    }

    if (RelativeBytes > 0) {
        if (RootBytes > 0 && RelativeName->Buffer[0] == L'\\') {
            RtlCopyMemory(Current, RelativeName->Buffer + 1, RelativeBytes - sizeof(WCHAR));
        }
        else {
            RtlCopyMemory(Current, RelativeName->Buffer, RelativeBytes);
        }
    }

    if (RootNameAcquired == TRUE) {
        CmCallbackReleaseKeyObjectIDEx(RootName);
    }

    OutPath->Buffer = Buffer;
    OutPath->Length = (USHORT)(DragonWideLength(Buffer) * sizeof(WCHAR));
    OutPath->MaximumLength = (USHORT)TotalBytes;
    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 统一判定入口：先走内置自保护，再走动态规则。

        顺序不可颠倒：动态规则可以被用户态 DrgCmdClearRules 整表清空，
        而内置自保护是编译期固化的。
--*/
static
NTSTATUS
DragonBlockRegistryOperation(
    _In_ PUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ ULONG Operation
    )
{
    HANDLE ProcessId;
    ULONG RuleCode;
    ULONG Action;
    ULONG SelfCode;

    ProcessId = PsGetCurrentProcessId();
    RuleCode = 0;
    Action = DRG_ACTION_REPORT;

    /* 内置自保护：驱动服务键及其子键禁止改值 / 删值 / 删键 / 建子键 */
    SelfCode = DragonSelfProtectRegistry(KeyPath, Operation);
    if (SelfCode != 0) {

        DragonMetricsBump(DrgMetricSelfProtectHits, 1);
        DragonMetricsRecordLast(
            DRG_METRIC_CB_REGISTRY, SelfCode, DRG_ACTION_REPORT, ProcessId, KeyPath);

        DragonQueueViolation(
            SelfCode,
            DRG_ACTION_REPORT,
            ProcessId,
            KeyPath->Buffer,
            KeyPath->Length);

        return STATUS_ACCESS_DENIED;
    }

    DragonMetricsBump(DrgMetricRegistry, 1);

    if (DragonEvaluateRegistry(ProcessId, KeyPath, ValueName, Operation,
                               &RuleCode, &Action) == FALSE) {
        return STATUS_SUCCESS;
    }

    DragonMetricsBump(DrgMetricRulesHit, 1);
    DragonMetricsBump(DrgMetricBlocked, 1);
    DragonMetricsRecordLast(
        DRG_METRIC_CB_REGISTRY, RuleCode, Action, ProcessId, KeyPath);

    DragonQueueViolation(
        RuleCode,
        Action,
        ProcessId,
        KeyPath->Buffer,
        KeyPath->Length);

    return STATUS_ACCESS_DENIED;
}

/*++
@IRQL: <= APC_LEVEL
@brief 处理「创建 / 打开键」类通知。
--*/
static
NTSTATUS
DragonHandlePreOpenOrCreate(
    _In_ PUNICODE_STRING CompleteName,
    _In_opt_ PVOID RootObject,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    UNICODE_STRING FullPath;
    NTSTATUS Status;

    if (DragonIsRegistryWriteAccess(DesiredAccess) == FALSE) {
        return STATUS_SUCCESS;
    }

    if (DragonBuildKeyPath(RootObject, CompleteName, &FullPath) == FALSE) {
        return STATUS_SUCCESS;
    }

    /* 建键 / 打开键属于键级操作，没有值名可用于第二层约束 */
    Status = DragonBlockRegistryOperation(&FullPath, NULL, DRG_OP_CREATE | DRG_OP_WRITE);
    DragonFree(FullPath.Buffer);
    return Status;
}

/*++
@IRQL: <= APC_LEVEL
@brief 由键对象 + 值名拼出「键全路径 + 值名」。

@param  OutPath  成功时 Buffer 由 DragonAllocate 分配，调用方负责 DragonFree。
--*/
static
BOOLEAN
DragonBuildKeyValuePath(
    _In_opt_ PVOID KeyObject,
    _In_opt_ PCUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING OutPath
    )
{
    PCUNICODE_STRING KeyName;
    BOOLEAN KeyNameAcquired;
    ULONG KeyBytes;
    ULONG ValueBytes;
    ULONG TotalBytes;
    PWCHAR Buffer;
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValuePath;
    SIZE_T WorkStringBytes;

    OutPath->Buffer = NULL;
    OutPath->Length = 0;
    OutPath->MaximumLength = 0;

    KeyName = NULL;
    KeyNameAcquired = FALSE;

    if (KeyObject != NULL && g_RegistryCookieValid == TRUE) {
        if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(
                           &g_RegistryCookie,
                           KeyObject,
                           NULL,
                           &KeyName,
                           0)) &&
            KeyName != NULL) {
            KeyNameAcquired = TRUE;
        }
    }

    if (KeyNameAcquired == FALSE || KeyName->Buffer == NULL) {
        if (KeyNameAcquired == TRUE) {
            CmCallbackReleaseKeyObjectIDEx(KeyName);
        }
        return FALSE;
    }

    KeyBytes = KeyName->Length;
    ValueBytes = (ValueName != NULL && ValueName->Buffer != NULL) ? ValueName->Length : 0;

    /* 预留足够空间：键 + '\' + 值名 + NUL */
    TotalBytes = KeyBytes + sizeof(WCHAR) + ValueBytes + sizeof(WCHAR);
    if (TotalBytes > 0xFFFF) {
        CmCallbackReleaseKeyObjectIDEx(KeyName);
        return FALSE;
    }

    Buffer = (PWCHAR)DragonAllocate(TotalBytes);
    if (Buffer == NULL) {
        CmCallbackReleaseKeyObjectIDEx(KeyName);
        return FALSE;
    }

    RtlZeroMemory(Buffer, TotalBytes);

    WorkStringBytes = TotalBytes;

    KeyPath.Buffer = Buffer;
    KeyPath.Length = 0;
    KeyPath.MaximumLength = (USHORT)WorkStringBytes;

    RtlCopyUnicodeString(&KeyPath, KeyName);
    if (KeyPath.Length == 0) {
        CmCallbackReleaseKeyObjectIDEx(KeyName);
        DragonFree(Buffer);
        return FALSE;
    }

    CmCallbackReleaseKeyObjectIDEx(KeyName);

    if (ValueBytes > 0) {

        ValuePath = *ValueName;

        if (KeyPath.Length > 0 &&
            KeyPath.Buffer[(KeyPath.Length / sizeof(WCHAR)) - 1] != L'\\') {
            (VOID)RtlAppendUnicodeToString(&KeyPath, L"\\");
        }

        (VOID)RtlAppendUnicodeStringToString(&KeyPath, &ValuePath);
    }

    OutPath->Buffer = Buffer;
    OutPath->Length = KeyPath.Length;
    OutPath->MaximumLength = (USHORT)TotalBytes;
    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 注册表回调主入口。
--*/
static
NTSTATUS
DragonRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS NotifyClass;
    PREG_CREATE_KEY_INFORMATION OpenInfo;
    PREG_DELETE_KEY_INFORMATION DeleteKeyInfo;
    PREG_SET_VALUE_KEY_INFORMATION SetValueInfo;
    PREG_DELETE_VALUE_KEY_INFORMATION DeleteValueInfo;
    UNICODE_STRING Path;
    UNICODE_STRING KeyPath;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL || Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_SUCCESS;
    }

    NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (NotifyClass) {

        case RegNtPreCreateKey:
        case RegNtPreCreateKeyEx:
        case RegNtPreOpenKey:
        case RegNtPreOpenKeyEx:
            OpenInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
            return DragonHandlePreOpenOrCreate(
                       OpenInfo->CompleteName,
                       OpenInfo->RootObject,
                       OpenInfo->DesiredAccess);

        case RegNtPreDeleteKey:
            DeleteKeyInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (DragonBuildKeyPath(DeleteKeyInfo->Object, NULL, &KeyPath) == FALSE) {
                return STATUS_SUCCESS;
            }
            Status = DragonBlockRegistryOperation(&KeyPath, NULL, DRG_OP_DELETE);
            DragonFree(KeyPath.Buffer);
            return Status;

        case RegNtPreSetValueKey:
            SetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (DragonBuildKeyValuePath(SetValueInfo->Object, SetValueInfo->ValueName, &Path) == FALSE) {
                return STATUS_SUCCESS;
            }
            Status = DragonBlockRegistryOperation(&Path, SetValueInfo->ValueName, DRG_OP_WRITE);
            DragonFree(Path.Buffer);
            return Status;

        case RegNtPreDeleteValueKey:
            DeleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (DragonBuildKeyValuePath(DeleteValueInfo->Object, DeleteValueInfo->ValueName, &Path) == FALSE) {
                return STATUS_SUCCESS;
            }
            Status = DragonBlockRegistryOperation(&Path, DeleteValueInfo->ValueName, DRG_OP_DELETE);
            DragonFree(Path.Buffer);
            return Status;

        default:
            break;
    }

    return STATUS_SUCCESS;
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 注册注册表回调（幂等）。
--*/
NTSTATUS
DragonRegistryGuardStart(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS Status;
    UNICODE_STRING Altitude;

    if (g_RegistryCookieValid == TRUE) {
        return STATUS_SUCCESS;
    }

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&Altitude, DRG_REG_ALTITUDE);

    Status = CmRegisterCallbackEx(
                 DragonRegistryCallback,
                 &Altitude,
                 DriverObject,
                 NULL,
                 &g_RegistryCookie,
                 NULL);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    g_RegistryCookieValid = TRUE;
    g_Dragon.RegistryCallbackRegistered = TRUE;
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 注销注册表回调（幂等）。
--*/
VOID
DragonRegistryGuardStop(
    VOID
    )
{
    NTSTATUS Status;

    if (g_RegistryCookieValid == FALSE) {
        return;
    }

    Status = CmUnRegisterCallback(g_RegistryCookie);
    if (NT_SUCCESS(Status)) {
        g_RegistryCookieValid = FALSE;
        g_RegistryCookie.QuadPart = 0;
        g_Dragon.RegistryCallbackRegistered = FALSE;
    }
}
