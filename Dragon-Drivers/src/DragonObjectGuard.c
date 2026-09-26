/*++
===============================================================================
 Dragon-Drivers / DragonObjectGuard.c

 对象级防护：
   1. ObRegisterCallbacks（PsProcessType / PsThreadType，
      OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE）
      —— 命中规则时**剥离**被拒权限位，而不是整体拒绝句柄创建。
         这是内核对象回调唯一可用的处置方式（返回 OB_PREOP_SUCCESS 并修改
         DesiredAccess），也是杀软驱动的主流做法。
   2. PsSetCreateThreadNotifyRoutine —— 跨进程创建线程时投递内存分析作业。
   3. PsSetLoadImageNotifyRoutine —— 模块加载时评估 Process+ImageLoad 规则。

 权限映射采用「访问掩码 <-> 语义操作位」双向表驱动，避免冗长分支；
 语义位定义位于 DragonProtocol.h，属于对外数据契约。

 安全要点：
   · Info->KernelHandle 为真时直接放行——内核自身发起的句柄操作不是用户行为；
   · 源进程与目标进程相同的自访问直接放行；
   · 全程不缓存 POB_PRE_OPERATION_INFORMATION 或其内部指针。
===============================================================================
--*/

#include "DragonCommon.h"

/*-----------------------------------------------------------------------------
  访问掩码 <-> 语义操作位映射表
-----------------------------------------------------------------------------*/
typedef struct _DRG_ACCESS_MAP {
    ACCESS_MASK Mask;
    ULONG       Operation;
} DRG_ACCESS_MAP;

static const DRG_ACCESS_MAP g_ProcessAccessMap[] = {
    { PROCESS_VM_READ,                                DRG_OP_VM_READ },
    { PROCESS_VM_WRITE,                               DRG_OP_VM_WRITE },
    { PROCESS_VM_OPERATION,                           DRG_OP_VM_OPERATION },
    { PROCESS_CREATE_THREAD,                          DRG_OP_CREATE_THREAD },
    { PROCESS_TERMINATE,                              DRG_OP_TERMINATE },
    { PROCESS_SUSPEND_RESUME,                         DRG_OP_SUSPEND_RESUME },
    { PROCESS_DUP_HANDLE,                             DRG_OP_DUP_HANDLE },
    { PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA,    DRG_OP_SET_INFORMATION },
    { PROCESS_CREATE_PROCESS,                         DRG_OP_CREATE_PROCESS }
};

static const DRG_ACCESS_MAP g_ThreadAccessMap[] = {
    { THREAD_SET_CONTEXT,                             DRG_OP_THREAD_SET_CONTEXT },
    { THREAD_TERMINATE,                               DRG_OP_TERMINATE },
    { THREAD_SUSPEND_RESUME,                          DRG_OP_SUSPEND_RESUME },
    { THREAD_SET_INFORMATION,                         DRG_OP_SET_INFORMATION },
    { THREAD_SET_THREAD_TOKEN,                        DRG_OP_THREAD_SET_TOKEN },
    { THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION, DRG_OP_IMPERSONATE }
};

/*++
@IRQL: <= APC_LEVEL
@brief 访问掩码 -> 语义操作位。
--*/
static
ULONG
DragonAccessToOperations(
    _In_reads_(EntryCount) const DRG_ACCESS_MAP *Map,
    _In_ ULONG EntryCount,
    _In_ ACCESS_MASK Access
    )
{
    ULONG Operations;
    ULONG Index;

    Operations = 0;

    for (Index = 0; Index < EntryCount; Index++) {
        if ((Access & Map[Index].Mask) != 0) {
            Operations |= Map[Index].Operation;
        }
    }

    return Operations;
}

/*++
@IRQL: <= APC_LEVEL
@brief 语义操作位 -> 需要剥离的访问掩码。
--*/
static
ACCESS_MASK
DragonOperationsToAccess(
    _In_reads_(EntryCount) const DRG_ACCESS_MAP *Map,
    _In_ ULONG EntryCount,
    _In_ ULONG Operations
    )
{
    ACCESS_MASK Access;
    ULONG Index;

    Access = 0;

    for (Index = 0; Index < EntryCount; Index++) {
        if ((Operations & Map[Index].Operation) != 0) {
            Access |= Map[Index].Mask;
        }
    }

    return Access;
}

/*++
@IRQL: <= APC_LEVEL
@brief 取出本次操作对应的 DesiredAccess 指针（仅句柄创建 / 句柄复制有）。
--*/
static
PACCESS_MASK
DragonDesiredAccessPointer(
    _In_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE &&
        Info->Parameters != NULL) {
        return &Info->Parameters->CreateHandleInformation.DesiredAccess;
    }

    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE &&
        Info->Parameters != NULL) {
        return &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    return NULL;
}

/*++
@IRQL: <= APC_LEVEL
@brief 句柄操作类型折算为规则语义位。
--*/
static
ULONG
DragonHandleOperationType(
    _In_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        return DRG_HANDLE_CREATE;
    }

    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return DRG_HANDLE_DUPLICATE;
    }

    return 0;
}

/*++
@IRQL: <= APC_LEVEL
@brief 进程/线程对象句柄操作前回调（两个对象类型共用）。

@note  ObRegisterCallbacks 的前回调运行在 PASSIVE_LEVEL，可以安全调用
       DragonEvaluateProcessAccess（内部会解析进程镜像路径）。
--*/
static
OB_PREOP_CALLBACK_STATUS
DragonObjectPreCallback(
    _In_opt_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    PACCESS_MASK DesiredAccess;
    ULONG HandleOperation;
    ACCESS_MASK OriginalAccess;
    ACCESS_MASK DeniedMask;
    ACCESS_MASK EffectiveDenied;
    ACCESS_MASK ClientMask;
    ACCESS_MASK ProtectedAccess;
    HANDLE SourcePid;
    HANDLE TargetPid;
    ULONG ObjectType;
    ULONG RequestedOperations;
    ULONG DeniedOperations;
    ULONG RuleCode;
    ULONG Action;
    OB_PREOP_CALLBACK_STATUS Result;

    UNREFERENCED_PARAMETER(RegistrationContext);

    Result = OB_PREOP_SUCCESS;

    if (Info == NULL) {
        return Result;
    }

    if (g_Dragon.ObjectGuardReady == FALSE) {
        return Result;
    }

    /* 内核句柄创建/复制不属于用户行为，直接放行 */
    if (Info->KernelHandle) {
        return Result;
    }

    DesiredAccess = DragonDesiredAccessPointer(Info);
    HandleOperation = DragonHandleOperationType(Info);

    if (DesiredAccess == NULL || *DesiredAccess == 0 || HandleOperation == 0) {
        return Result;
    }

    SourcePid = PsGetCurrentProcessId();
    if (SourcePid == NULL) {
        return Result;
    }

    TargetPid = NULL;
    ObjectType = 0;
    RequestedOperations = 0;

    if (Info->Object == NULL) {
        return Result;
    }

    if (Info->ObjectType == *PsProcessType) {
        TargetPid = PsGetProcessId((PEPROCESS)Info->Object);
        ObjectType = DRG_OBJECT_PROCESS;
        RequestedOperations = DragonAccessToOperations(
                                  g_ProcessAccessMap,
                                  RTL_NUMBER_OF(g_ProcessAccessMap),
                                  *DesiredAccess);
    }
    else if (Info->ObjectType == *PsThreadType) {
        TargetPid = PsGetThreadProcessId((PETHREAD)Info->Object);
        ObjectType = DRG_OBJECT_THREAD;
        RequestedOperations = DragonAccessToOperations(
                                  g_ThreadAccessMap,
                                  RTL_NUMBER_OF(g_ThreadAccessMap),
                                  *DesiredAccess);
    }
    else {
        return Result;
    }

    if (TargetPid == NULL || SourcePid == TargetPid) {
        return Result;
    }

    /*
     * 内置自保护：已连接的客户端进程（防护驱动自身的用户态组件）不允许被
     * 其它进程取得处置权 —— 这里从其它进程的期望访问掩码中剥掉
     * PROCESS_TERMINATE / PROCESS_SUSPEND_RESUME（进程对象）与
     * THREAD_TERMINATE / THREAD_SUSPEND_RESUME（线程对象），属于防御性收敛：
     * 只削减「别人能对这个进程做什么」，驱动自身不提供任何处置能力。
     *
     * 这一段刻意放在「发起方可信则放行」之前 —— 信任白名单由用户态经端口
     * 写入，若让它先短路，等于给攻击者留了一条「先白名单自己、再杀客户端」
     * 的旁路。自保护不参与任何白名单裁决。
     */
    ClientMask = DragonSelfProtectClientMask((PEPROCESS)Info->Object, ObjectType);

    if (ClientMask != 0) {
        ProtectedAccess = *DesiredAccess & ClientMask;

        if (ProtectedAccess != 0) {
            *DesiredAccess &= ~ProtectedAccess;

            DragonQueueAccessReport(
                DRG_CODE_SELF_CLIENT,
                DRG_ACTION_REPORT,
                SourcePid,
                TargetPid,
                (ObjectType == DRG_OBJECT_PROCESS) ? DRG_MSG_PROC_HANDLE : DRG_MSG_THREAD_HANDLE,
                (ObjectType == DRG_OBJECT_PROCESS)
                    ? (USHORT)(DragonWideLength(DRG_MSG_PROC_HANDLE) * sizeof(WCHAR))
                    : (USHORT)(DragonWideLength(DRG_MSG_THREAD_HANDLE) * sizeof(WCHAR)));
        }
    }

    if (DragonIsProcessTrusted(SourcePid) == TRUE) {
        return Result;
    }

    if (RequestedOperations == 0) {
        return Result;
    }

    DeniedOperations = 0;
    RuleCode = 0;
    Action = DRG_ACTION_REPORT;

    DragonMetricsBump(DrgMetricProcessAccess, 1);

    if (DragonEvaluateProcessAccess(
            SourcePid,
            TargetPid,
            RequestedOperations,
            HandleOperation,
            ObjectType,
            &DeniedOperations,
            &RuleCode,
            &Action) == FALSE) {
        return Result;
    }

    if (ObjectType == DRG_OBJECT_PROCESS) {
        DeniedMask = DragonOperationsToAccess(
                         g_ProcessAccessMap,
                         RTL_NUMBER_OF(g_ProcessAccessMap),
                         DeniedOperations);
    }
    else {
        DeniedMask = DragonOperationsToAccess(
                         g_ThreadAccessMap,
                         RTL_NUMBER_OF(g_ThreadAccessMap),
                         DeniedOperations);
    }

    OriginalAccess = *DesiredAccess;
    EffectiveDenied = OriginalAccess & DeniedMask;

    if (EffectiveDenied == 0) {
        return Result;
    }

    *DesiredAccess = OriginalAccess & ~EffectiveDenied;

    DragonQueueAccessReport(
        RuleCode,
        Action,
        SourcePid,
        TargetPid,
        (ObjectType == DRG_OBJECT_PROCESS) ? DRG_MSG_PROC_HANDLE : DRG_MSG_THREAD_HANDLE,
        (ObjectType == DRG_OBJECT_PROCESS)
            ? (USHORT)(DragonWideLength(DRG_MSG_PROC_HANDLE) * sizeof(WCHAR))
            : (USHORT)(DragonWideLength(DRG_MSG_THREAD_HANDLE) * sizeof(WCHAR)));

    return Result;
}

/*=============================================================================
  线程通知
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL  (官方保证 <= APC_LEVEL)
@brief 线程创建通知：跨进程创建线程时投递内存分析作业。

@note  官方文档明确：创建线程时本回调运行在「创建新线程的那个线程」的上下文中，
       因此 PsGetCurrentProcessId() 就是发起方（注入方）。
--*/
static
VOID
DragonThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    HANDLE SourcePid;

    if (Create == FALSE) {
        return;
    }

    if (g_Dragon.ObjectGuardReady == FALSE) {
        return;
    }

    SourcePid = PsGetCurrentProcessId();
    if (SourcePid == NULL || SourcePid == ProcessId) {
        return;
    }

    if (DragonIsProcessTrusted(SourcePid) == TRUE) {
        return;
    }

    DragonQueueThreadScan(SourcePid, ProcessId, ThreadId);
}

/*=============================================================================
  镜像加载通知
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL  (官方保证 <= APC_LEVEL)
@brief 镜像加载通知：评估 Process 类别 + ImageLoad 操作位规则。
--*/
static
VOID
DragonImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_opt_ HANDLE ProcessId,
    _In_opt_ PIMAGE_INFO ImageInfo
    )
{
    ULONG RuleCode;
    ULONG Action;

    if (g_Dragon.ObjectGuardReady == FALSE) {
        return;
    }

    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo == NULL) {
        return;
    }

    /* 驱动自身与内核模块的加载不属于用户进程行为 */
    if (ImageInfo->SystemModeImage) {
        return;
    }

    if (ProcessId == NULL) {
        return;
    }

    RuleCode = 0;
    Action = DRG_ACTION_REPORT;

    DragonMetricsBump(DrgMetricImageLoad, 1);

    if (DragonEvaluateImageLoad(ProcessId, FullImageName, ImageInfo, &RuleCode, &Action) == FALSE) {
        return;
    }

    /* 上报 + 按 Action 处置（Report / Terminate 走同一条通路） */
    DragonQueueViolation(RuleCode, Action, ProcessId, FullImageName->Buffer, FullImageName->Length);
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 注册对象回调、线程通知与镜像通知（幂等）。

        任一步失败都会回滚已完成的注册，保证不留半初始化状态。
--*/
NTSTATUS
DragonObjectGuardStart(
    VOID
    )
{
    NTSTATUS Status;
    OB_OPERATION_REGISTRATION OperationRegistration[2];
    OB_CALLBACK_REGISTRATION CallbackRegistration;

    if (g_Dragon.ObjectGuardReady == TRUE) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(OperationRegistration, sizeof(OperationRegistration));
    RtlZeroMemory(&CallbackRegistration, sizeof(CallbackRegistration));

    OperationRegistration[0].ObjectType = PsProcessType;
    OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[0].PreOperation = DragonObjectPreCallback;
    OperationRegistration[0].PostOperation = NULL;

    OperationRegistration[1].ObjectType = PsThreadType;
    OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[1].PreOperation = DragonObjectPreCallback;
    OperationRegistration[1].PostOperation = NULL;

    CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CallbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(OperationRegistration);
    CallbackRegistration.OperationRegistration = OperationRegistration;
    CallbackRegistration.RegistrationContext = NULL;
    RtlInitUnicodeString(&CallbackRegistration.Altitude, DRG_OB_ALTITUDE);

    Status = ObRegisterCallbacks(&CallbackRegistration, &g_Dragon.ObRegistrationHandle);
    if (!NT_SUCCESS(Status)) {
        g_Dragon.ObRegistrationHandle = NULL;
        return Status;
    }

    Status = PsSetCreateThreadNotifyRoutine(DragonThreadNotify);
    if (!NT_SUCCESS(Status)) {
        ObUnRegisterCallbacks(g_Dragon.ObRegistrationHandle);
        g_Dragon.ObRegistrationHandle = NULL;
        return Status;
    }
    g_Dragon.ThreadNotifyRegistered = TRUE;

    Status = PsSetLoadImageNotifyRoutine(DragonImageNotify);
    if (!NT_SUCCESS(Status)) {
        (VOID)PsRemoveCreateThreadNotifyRoutine(DragonThreadNotify);
        g_Dragon.ThreadNotifyRegistered = FALSE;
        ObUnRegisterCallbacks(g_Dragon.ObRegistrationHandle);
        g_Dragon.ObRegistrationHandle = NULL;
        return Status;
    }
    g_Dragon.ImageNotifyRegistered = TRUE;

    g_Dragon.ObjectGuardReady = TRUE;
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 注销对象回调、线程通知与镜像通知（幂等）。
--*/
VOID
DragonObjectGuardStop(
    VOID
    )
{
    NTSTATUS Status;

    /* 先关闭评估开关，避免注销过程中仍有新作业进入 */
    g_Dragon.ObjectGuardReady = FALSE;

    if (g_Dragon.ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_Dragon.ObRegistrationHandle);
        g_Dragon.ObRegistrationHandle = NULL;
    }

    if (g_Dragon.ThreadNotifyRegistered == TRUE) {
        Status = PsRemoveCreateThreadNotifyRoutine(DragonThreadNotify);
        if (NT_SUCCESS(Status) || Status == STATUS_PROCEDURE_NOT_FOUND) {
            g_Dragon.ThreadNotifyRegistered = FALSE;
        }
    }

    if (g_Dragon.ImageNotifyRegistered == TRUE) {
        Status = PsRemoveLoadImageNotifyRoutine(DragonImageNotify);
        if (NT_SUCCESS(Status) || Status == STATUS_PROCEDURE_NOT_FOUND) {
            g_Dragon.ImageNotifyRegistered = FALSE;
        }
    }
}
