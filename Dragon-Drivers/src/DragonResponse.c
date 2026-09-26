/*++
===============================================================================
 Dragon-Drivers / DragonResponse.c

 处置层：作业队列 + 事件上报 + 进程终止 + 跨进程线程内存分析。

 设计要点（对应规范「IOCTL安全规范 / WDF对象生命周期规范」）：
   · 所有内核回调路径都**不**直接做重活：只分配作业节点、入队、唤醒工作项。
   · 唯一的重活执行者是 WDF 工作项（EvtWorkItem），官方保证运行在
     PASSIVE_LEVEL，因此里面可以安全调用 SeLocateProcessImageName /
     ZwTerminateProcess / KeStackAttachProcess / FltSendMessage。
   · 不使用 PsCreateSystemThread —— 不创建任何长期驻留线程。
   · 工作项对象以控制设备对象为父，卸载前先 WdfWorkItemFlush 再 WdfObjectDelete，
     不存在「工作项仍在跑而对象已销毁」的窗口。

 作业节点里的 PEPROCESS 引用规则：
   · 只有线程分析作业在投递瞬间持有 SourceProcess/TargetProcess 的引用，
     并在作业释放时统一 ObDereferenceObject；
   · 其余作业只保存 PID + 创建时间，执行时重新解析，彻底规避悬挂指针。
===============================================================================
--*/

#include "DragonCommon.h"

/*-----------------------------------------------------------------------------
  线程信息查询
  THREADINFOCLASS 及其取值 ThreadQuerySetWin32StartAddress(=9) 由官方 WDK
  头文件 ntddk.h 提供；但 WDK 未随附 ZwQueryInformationThread 的内核态原型
  （ntifs.h 中没有该声明），这里按官方参数表显式声明，符号从 NtosKrnl 导入。
  参考：NtQueryInformationThread / THREADINFOCLASS 官方文档。
-----------------------------------------------------------------------------*/
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/*-----------------------------------------------------------------------------
  被终止保护名单
-----------------------------------------------------------------------------*/
static const PCWSTR g_CriticalImageNames[] = {
    L"csrss.exe",
    L"smss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"services.exe",
    L"lsass.exe",
    L"svchost.exe",
    L"fontdrvhost.exe",
    L"conhost.exe"
};

/*=============================================================================
  作业队列
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 分配一个作业节点；PathBytes 为 0 时不附带路径数据。
--*/
static
PDRG_JOB
DragonJobAllocate(
    _In_ ULONG Kind,
    _In_ USHORT PathBytes
    )
{
    PDRG_JOB Job;
    SIZE_T Total;

    Total = DRG_JOB_HEADER_SIZE + (SIZE_T)PathBytes + sizeof(WCHAR);

    Job = (PDRG_JOB)DragonAllocate(Total);
    if (Job == NULL) {
        return NULL;
    }

    Job->Kind = Kind;
    Job->PathBytes = PathBytes;
    return Job;
}

/*++
@IRQL: <= APC_LEVEL
@brief 释放作业节点，并归还其中持有的进程引用。
--*/
static
VOID
DragonJobRelease(
    _In_ PDRG_JOB Job
    )
{
    if (Job == NULL) {
        return;
    }

    if (Job->TargetProcess != NULL) {
        ObDereferenceObject(Job->TargetProcess);
        Job->TargetProcess = NULL;
    }

    if (Job->SourceProcess != NULL) {
        ObDereferenceObject(Job->SourceProcess);
        Job->SourceProcess = NULL;
    }

    DragonFree(Job);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 从队列头部摘取一个作业。
--*/
static
PDRG_JOB
DragonJobPop(
    VOID
    )
{
    PDRG_JOB Job;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    Job = NULL;

    KeAcquireSpinLock(&g_Dragon.JobLock, &OldIrql);
    if (IsListEmpty(&g_Dragon.JobQueue) == FALSE) {
        Entry = RemoveHeadList(&g_Dragon.JobQueue);
        Job = CONTAINING_RECORD(Entry, DRG_JOB, Link);
        InitializeListHead(&Job->Link);
    }
    KeReleaseSpinLock(&g_Dragon.JobLock, OldIrql);

    return Job;
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 队列中是否仍有作业。
--*/
static
BOOLEAN
DragonJobPending(
    VOID
    )
{
    BOOLEAN Pending;
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_Dragon.JobLock, &OldIrql);
    Pending = (IsListEmpty(&g_Dragon.JobQueue) == FALSE) ? TRUE : FALSE;
    KeReleaseSpinLock(&g_Dragon.JobLock, OldIrql);

    return Pending;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 丢弃队列中的全部作业。
--*/
static
VOID
DragonJobPurge(
    VOID
    )
{
    PDRG_JOB Job;

    for (;;) {
        Job = DragonJobPop();
        if (Job == NULL) {
            break;
        }

        InterlockedDecrement(&g_Dragon.JobCount);
        DragonJobRelease(Job);
    }
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 作业入队，并确保排空工作项已排队。

@return TRUE 表示已成功入队。
--*/
static
BOOLEAN
DragonJobEnqueue(
    _In_ PDRG_JOB Job
    )
{
    LONG Count;
    KIRQL OldIrql;
    BOOLEAN Accepted;
    BOOLEAN Enqueued;

    if (Job == NULL) {
        return FALSE;
    }

    if (g_Dragon.DrainWorkItem == NULL) {
        return FALSE;
    }

    /*
     * 进入「在途入队」临界区。卸载流程会等待该计数归零后才销毁工作项对象，
     * 因此不会出现「工作项已删除但仍被 Enqueue」的窗口。
     */
    InterlockedIncrement(&g_Dragon.EnqueueActive);

    if (InterlockedCompareExchange(&g_Dragon.Shutdown, 0, 0) != 0) {
        InterlockedDecrement(&g_Dragon.EnqueueActive);
        return FALSE;
    }

    Count = InterlockedIncrement(&g_Dragon.JobCount);
    if (Count > (LONG)DRG_MAX_PENDING_JOBS) {
        InterlockedDecrement(&g_Dragon.JobCount);
        InterlockedIncrement64(&g_Dragon.EventsDropped);
        InterlockedDecrement(&g_Dragon.EnqueueActive);
        return FALSE;
    }

    Accepted = FALSE;

    KeAcquireSpinLock(&g_Dragon.JobLock, &OldIrql);
    if (InterlockedCompareExchange(&g_Dragon.Shutdown, 0, 0) == 0) {
        InsertTailList(&g_Dragon.JobQueue, &Job->Link);
        Accepted = TRUE;
    }
    KeReleaseSpinLock(&g_Dragon.JobLock, OldIrql);

    if (Accepted == FALSE) {
        InterlockedDecrement(&g_Dragon.JobCount);
        InterlockedDecrement(&g_Dragon.EnqueueActive);
        return FALSE;
    }

    /* 只允许一个排空工作项在途；已经排过队就不再重复入队 */
    Enqueued = FALSE;
    if (InterlockedCompareExchange(&g_Dragon.DrainScheduled, 1, 0) == 0) {
        WdfWorkItemEnqueue(g_Dragon.DrainWorkItem);
        Enqueued = TRUE;
    }

    UNREFERENCED_PARAMETER(Enqueued);
    InterlockedDecrement(&g_Dragon.EnqueueActive);
    return TRUE;
}

/*=============================================================================
  事件上报
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 通过过滤管理器通信端口向用户态投递一条事件。

        输入侧保证：
          · 仅当端口处于可接受状态且客户端已连接时发送；
          · 上报缓冲为内核态复制体，用户态不参与缓冲区构造；
          · FltSendMessage 的 ClientPort 出参由 Filter Manager 维护，
            全程处于 rundown 保护之下，避免与断开流程竞争。

@param  Action  DRG_ACTION_*：本条事件对应的处置动作，供用户态审计与呈现。
--*/
NTSTATUS
DragonSendEvent(
    _In_ ULONG Code,
    _In_ ULONG Action,
    _In_ HANDLE ProcessId,
    _In_opt_ PCWSTR Path,
    _In_ USHORT PathBytes
    )
{
    NTSTATUS Status;
    PDRG_EVENT Event;
    LARGE_INTEGER Timeout;
    LONG State;
    PFLT_PORT PortSnapshot;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    State = DragonStateGet();
    if (State != (LONG)DrgStateRunning && State != (LONG)DrgStateRetry) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (InterlockedCompareExchange(&g_Dragon.PortAccepting, 0, 0) == 0) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (ExAcquireRundownProtection(&g_Dragon.PortRundown) == FALSE) {
        return STATUS_PORT_DISCONNECTED;
    }

    Status = STATUS_PORT_DISCONNECTED;

    if (g_Dragon.ClientPort != NULL && g_Dragon.FilterHandle != NULL) {

        Event = (PDRG_EVENT)DragonAllocate(sizeof(DRG_EVENT));
        if (Event == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            InterlockedIncrement64(&g_Dragon.EventsDropped);
        }
        else {
            Event->MessageCode = Code;
            Event->Action = Action;
            Event->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
            (VOID)DragonCopyPath(Event->Path, DRG_PATH_CHARS, Path, PathBytes);

            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                Timeout.QuadPart = DRG_EVENT_TIMEOUT_100NS;
            }
            else {
                Timeout.QuadPart = 0;
            }

            /*
             * 关键：把客户端端口句柄先复制到局部变量，再把局部变量的地址交给
             * FltSendMessage。
             *
             * 官方文档把 ClientPort 标注为 [in]（只读语义），并未承诺失败时会回写
             * NULL；但该参数类型是 PFLT_PORT*，历史上确有实现会清空该位置。若直接
             * 传 &g_Dragon.ClientPort：
             *   · 设备上下文里的句柄可能被第三方行为改写为 NULL；
             *   · 卸载时 DragonCommsClose 就会拿不到句柄去 FltCloseClientPort，
             *     客户端端口句柄泄漏，FltUnregisterFilter 进而无法干净完成。
             * 传局部副本后，无论 FltMgr 是否回写，我方记录的句柄始终完整，
             * 而且副本被清零时我们还能据此判定客户端已死、主动收敛状态。
             */
            PortSnapshot = g_Dragon.ClientPort;

            Status = FltSendMessage(
                         g_Dragon.FilterHandle,
                         &PortSnapshot,
                         Event,
                         sizeof(DRG_EVENT),
                         NULL,
                         NULL,
                         &Timeout);

            if (PortSnapshot == NULL) {
                /*
                 * 客户端已断开：清掉我方记录，避免后续继续对死端口发消息。
                 * 真正的句柄关闭由 DragonPortDisconnect 完成（Filter Manager
                 * 会调用它），这里只做状态收敛。
                 * 连接锁在本路径上必然已创建（端口存在即证明创建顺序已走到锁之后），
                 * 但仍按规范对 WDF 句柄判空后再使用。
                 */
                if (g_Dragon.ConnectionLock != NULL) {
                    WdfSpinLockAcquire(g_Dragon.ConnectionLock);
                    g_Dragon.ClientPort = NULL;
                    InterlockedExchange(&g_Dragon.ClientPid, 0);
                    WdfSpinLockRelease(g_Dragon.ConnectionLock);
                }
            }

            if (NT_SUCCESS(Status)) {
                InterlockedIncrement64(&g_Dragon.EventsReported);
            }
            else {
                InterlockedIncrement64(&g_Dragon.EventsDropped);
            }

            DragonFree(Event);
        }
    }

    ExReleaseRundownProtection(&g_Dragon.PortRundown);
    return Status;
}

/*=============================================================================
  投递接口（供各防护模块调用，IRQL 上限 APC_LEVEL）
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 投递「仅上报」作业。
--*/
VOID
DragonQueueReport(
    _In_ ULONG Code,
    _In_ HANDLE ProcessId,
    _In_opt_ PCWSTR Path,
    _In_ USHORT PathBytes
    )
{
    PDRG_JOB Job;
    USHORT LimitBytes;

    LimitBytes = (PathBytes > (USHORT)((DRG_PATH_CHARS - 1) * sizeof(WCHAR)))
                     ? (USHORT)((DRG_PATH_CHARS - 1) * sizeof(WCHAR))
                     : PathBytes;

    Job = DragonJobAllocate((ULONG)DrgJobReport, LimitBytes);
    if (Job == NULL) {
        return;
    }

    Job->RuleCode = Code;
    Job->SourcePid = ProcessId;

    /*
     * 作业节点的 Path 是变长区，实际容量为 (LimitBytes + sizeof(WCHAR)) 字节。
     * 这里必须把「真实容量（以 WCHAR 计，含结尾 NUL）」传给复制函数，
     * 不能图省事传 DRG_PATH_CHARS —— 否则一旦 SourceBytes 的裁剪逻辑被改动，
     * 就会写出缓冲区边界（非分页池溢出 = 直接蓝屏）。
     */
    if (LimitBytes > 0 && Path != NULL) {
        (VOID)DragonCopyPath(
                  Job->Path,
                  (LimitBytes / sizeof(WCHAR)) + 1,
                  Path,
                  LimitBytes);
    }

    if (DragonJobEnqueue(Job) == FALSE) {
        DragonJobRelease(Job);
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 投递「终止进程」作业；Pid <= 4 直接忽略。
--*/
VOID
DragonQueueTerminate(
    _In_ HANDLE ProcessId
    )
{
    PDRG_JOB Job;
    PEPROCESS Process;
    NTSTATUS Status;

    if (ProcessId == NULL || (ULONG_PTR)ProcessId <= 4) {
        return;
    }

    Job = DragonJobAllocate((ULONG)DrgJobTerminate, 0);
    if (Job == NULL) {
        return;
    }

    Job->TargetPid = ProcessId;

    /* 记录投递瞬间的进程身份，执行时比对，避免 PID 复用误杀 */
    Process = NULL;
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(Status) && Process != NULL) {
        Job->TargetCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
        ObDereferenceObject(Process);
    }

    if (DragonJobEnqueue(Job) == FALSE) {
        DragonJobRelease(Job);
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 投递「跨进程线程分析」作业。

@note  SourceProcess / TargetProcess 持有引用，由作业释放时统一归还；
      解析失败时退化为只按 PID 处理。
--*/
VOID
DragonQueueThreadScan(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE ThreadId
    )
{
    PDRG_JOB Job;
    PEPROCESS SourceProcess;
    PEPROCESS TargetProcess;
    NTSTATUS Status;

    if (SourcePid == NULL || TargetPid == NULL || ThreadId == NULL) {
        return;
    }

    Job = DragonJobAllocate((ULONG)DrgJobThreadScan, 0);
    if (Job == NULL) {
        return;
    }

    Job->SourcePid = SourcePid;
    Job->TargetPid = TargetPid;
    Job->ThreadId = ThreadId;

    SourceProcess = PsGetCurrentProcess();
    if (SourceProcess != NULL) {
        ObReferenceObject(SourceProcess);
        Job->SourceProcess = SourceProcess;
    }

    TargetProcess = NULL;
    Status = PsLookupProcessByProcessId(TargetPid, &TargetProcess);
    if (NT_SUCCESS(Status) && TargetProcess != NULL) {
        Job->TargetProcess = TargetProcess;
        Job->TargetCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(TargetProcess);
    }

    if (Job->SourceProcess == NULL) {
        DragonJobRelease(Job);
        return;
    }

    if (DragonJobEnqueue(Job) == FALSE) {
        DragonJobRelease(Job);
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 投递「句柄访问降权」上报作业。

        目标进程镜像路径在作业执行阶段解析（PASSIVE_LEVEL），
        Fallback 为解析失败时使用的占位文本，随作业一起复制入队。
--*/
VOID
DragonQueueAccessReport(
    _In_ ULONG Code,
    _In_ ULONG Action,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_opt_ PCWSTR Fallback,
    _In_ USHORT FallbackBytes
    )
{
    PDRG_JOB Job;
    USHORT LimitBytes;

    if (SourcePid == NULL || TargetPid == NULL) {
        return;
    }

    LimitBytes = (FallbackBytes > (USHORT)((DRG_PATH_CHARS - 1) * sizeof(WCHAR)))
                     ? (USHORT)((DRG_PATH_CHARS - 1) * sizeof(WCHAR))
                     : FallbackBytes;

    Job = DragonJobAllocate((ULONG)DrgJobAccessReport, LimitBytes);
    if (Job == NULL) {
        return;
    }

    Job->RuleCode = Code;
    Job->Action = Action;
    Job->SourcePid = SourcePid;
    Job->TargetPid = TargetPid;

    if (LimitBytes > 0 && Fallback != NULL) {
        /* 同 DragonQueueReport：容量必须用作业节点的真实变长区大小 */
        (VOID)DragonCopyPath(
                  Job->Path,
                  (LimitBytes / sizeof(WCHAR)) + 1,
                  Fallback,
                  LimitBytes);
    }

    if (DragonJobEnqueue(Job) == FALSE) {
        DragonJobRelease(Job);
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 组合投递：先上报事件，再按 Action 处置。

        调用方通常是拦截型回调，需要「上报 + 处置」同时发生时使用。
--*/
VOID
DragonQueueViolation(
    _In_ ULONG Code,
    _In_ ULONG Action,
    _In_ HANDLE ActorPid,
    _In_opt_ PCWSTR Path,
    _In_ USHORT PathBytes
    )
{
    DragonQueueReport(Code, ActorPid, Path, PathBytes);

    if (Action == DRG_ACTION_TERMINATE) {
        DragonQueueTerminate(ActorPid);
    }
}

/*=============================================================================
  作业执行：进程终止
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 判断目标进程是否属于「不允许终止」的保护集合。

        保护对象：
          · 空指针 / 系统进程对象；
          · 已连接的客户端进程（自我保护）；
          · 位于 System32 之下的关键系统进程；
          · 任何无法解析镜像路径的进程（保守处理）。
--*/
static
BOOLEAN
DragonIsProtectedProcess(
    _In_opt_ PEPROCESS Process
    )
{
    PUNICODE_STRING ImagePath;
    NTSTATUS Status;
    ULONG Chars;
    LONG LastSeparator;
    LONG ParentSeparator;
    LONG Index;
    ULONG NameIndex;
    BOOLEAN Protected;
    UNICODE_STRING DirectoryName;
    UNICODE_STRING FileName;
    static const UNICODE_STRING System32Name = RTL_CONSTANT_STRING(L"System32");

    if (Process == NULL || Process == PsInitialSystemProcess) {
        return TRUE;
    }

    if ((ULONG)(ULONG_PTR)PsGetProcessId(Process) ==
        (ULONG)InterlockedCompareExchange(&g_Dragon.ClientPid, 0, 0) &&
        (ULONG)(ULONG_PTR)PsGetProcessId(Process) != 0) {
        return TRUE;
    }

    if (DragonAtPassiveLevel() == FALSE) {
        return TRUE;
    }

    ImagePath = NULL;
    Status = SeLocateProcessImageName(Process, &ImagePath);
    if (!NT_SUCCESS(Status) || ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0) {
        if (ImagePath != NULL) {
            ExFreePool(ImagePath);
        }
        return TRUE;
    }

    Chars = ImagePath->Length / sizeof(WCHAR);
    LastSeparator = -1;
    ParentSeparator = -1;

    for (Index = (LONG)Chars - 1; Index >= 0; Index--) {
        if (ImagePath->Buffer[Index] != L'\\') {
            continue;
        }

        if (LastSeparator < 0) {
            LastSeparator = Index;
        }
        else {
            ParentSeparator = Index;
            break;
        }
    }

    Protected = TRUE;

    if (LastSeparator > 0 && ParentSeparator >= 0 && (ULONG)(LastSeparator + 1) < Chars) {

        DirectoryName.Length = (USHORT)((LastSeparator - ParentSeparator - 1) * sizeof(WCHAR));
        DirectoryName.MaximumLength = DirectoryName.Length;
        DirectoryName.Buffer = ImagePath->Buffer + ParentSeparator + 1;

        FileName.Length = (USHORT)((Chars - LastSeparator - 1) * sizeof(WCHAR));
        FileName.MaximumLength = FileName.Length;
        FileName.Buffer = ImagePath->Buffer + LastSeparator + 1;

        if (RtlEqualUnicodeString(&DirectoryName, &System32Name, TRUE) == FALSE) {
            Protected = FALSE;
        }
        else {
            Protected = FALSE;
            for (NameIndex = 0; NameIndex < RTL_NUMBER_OF(g_CriticalImageNames); NameIndex++) {
                UNICODE_STRING CriticalName;

                RtlInitUnicodeString(&CriticalName, g_CriticalImageNames[NameIndex]);
                if (RtlEqualUnicodeString(&FileName, &CriticalName, TRUE) == TRUE) {
                    Protected = TRUE;
                    break;
                }
            }
        }
    }

    ExFreePool(ImagePath);
    return Protected;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 终止目标进程（带身份校验与保护名单校验）。
--*/
static
VOID
DragonExecuteTermination(
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER ExpectedCreateTime
    )
{
    PEPROCESS Process;
    NTSTATUS Status;
    HANDLE ProcessHandle;

    if (ProcessId == NULL || (ULONG_PTR)ProcessId <= 4) {
        return;
    }

    /*
     * ZwTerminateProcess / ObOpenObjectByPointer 的官方 IRQL 约束是 PASSIVE_LEVEL。
     * 本函数只可能由 WDF 工作项（框架保证 PASSIVE_LEVEL）调用到这里，
     * 显式断言是为了把该前提固化，防止将来被挪到更高 IRQL 的上下文而直接蓝屏。
     */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    Process = NULL;
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status) || Process == NULL) {
        return;
    }

    if (ExpectedCreateTime.QuadPart != 0 &&
        PsGetProcessCreateTimeQuadPart(Process) != ExpectedCreateTime.QuadPart) {
        ObDereferenceObject(Process);
        return;
    }

    if (DragonIsProtectedProcess(Process) == TRUE) {
        ObDereferenceObject(Process);
        return;
    }

    ProcessHandle = NULL;
    Status = ObOpenObjectByPointer(
                 Process,
                 OBJ_KERNEL_HANDLE,
                 NULL,
                 PROCESS_TERMINATE,
                 *PsProcessType,
                 KernelMode,
                 &ProcessHandle);

    if (NT_SUCCESS(Status) && ProcessHandle != NULL) {
        (VOID)ZwTerminateProcess(ProcessHandle, STATUS_ACCESS_DENIED);
        ZwClose(ProcessHandle);
    }

    ObDereferenceObject(Process);
}

/*=============================================================================
  作业执行：跨进程线程分析
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 判断保护属性是否含可执行位。
--*/
static
BOOLEAN
DragonIsExecutableProtection(
    _In_ ULONG Protect
    )
{
    ULONG Base;

    Base = Protect & 0xFFu;

    return (Base == PAGE_EXECUTE ||
            Base == PAGE_EXECUTE_READ ||
            Base == PAGE_EXECUTE_READWRITE ||
            Base == PAGE_EXECUTE_WRITECOPY) ? TRUE : FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 判断保护属性是否可写且可执行。
--*/
static
BOOLEAN
DragonIsWritableExecutableProtection(
    _In_ ULONG Protect
    )
{
    ULONG Base;

    Base = Protect & 0xFFu;

    return (Base == PAGE_EXECUTE_READWRITE ||
            Base == PAGE_EXECUTE_WRITECOPY) ? TRUE : FALSE;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 在目标进程上下文中查询地址所在内存区域并折算为规则语义位。

@return TRUE 表示地址位于已提交且可执行的内存区域。
--*/
static
BOOLEAN
DragonQueryThreadRegion(
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID Address,
    _Out_ PULONG OutMemoryType,
    _Out_ PULONG OutProtection,
    _Out_ PSIZE_T OutRegionSize
    )
{
    KAPC_STATE ApcState;
    MEMORY_BASIC_INFORMATION MemoryInformation;
    SIZE_T ReturnLength;
    NTSTATUS Status;
    ULONG MemoryType;
    ULONG Protection;

    *OutMemoryType = 0;
    *OutProtection = 0;
    *OutRegionSize = 0;

    if (TargetProcess == NULL || Address == NULL) {
        return FALSE;
    }

    /*
     * KeStackAttachProcess 与 ZwQueryVirtualMemory 都要求 PASSIVE_LEVEL。
     * 本函数只由工作项路径调用，这里做显式断言以防未来被误用在更高 IRQL 上。
     */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    RtlZeroMemory(&MemoryInformation, sizeof(MemoryInformation));
    ReturnLength = 0;

    /*
     * 绝不能对「当前进程」调用 KeStackAttachProcess：
     *   该例程要求目标进程与当前进程不同，对当前进程 attach 属于未定义用法，
     *   会破坏 APC 状态链并导致蓝屏（工作项运行在 System 进程上下文，
     *   如果目标进程恰好是 System 就会命中这条路径）。
     * 因此先判断是否已在目标上下文，是则直接查询。
     */
    if (TargetProcess == PsGetCurrentProcess()) {

        Status = ZwQueryVirtualMemory(
                     ZwCurrentProcess(),
                     Address,
                     MemoryBasicInformation,
                     &MemoryInformation,
                     sizeof(MemoryInformation),
                     &ReturnLength);
    }
    else {
        KeStackAttachProcess(TargetProcess, &ApcState);

        Status = ZwQueryVirtualMemory(
                     ZwCurrentProcess(),
                     Address,
                     MemoryBasicInformation,
                     &MemoryInformation,
                     sizeof(MemoryInformation),
                     &ReturnLength);

        KeUnstackDetachProcess(&ApcState);
    }

    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    if (MemoryInformation.State != MEM_COMMIT) {
        return FALSE;
    }

    if (DragonIsExecutableProtection(MemoryInformation.Protect) == FALSE) {
        return FALSE;
    }

    if (MemoryInformation.Type == MEM_PRIVATE) {
        MemoryType = DRG_MEMORY_PRIVATE;
    }
    else if (MemoryInformation.Type == MEM_MAPPED) {
        MemoryType = DRG_MEMORY_MAPPED;
    }
    else if (MemoryInformation.Type == DRG_MEM_IMAGE_TYPE) {
        MemoryType = DRG_MEMORY_IMAGE;
    }
    else {
        return FALSE;
    }

    Protection = DRG_PROTECT_EXECUTE;
    if (DragonIsWritableExecutableProtection(MemoryInformation.Protect) == TRUE) {
        Protection |= DRG_PROTECT_EXECUTE_WRITE;
    }

    *OutMemoryType = MemoryType;
    *OutProtection = Protection;
    *OutRegionSize = MemoryInformation.RegionSize;
    return TRUE;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 解析跨进程新建线程的 Win32 起始地址。
--*/
static
NTSTATUS
DragonQueryThreadStartAddress(
    _In_ HANDLE ThreadId,
    _Out_ PVOID *OutStartAddress
    )
{
    PETHREAD Thread;
    NTSTATUS Status;
    HANDLE ThreadHandle;
    PVOID StartAddress;
    ULONG ReturnLength;

    *OutStartAddress = NULL;

    /* PsLookupThreadByThreadId / ObOpenObjectByPointer 要求 <= APC_LEVEL */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Thread = NULL;
    Status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(Status) || Thread == NULL) {
        return (NT_SUCCESS(Status) ? STATUS_NOT_FOUND : Status);
    }

    ThreadHandle = NULL;
    Status = ObOpenObjectByPointer(
                 Thread,
                 OBJ_KERNEL_HANDLE,
                 NULL,
                 THREAD_QUERY_INFORMATION,
                 *PsThreadType,
                 KernelMode,
                 &ThreadHandle);

    ObDereferenceObject(Thread);

    if (!NT_SUCCESS(Status) || ThreadHandle == NULL) {
        return Status;
    }

    StartAddress = NULL;
    ReturnLength = 0;

    Status = ZwQueryInformationThread(
                 ThreadHandle,
                 ThreadQuerySetWin32StartAddress,
                 &StartAddress,
                 sizeof(StartAddress),
                 &ReturnLength);

    ZwClose(ThreadHandle);

    if (!NT_SUCCESS(Status) || StartAddress == NULL) {
        return (NT_SUCCESS(Status) ? STATUS_NOT_FOUND : Status);
    }

    *OutStartAddress = StartAddress;
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 执行跨进程线程分析作业。
--*/
static
VOID
DragonExecuteThreadScan(
    _In_ PDRG_JOB Job
    )
{
    PEPROCESS TargetProcess;
    NTSTATUS Status;
    PVOID StartAddress;
    ULONG MemoryType;
    ULONG Protection;
    SIZE_T RegionSize;
    ULONG RuleCode;
    ULONG Action;
    PUNICODE_STRING TargetPath;
    WCHAR Fallback[64];

    if (Job->TargetPid == NULL || Job->ThreadId == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&g_Dragon.Shutdown, 0, 0) != 0) {
        return;
    }

    /* 目标进程身份校验：优先使用投递时持有的引用，退化时按 PID 重新解析 */
    TargetProcess = Job->TargetProcess;
    if (TargetProcess != NULL) {
        if (Job->TargetCreateTime.QuadPart != 0 &&
            PsGetProcessCreateTimeQuadPart(TargetProcess) != Job->TargetCreateTime.QuadPart) {
            return;
        }
    }
    else {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(Job->TargetPid, &TargetProcess)) || TargetProcess == NULL) {
            return;
        }

        Status = STATUS_SUCCESS;
        if (Job->TargetCreateTime.QuadPart != 0 &&
            PsGetProcessCreateTimeQuadPart(TargetProcess) != Job->TargetCreateTime.QuadPart) {
            ObDereferenceObject(TargetProcess);
            return;
        }
    }

    StartAddress = NULL;
    Status = DragonQueryThreadStartAddress(Job->ThreadId, &StartAddress);
    if (!NT_SUCCESS(Status) || StartAddress == NULL) {
        goto Exit;
    }

    if (DragonQueryThreadRegion(TargetProcess, StartAddress, &MemoryType, &Protection, &RegionSize) == FALSE) {
        goto Exit;
    }

    if (InterlockedCompareExchange(&g_Dragon.Shutdown, 0, 0) != 0) {
        goto Exit;
    }

    RuleCode = 0;
    Action = DRG_ACTION_REPORT;

    if (DragonEvaluateThread(
            Job->SourcePid,
            Job->TargetPid,
            MemoryType,
            Protection,
            RegionSize,
            &RuleCode,
            &Action) == FALSE) {
        goto Exit;
    }

    Job->RuleCode = RuleCode;
    Job->Action = Action;

    RtlZeroMemory(Fallback, sizeof(Fallback));
    (VOID)RtlStringCchCopyW(Fallback, RTL_NUMBER_OF(Fallback), DRG_MSG_REMOTE_THREAD);

    TargetPath = NULL;
    if (DragonAtPassiveLevel() == TRUE &&
        NT_SUCCESS(SeLocateProcessImageName(TargetProcess, &TargetPath)) &&
        TargetPath != NULL &&
        TargetPath->Buffer != NULL) {

        (VOID)DragonSendEvent(
                  RuleCode,
                  Action,
                  Job->SourcePid,
                  TargetPath->Buffer,
                  TargetPath->Length);

        ExFreePool(TargetPath);
    }
    else {
        (VOID)DragonSendEvent(
                  RuleCode,
                  Action,
                  Job->SourcePid,
                  Fallback,
                  (USHORT)(DragonWideLength(Fallback) * sizeof(WCHAR)));
    }

    if (Action == DRG_ACTION_TERMINATE) {
        DragonQueueTerminate(Job->SourcePid);
    }

Exit:
    if (Job->TargetProcess == NULL && TargetProcess != NULL) {
        ObDereferenceObject(TargetProcess);
    }
}

/*=============================================================================
  工作项
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 执行句柄访问降权上报作业：优先上报目标进程镜像路径，
       解析失败时退化为作业内携带的占位文本。
--*/
static
VOID
DragonExecuteAccessReport(
    _In_ PDRG_JOB Job
    )
{
    PEPROCESS TargetProcess;
    PUNICODE_STRING TargetPath;
    NTSTATUS Status;
    BOOLEAN Reported;

    if (Job->TargetPid == NULL) {
        return;
    }

    /* SeLocateProcessImageName 要求 PASSIVE_LEVEL；同样做显式断言 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    Reported = FALSE;
    TargetProcess = NULL;

    Status = PsLookupProcessByProcessId(Job->TargetPid, &TargetProcess);
    if (NT_SUCCESS(Status) && TargetProcess != NULL) {

        TargetPath = NULL;
        Status = SeLocateProcessImageName(TargetProcess, &TargetPath);
        if (NT_SUCCESS(Status) && TargetPath != NULL && TargetPath->Buffer != NULL) {
            (VOID)DragonSendEvent(
                      Job->RuleCode,
                      Job->Action,
                      Job->SourcePid,
                      TargetPath->Buffer,
                      TargetPath->Length);
            ExFreePool(TargetPath);
            Reported = TRUE;
        }

        ObDereferenceObject(TargetProcess);
    }

    if (Reported == FALSE) {
        (VOID)DragonSendEvent(
                  Job->RuleCode,
                  Job->Action,
                  Job->SourcePid,
                  Job->Path,
                  Job->PathBytes);
    }

    if (Job->Action == DRG_ACTION_TERMINATE) {
        DragonQueueTerminate(Job->SourcePid);
    }
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 分发单个作业。
--*/
static
VOID
DragonExecuteJob(
    _In_ PDRG_JOB Job
    )
{
    switch ((DRG_JOB_KIND)Job->Kind) {

        case DrgJobReport:
            (VOID)DragonSendEvent(
                      Job->RuleCode,
                      Job->Action,
                      Job->SourcePid,
                      Job->Path,
                      Job->PathBytes);
            break;

        case DrgJobTerminate:
            DragonExecuteTermination(Job->TargetPid, Job->TargetCreateTime);
            break;

        case DrgJobThreadScan:
            DragonExecuteThreadScan(Job);
            break;

        case DrgJobAccessReport:
            DragonExecuteAccessReport(Job);
            break;

        default:
            break;
    }
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 排空工作项回调：循环取出作业并执行，直到队列为空。

        每轮处理上限 DRG_DRAIN_BATCH_LIMIT，超出则主动让出工作线程并重新排队，
        避免长时间占用系统工作线程（规范「IOCTL安全规范」第 3 条精神）。
--*/
static
VOID
DragonDrainEvtWorkItem(
    _In_ WDFWORKITEM WorkItem
    )
{
    PDRG_JOB Job;
    ULONG Batch;

    UNREFERENCED_PARAMETER(WorkItem);

    Batch = 0;

    for (;;) {

        Job = DragonJobPop();

        if (Job == NULL) {
            InterlockedExchange(&g_Dragon.DrainScheduled, 0);

            /* 清标志后再确认一次，避免与入队线程竞态导致漏调度 */
            if (DragonJobPending() == FALSE) {
                break;
            }

            if (InterlockedCompareExchange(&g_Dragon.DrainScheduled, 1, 0) != 0) {
                break;
            }

            continue;
        }

        InterlockedDecrement(&g_Dragon.JobCount);
        DragonExecuteJob(Job);
        DragonJobRelease(Job);

        Batch++;
        if (Batch >= DRG_DRAIN_BATCH_LIMIT) {
            InterlockedExchange(&g_Dragon.DrainScheduled, 0);
            if (DragonJobPending() == TRUE &&
                InterlockedCompareExchange(&g_Dragon.DrainScheduled, 1, 0) == 0) {
                WdfWorkItemEnqueue(g_Dragon.DrainWorkItem);
            }
            break;
        }
    }
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 创建作业队列与排空工作项。

@note  工作项必须挂在一个「设备对象或设备对象祖先」之下，因此这里以控制设备
       对象为父；这也是非 PnP KMDF 驱动应当创建控制设备的原因之一。
--*/
NTSTATUS
DragonResponseInitialize(
    _In_ WDFDRIVER Driver
    )
{
    NTSTATUS Status;
    WDF_OBJECT_ATTRIBUTES Attributes;
    WDF_WORKITEM_CONFIG Config;

    UNREFERENCED_PARAMETER(Driver);

    if (g_Dragon.ControlDevice == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InitializeListHead(&g_Dragon.JobQueue);
    KeInitializeSpinLock(&g_Dragon.JobLock);
    InterlockedExchange(&g_Dragon.JobCount, 0);
    InterlockedExchange(&g_Dragon.DrainScheduled, 0);
    InterlockedExchange(&g_Dragon.EnqueueActive, 0);
    InterlockedExchange(&g_Dragon.Shutdown, 0);

    WDF_OBJECT_ATTRIBUTES_INIT(&Attributes);
    Attributes.ParentObject = g_Dragon.ControlDevice;

    WDF_WORKITEM_CONFIG_INIT(&Config, DragonDrainEvtWorkItem);
    Config.AutomaticSerialization = FALSE;

    Status = WdfWorkItemCreate(&Config, &Attributes, &g_Dragon.DrainWorkItem);
    if (!NT_SUCCESS(Status)) {
        g_Dragon.DrainWorkItem = NULL;
        return Status;
    }

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 停止排空工作项、清空残余作业并删除工作项对象。

        顺序保证：
          1. 置 Shutdown，阻断一切新的入队；
          2. 反复 Flush + 检查，直到既无在途回调也无待处理作业；
          3. 丢弃残余作业；
          4. 删除工作项对象（此后任何入队都不可能成功）。
--*/
VOID
DragonResponseTeardown(
    VOID
    )
{
    ULONG Attempt;
    BOOLEAN Empty;
    BOOLEAN Quiesced;
    LARGE_INTEGER Delay;
    KIRQL OldIrql;

    InterlockedExchange(&g_Dragon.Shutdown, 1);

    /*
     * WdfWorkItemFlush / WdfObjectDelete / KeDelayExecutionThread 都要求
     * PASSIVE_LEVEL。本函数的两条调用链（FilterUnloadCallback、DriverEntry 失败
     * 清理）都在 PASSIVE，但这里仍显式判定：若未来出现在更高 IRQL 上，
     * 宁可「不删工作项」（交给父设备对象级联回收）也不能触发断言蓝屏。
     * 尾部的作业清理只用自旋锁，任意 IRQL 下都安全，因此始终执行。
     */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL && g_Dragon.DrainWorkItem != NULL) {

        Delay.QuadPart = DRG_SHUTDOWN_POLL_100NS;

        for (Attempt = 0; Attempt < DRG_SHUTDOWN_MAX_POLLS; Attempt++) {

            WdfWorkItemFlush(g_Dragon.DrainWorkItem);

            KeAcquireSpinLock(&g_Dragon.JobLock, &OldIrql);
            Empty = (IsListEmpty(&g_Dragon.JobQueue) == TRUE) ? TRUE : FALSE;
            KeReleaseSpinLock(&g_Dragon.JobLock, OldIrql);

            Quiesced = (Empty == TRUE &&
                        InterlockedCompareExchange(&g_Dragon.DrainScheduled, 0, 0) == 0 &&
                        InterlockedCompareExchange(&g_Dragon.EnqueueActive, 0, 0) == 0)
                           ? TRUE
                           : FALSE;

            if (Quiesced == TRUE) {
                break;
            }

            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        }

        WdfObjectDelete(g_Dragon.DrainWorkItem);
        g_Dragon.DrainWorkItem = NULL;
    }

    DragonJobPurge();
    InterlockedExchange(&g_Dragon.JobCount, 0);
    InterlockedExchange(&g_Dragon.DrainScheduled, 0);
}
