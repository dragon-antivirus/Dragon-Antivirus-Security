/*++
===============================================================================
 Dragon-Drivers / DragonComms.c

 通信端口（Filter Manager 消息端口）+ 命令分发 + 运行状态机。

 端口特性：
   · 单一客户端（FltCreateCommunicationPort 的 MaxConnections = 1）；
   · 连接必须同时满足四项校验才被接受：
       1. ConnectionContext 自描述的 Size / Version / Magic；
       2. 上下文中声明的 ProcessId 必须等于实际发起进程；
       3. 实际发起进程的镜像路径必须与注册表登记的 ClientImagePath 完全一致；
       4. 驱动处于 Running / Retry 状态且端口处于可接受状态。
   · 断开路径与发送路径通过 EX_RUNDOWN_REF 交叉保护，不会出现
     「端口已关闭但仍在 FltSendMessage」的窗口。

 输入缓冲区处理（重要）：
   ConnectionContext 与 InputBuffer 都由 Filter Manager 交付，来源是用户态
   FilterConnectCommunicationPort / FilterSendMessage 的调用参数。这里遵循
   「绝不信任输入」原则：
     · 先长度校验，再用结构化异常处理（__try/__except）包裹复制，
       既不因非法地址把访问违例变成可利用的崩溃点，也不会泄漏异常码之外的
       任何内部状态；
     · 复制到内核栈局部变量后，所有字段都按协议再次逐项校验；
     · 绝不把交付缓冲区指针保存到任何长期结构中。
===============================================================================
--*/

#include "DragonCommon.h"

/*=============================================================================
  状态机
=============================================================================*/

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 读取当前驱动状态。
--*/
LONG
DragonStateGet(
    VOID
    )
{
    return InterlockedCompareExchange(&g_Dragon.DriverState, 0, 0);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 设置驱动状态。
--*/
VOID
DragonStateSet(
    _In_ LONG State
    )
{
    InterlockedExchange(&g_Dragon.DriverState, State);
}

/*=============================================================================
  客户端授权
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 校验连接请求是否来自被授权的客户端。

        额外要求：ClientImagePath 必须已由驱动服务注册表登记，
        否则一律拒绝——避免「未配置即开放端口」。
--*/
static
BOOLEAN
DragonIsAuthorizedClient(
    _In_opt_ PVOID ConnectionContext,
    _In_ ULONG SizeOfContext
    )
{
    DRG_CONNECTION_CONTEXT Context;
    PUNICODE_STRING ImagePath;
    NTSTATUS Status;
    BOOLEAN Authorized;

    if (ConnectionContext == NULL || SizeOfContext < sizeof(DRG_CONNECTION_CONTEXT)) {
        return FALSE;
    }

    if (g_Dragon.ClientImagePath.Buffer == NULL ||
        g_Dragon.ClientIdentityReady == FALSE ||
        g_Dragon.ClientImagePath.Length == 0) {
        return FALSE;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    RtlZeroMemory(&Context, sizeof(Context));

    __try {
        RtlCopyMemory(&Context, ConnectionContext, sizeof(Context));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (Context.Size < sizeof(DRG_CONNECTION_CONTEXT)) {
        return FALSE;
    }

    if (Context.Version != DRG_CONNECTION_VERSION) {
        return FALSE;
    }

    if (Context.Magic != DRG_CONNECTION_MAGIC) {
        return FALSE;
    }

    if (Context.ProcessId != (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        return FALSE;
    }

    ImagePath = NULL;
    Status = SeLocateProcessImageName(PsGetCurrentProcess(), &ImagePath);
    if (!NT_SUCCESS(Status) || ImagePath == NULL || ImagePath->Buffer == NULL) {
        if (ImagePath != NULL) {
            ExFreePool(ImagePath);
        }
        return FALSE;
    }

    Authorized = RtlEqualUnicodeString(ImagePath, &g_Dragon.ClientImagePath, TRUE);
    ExFreePool(ImagePath);
    return Authorized;
}

/*=============================================================================
  端口回调
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 连接通知：完成授权校验与单客户端登记。
--*/
static
NTSTATUS
DragonPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_opt_ PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID *ConnectionPortCookie
    )
{
    NTSTATUS Status;
    LONG State;
    ULONG ProcessId;

    UNREFERENCED_PARAMETER(ServerPortCookie);

    if (ConnectionPortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ConnectionPortCookie = NULL;

    if (DragonIsAuthorizedClient(ConnectionContext, SizeOfContext) == FALSE) {
        return STATUS_ACCESS_DENIED;
    }

    if (InterlockedCompareExchange(&g_Dragon.PortAccepting, 0, 0) == 0) {
        return STATUS_DELETE_PENDING;
    }

    State = DragonStateGet();
    if (State != (LONG)DrgStateRunning && State != (LONG)DrgStateRetry) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (ExAcquireRundownProtection(&g_Dragon.PortRundown) == FALSE) {
        return STATUS_DELETE_PENDING;
    }

    ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    Status = STATUS_SUCCESS;

    /*
     * 临界区内只做状态读取与指针 / PID 交换，无分页访问、无阻塞调用，
     * 因此可以在自旋锁下安全执行（详见 DragonCommon.h 中 ConnectionLock 的说明）。
     * 锁为 NULL 仅可能出现在初始化失败路径上，此时一律拒绝连接，
     * 且必须走统一的 rundown 归还出口，绝不能提前 return（否则轮转保护泄漏，
     * 卸载时的 ExWaitForRundownProtectionRelease 会永久阻塞）。
     */
    if (g_Dragon.ConnectionLock == NULL) {
        Status = STATUS_DEVICE_NOT_READY;
    }
    else {
        WdfSpinLockAcquire(g_Dragon.ConnectionLock);

        State = DragonStateGet();

        if (InterlockedCompareExchange(&g_Dragon.PortAccepting, 0, 0) == 0) {
            Status = STATUS_DELETE_PENDING;
        }
        else if (State != (LONG)DrgStateRunning && State != (LONG)DrgStateRetry) {
            Status = STATUS_DEVICE_NOT_READY;
        }
        else if (g_Dragon.ClientPort != NULL) {
            Status = STATUS_DEVICE_BUSY;
        }
        else {
            g_Dragon.ClientPort = ClientPort;
            InterlockedExchange(&g_Dragon.ClientPid, (LONG)ProcessId);

            /*
             * 记录客户端进程创建时间：内置自保护在句柄回调里依赖「PID + 创建时间」
             * 确认目标确实是我们的客户端，避免 PID 复用后被冒名保护。
             * PsGetProcessCreateTimeQuadPart 只读 EPROCESS 的非分页字段，
             * 在本临界区内调用不违反自旋锁约束。
             */
            g_Dragon.ClientCreateTime.QuadPart =
                PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());

            /* 连接凭据用 PID 表示，断开时据此判断是否为当前客户端 */
            *ConnectionPortCookie = (PVOID)(ULONG_PTR)ProcessId;
        }

        WdfSpinLockRelease(g_Dragon.ConnectionLock);
    }

    if (!NT_SUCCESS(Status)) {
        ExReleaseRundownProtection(&g_Dragon.PortRundown);
        return Status;
    }

    InterlockedExchange(&g_Dragon.UnloadAuthorized, 0);
    ExReleaseRundownProtection(&g_Dragon.PortRundown);

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 断开通知：关闭客户端端口并清除客户端身份。
--*/
static
VOID
DragonPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    )
{
    PFLT_PORT ClientPort;
    PFLT_FILTER FilterHandle;
    PFLT_PORT PortToClose;

    if (ConnectionCookie == NULL) {
        return;
    }

    ClientPort = NULL;
    FilterHandle = g_Dragon.FilterHandle;

    /*
     * 断开回调的 IRQL 在官方文档中未做 PASSIVE_LEVEL 保证，因此这里使用自旋锁，
     * 临界区内同样只做指针 / PID 交换。
     */
    if (g_Dragon.ConnectionLock != NULL) {
        WdfSpinLockAcquire(g_Dragon.ConnectionLock);

        if (g_Dragon.ClientPort != NULL &&
            (ULONG)(ULONG_PTR)ConnectionCookie ==
                (ULONG)InterlockedCompareExchange(&g_Dragon.ClientPid, 0, 0)) {

            ClientPort = g_Dragon.ClientPort;
            g_Dragon.ClientPort = NULL;
            InterlockedExchange(&g_Dragon.ClientPid, 0);
            g_Dragon.ClientCreateTime.QuadPart = 0;
        }

        WdfSpinLockRelease(g_Dragon.ConnectionLock);
    }

    if (ClientPort != NULL && FilterHandle != NULL) {
        PortToClose = ClientPort;
        FltCloseClientPort(FilterHandle, &PortToClose);
    }

    InterlockedExchange(&g_Dragon.UnloadAuthorized, 0);
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 处理「清除规则」命令。
--*/
static
NTSTATUS
DragonHandleClearRules(
    VOID
    )
{
    DragonRulesClear();
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 处理「加载规则文件」命令。
--*/
static
NTSTATUS
DragonHandleLoadRuleFile(
    _Inout_ PUNICODE_STRING Path
    )
{
    NTSTATUS Status;

    if (Path->Length == 0 || Path->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = DragonRulesLoadFile(Path);
    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 查询状态：把 ULONG 状态写回用户态输出缓冲区。
--*/
static
NTSTATUS
DragonHandleQueryState(
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnOutputBufferLength
    )
{
    ULONG Flags;
    DRG_STATE_REPLY Reply;

    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(DRG_STATE_REPLY) ||
        ReturnOutputBufferLength == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Flags = 0;
    if (g_Dragon.RulesEngineReady == TRUE) {
        Flags |= DRG_FLAG_RULES_LOADED;
    }
    if (g_Dragon.ClientPort != NULL) {
        Flags |= DRG_FLAG_CLIENT_ATTACHED;
    }

    Reply.State = (ULONG)DragonStateGet();
    Reply.Flags = Flags;

    __try {
        RtlCopyMemory(OutputBuffer, &Reply, sizeof(Reply));
        *ReturnOutputBufferLength = sizeof(Reply);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 查询勒索防护状态。
--*/
static
NTSTATUS
DragonHandleQueryRansom(
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnOutputBufferLength
    )
{
    DRG_RANSOM_STATUS Snapshot;

    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(DRG_RANSOM_STATUS) ||
        ReturnOutputBufferLength == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    DragonRansomQueryStatus(&Snapshot);

    __try {
        RtlCopyMemory(OutputBuffer, &Snapshot, sizeof(Snapshot));
        *ReturnOutputBufferLength = sizeof(Snapshot);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 恢复被勒索影响的文件，并解除阻断。

@param  Argument DRG_RESTORE_MODE_ROLLBACK（恢复 + 解封）
                 或 DRG_RESTORE_MODE_RELEASE（仅解封）
--*/
static
NTSTATUS
DragonHandleRestoreFiles(
    _In_opt_ PUNICODE_STRING Path,
    _In_ ULONG Argument,
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS Status;
    DRG_RESTORE_REPLY Reply;
    ULONG Mode;

    Mode = (Argument == DRG_RESTORE_MODE_RELEASE)
               ? DRG_RESTORE_MODE_RELEASE
               : DRG_RESTORE_MODE_ROLLBACK;

    Status = DragonRansomRestore(Path, Mode, &Reply);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* 回复体可选：调用方不关心计数时允许省略输出缓冲区 */
    if (OutputBuffer != NULL &&
        OutputBufferLength >= sizeof(DRG_RESTORE_REPLY) &&
        ReturnOutputBufferLength != NULL) {

        __try {
            RtlCopyMemory(OutputBuffer, &Reply, sizeof(Reply));
            *ReturnOutputBufferLength = sizeof(Reply);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 查询诊断统计。

        快照结构 1.2KB，放在非分页池而不是内核栈上 —— 端口消息回调可能被
        Filter Manager 从任意线程上下文调用，保持栈帧小是最稳妥的做法。
--*/
static
NTSTATUS
DragonHandleQueryMetrics(
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS Status;
    PDRG_METRICS Snapshot;

    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(DRG_METRICS) ||
        ReturnOutputBufferLength == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Snapshot = (PDRG_METRICS)DragonAllocate(sizeof(DRG_METRICS));
    if (Snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DragonMetricsQuery(Snapshot);

    Status = STATUS_SUCCESS;

    __try {
        RtlCopyMemory(OutputBuffer, Snapshot, sizeof(DRG_METRICS));
        *ReturnOutputBufferLength = sizeof(DRG_METRICS);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    DragonFree(Snapshot);

    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 消息通知：解析用户态命令并分发。

        命令语义（与用户态数据契约一致）：
          1 追加白名单模式    2 删除白名单模式
          3 加载规则 JSON     4 清空动态规则
          5 授权卸载          6 撤销卸载授权
          7 查询状态
--*/
static
NTSTATUS
DragonPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_opt_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS Status;
    PDRG_COMMAND_MESSAGE Message;
    UNICODE_STRING Path;
    LONG State;
    ULONG Command;
    BOOLEAN RundownHeld;
    BOOLEAN CopyOk;
    NTSTATUS CopyStatus;

    Message = NULL;
    RundownHeld = FALSE;
    CopyOk = FALSE;
    CopyStatus = STATUS_SUCCESS;

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    if (PortCookie == NULL ||
        (ULONG)(ULONG_PTR)PortCookie != (ULONG)InterlockedCompareExchange(&g_Dragon.ClientPid, 0, 0)) {
        return STATUS_ACCESS_DENIED;
    }

    if (InputBuffer == NULL || InputBufferLength < sizeof(DRG_COMMAND_MESSAGE)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ExAcquireRundownProtection(&g_Dragon.PortRundown) == FALSE) {
        return STATUS_DELETE_PENDING;
    }

    RundownHeld = TRUE;
    Status = STATUS_SUCCESS;

    /*
     * 2 KB 的命令缓冲放在非分页池而不是内核栈上：端口消息回调可能被 Filter Manager
     * 从任意线程上下文调用，保持栈帧极小是对内核栈最稳妥的做法。所有失败分支统一
     * 走 Exit 标签释放，不存在泄漏路径。
     */
    Message = (PDRG_COMMAND_MESSAGE)DragonAllocate(sizeof(DRG_COMMAND_MESSAGE));
    if (Message == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    /*
     * 结构化异常处理只负责「探测并复制」，不在 __except 块内做控制流跳转，
     * 避免 MSVC 对越过 SEH 边界的 goto 发出告警或产生未定义行为。
     */
    __try {
        RtlCopyMemory(Message, InputBuffer, sizeof(DRG_COMMAND_MESSAGE));
        CopyOk = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        CopyOk = FALSE;
        CopyStatus = GetExceptionCode();
    }

    if (CopyOk == FALSE) {
        Status = CopyStatus;
        goto Exit;
    }

    /* 强制结尾，杜绝未终止的宽字符串 */
    Message->Path[DRG_PATH_CHARS - 1] = L'\0';

    Command = Message->Command;
    State = DragonStateGet();

    if (Command == (ULONG)DrgCmdQueryState) {
        Status = DragonHandleQueryState(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        goto Exit;
    }

    if (Command == (ULONG)DrgCmdAuthorizeUnload) {
        if (State != (LONG)DrgStateRunning && State != (LONG)DrgStateRetry) {
            Status = STATUS_DEVICE_NOT_READY;
            goto Exit;
        }

        InterlockedExchange(&g_Dragon.UnloadAuthorized, 1);
        goto Exit;
    }

    if (Command == (ULONG)DrgCmdRevokeUnload) {
        InterlockedExchange(&g_Dragon.UnloadAuthorized, 0);
        goto Exit;
    }

    if (Command < (ULONG)DrgCmdAddWhitelist || Command > (ULONG)DrgCmdQueryMetrics) {
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    if (State != (LONG)DrgStateRunning) {
        Status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }

    RtlInitUnicodeString(&Path, Message->Path);

    switch ((DRG_COMMAND)Command) {

        case DrgCmdAddWhitelist:
            if (Path.Length == 0) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            DragonTrustedAdd(&Path);
            Status = STATUS_SUCCESS;
            break;

        case DrgCmdRemoveWhitelist:
            if (Path.Length == 0) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            DragonTrustedRemove(&Path);
            Status = STATUS_SUCCESS;
            break;

        case DrgCmdLoadRuleFile:
            Status = DragonHandleLoadRuleFile(&Path);
            break;

        case DrgCmdClearRules:
            Status = DragonHandleClearRules();
            break;

        case DrgCmdQueryRansom:
            Status = DragonHandleQueryRansom(
                         OutputBuffer,
                         OutputBufferLength,
                         ReturnOutputBufferLength);
            break;

        case DrgCmdRestoreFiles:
            Status = DragonHandleRestoreFiles(
                         &Path,
                         Message->Argument,
                         OutputBuffer,
                         OutputBufferLength,
                         ReturnOutputBufferLength);
            break;

        case DrgCmdQueryMetrics:
            Status = DragonHandleQueryMetrics(
                         OutputBuffer,
                         OutputBufferLength,
                         ReturnOutputBufferLength);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

Exit:
    if (Message != NULL) {
        DragonFree(Message);
        Message = NULL;
    }

    if (RundownHeld == TRUE) {
        ExReleaseRundownProtection(&g_Dragon.PortRundown);
    }

    return Status;
}

/*=============================================================================
  端口生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 创建通信端口（要求过滤器已注册成功）。
--*/
NTSTATUS
DragonCommsCreate(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING PortName;

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_Dragon.FilterHandle == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (g_Dragon.ServerPort != NULL) {
        return STATUS_SUCCESS;
    }

    SecurityDescriptor = NULL;

    Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitUnicodeString(&PortName, DRG_PORT_NAME);

    InitializeObjectAttributes(
        &ObjectAttributes,
        &PortName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        SecurityDescriptor);

    InterlockedExchange(&g_Dragon.PortAccepting, 1);

    Status = FltCreateCommunicationPort(
                 g_Dragon.FilterHandle,
                 &g_Dragon.ServerPort,
                 &ObjectAttributes,
                 NULL,
                 DragonPortConnect,
                 DragonPortDisconnect,
                 DragonPortMessage,
                 1);

    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_Dragon.PortAccepting, 0);
        g_Dragon.ServerPort = NULL;
    }

    FltFreeSecurityDescriptor(SecurityDescriptor);
    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 关闭通信端口：停止接受新连接 -> 关闭服务端口 -> 关闭客户端端口
       -> 等待轮转保护释放，确保没有任何回调仍在引用端口。
--*/
VOID
DragonCommsClose(
    VOID
    )
{
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PFLT_PORT PortToClose;
    PFLT_FILTER FilterHandle;

    /* 1. 先关掉「接受连接」标志，所有新进入的端口回调会立即失败退出 */
    InterlockedExchange(&g_Dragon.PortAccepting, 0);

    FilterHandle = g_Dragon.FilterHandle;

    /* 2. 关闭服务端口：此后不再接受新连接 */
    ServerPort = g_Dragon.ServerPort;
    g_Dragon.ServerPort = NULL;

    if (ServerPort != NULL) {
        FltCloseCommunicationPort(ServerPort);
    }

    /*
     * 3. 关闭当前客户端端口，并清除客户端身份。
     *
     *    这里必须容忍 ConnectionLock 为 NULL：当 DriverEntry 在创建连接锁之前
     *    就失败时，统一清理路径同样会走到本函数；此时对 NULL 的 WDF 句柄调用
     *    WdfSpinLockAcquire 会直接触发 KMDF 断言（蓝屏）。锁不存在时说明
     *    端口也从未建立，直接原子读写即可，无并发可言。
     */
    ClientPort = NULL;

    if (g_Dragon.ConnectionLock != NULL) {
        WdfSpinLockAcquire(g_Dragon.ConnectionLock);
    }

    ClientPort = g_Dragon.ClientPort;
    g_Dragon.ClientPort = NULL;
    InterlockedExchange(&g_Dragon.ClientPid, 0);
    g_Dragon.ClientCreateTime.QuadPart = 0;

    if (g_Dragon.ConnectionLock != NULL) {
        WdfSpinLockRelease(g_Dragon.ConnectionLock);
    }

    if (ClientPort != NULL && FilterHandle != NULL) {
        PortToClose = ClientPort;
        FltCloseClientPort(FilterHandle, &PortToClose);
    }

    /*
     * 4. 等待在途端口回调全部退出。
     *
     *    ExWaitForRundownProtectionRelease 的语义是「先把轮转保护置为已释放，
     *    此后所有 ExAcquireRundownProtection 一律失败，直到现存持有者全部归还」。
     *    因此直接调用即可，不需要（也不能）在外层做「探测式」轮询——
     *    在它被调用之前任何获取都必然成功，轮询永远不会提前退出。
     *
     *    该例程对同一 EX_RUNDOWN_REF 只允许调用一次，用标志位保证幂等。
     */
    if (InterlockedExchange(&g_Dragon.PortRundownReleased, 1) == 0) {
        ExWaitForRundownProtectionRelease(&g_Dragon.PortRundown);
    }

    InterlockedExchange(&g_Dragon.UnloadAuthorized, 0);
}
