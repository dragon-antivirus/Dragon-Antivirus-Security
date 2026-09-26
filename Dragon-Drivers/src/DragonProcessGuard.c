/*++
===============================================================================
 Dragon-Drivers / DragonProcessGuard.c

 进程创建/退出通知 + 进程关系缓存。

 关系来源（唯一合法来源）：
   PsSetCreateProcessNotifyRoutineEx 的 PS_CREATE_NOTIFY_INFO 同时给出
   ParentProcessId 与 CreatingThreadId.UniqueProcess，这是**官方文档化**的
   获取父子/创建者关系的唯一入口，因此关系表在进程创建时刻填充。

 与参考实现的差异（规范约束导致，已在交付说明中标注）：
   参考实现额外通过 MmGetSystemRoutineAddress 动态解析
   PsGetProcessInheritedFromUniqueProcessId 作为「缓存未命中时」的兜底查询。
   该例程未被 WDK 头文件导出、也未在官方文档中公开；按规范第 1/2 条
   「严禁使用未文档化 API」，本驱动不采用该兜底，而是：
     · 缓存未命中时返回 FALSE（父进程维度不匹配）；
     · 进程自身镜像路径维度仍可正常匹配（层级 0 始终有效）。

 并发模型：
   g_RelationLock（KSPIN_LOCK）保护直接映射表；临界区内只做非分页内存访问。
   表中只保存 PID 与创建时间，不持有 EPROCESS 指针，因此不存在悬挂引用。
===============================================================================
--*/

#include "DragonCommon.h"

/*-----------------------------------------------------------------------------
  进程关系缓存
-----------------------------------------------------------------------------*/
static DRG_RELATION_ENTRY g_Relations[DRG_RELATION_BUCKETS][DRG_RELATION_WAYS];
static KSPIN_LOCK        g_RelationLock;
static BOOLEAN           g_RelationLockReady = FALSE;
static volatile LONG64   g_RelationSequence = 0;

/*++
@IRQL: PASSIVE_LEVEL
@brief 依据 PID 计算桶下标（PID 恒为 4 的倍数，右移 2 位后天然均匀）。
--*/
static
ULONG
DragonRelationBucket(
    _In_ HANDLE ProcessId
    )
{
    return (((ULONG)(ULONG_PTR)ProcessId) >> 2) & (DRG_RELATION_BUCKETS - 1);
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 写入一条关系。命中同 PID 直接覆盖；否则优先占用空槽，
       无空槽时淘汰该桶中序号最小（最久）的一条。
--*/
static
VOID
DragonProcessRelationStore(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE CreatorProcessId
    )
{
    ULONG Bucket;
    ULONG Index;
    ULONG Selected;
    KIRQL OldIrql;
    PDRG_RELATION_ENTRY Entry;
    PDRG_RELATION_ENTRY Candidate;
    LARGE_INTEGER ParentCreateTime;
    LARGE_INTEGER CreateTime;

    if (Process == NULL || ProcessId == NULL) {
        return;
    }

    /*
     * 锁未初始化（说明防护从未成功启动）时直接返回：绝不在未初始化的自旋锁上
     * 做 KeAcquireSpinLock，也绝不在 g_Relations 被当作有效表的前提下操作。
     */
    if (g_RelationLockReady == FALSE) {
        return;
    }

    /*
     * 所有需要查询进程对象的动作都必须在自旋锁之外完成：
     * PsLookupProcessByProcessId / PsGetProcessCreateTimeQuadPart 属于
     * PASSIVE~APC 级别操作，持自旋锁调用会把 IRQL 抬到 DISPATCH_LEVEL，
     * 属于规范永久黑名单里的「自旋锁内部执行阻塞/分页操作」。
     */
    CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    ParentCreateTime.QuadPart = 0;
    if (ParentProcessId != NULL) {
        PEPROCESS Parent;
        Parent = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ParentProcessId, &Parent)) && Parent != NULL) {
            ParentCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Parent);
            ObDereferenceObject(Parent);
        }
    }

    Bucket = DragonRelationBucket(ProcessId);
    Selected = 0;

    Candidate = NULL;
    Entry = NULL;

    KeAcquireSpinLock(&g_RelationLock, &OldIrql);

    for (Index = 0; Index < DRG_RELATION_WAYS; Index++) {

        Entry = &g_Relations[Bucket][Index];

        if (Entry->ProcessId == ProcessId || Entry->ProcessId == NULL) {
            Selected = Index;
            Candidate = Entry;
            break;
        }

        if (Candidate == NULL ||
            Entry->Sequence < g_Relations[Bucket][Selected].Sequence) {
            Selected = Index;
            Candidate = Entry;
        }
    }

    if (Candidate == NULL) {
        Candidate = &g_Relations[Bucket][Selected];
    }

    Candidate->ProcessId = ProcessId;
    Candidate->ParentProcessId = ParentProcessId;
    Candidate->CreatorProcessId = CreatorProcessId;
    Candidate->CreateTime = CreateTime;
    Candidate->ParentCreateTime = ParentCreateTime;
    Candidate->Sequence = (ULONGLONG)InterlockedIncrement64(&g_RelationSequence);

    KeReleaseSpinLock(&g_RelationLock, OldIrql);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 删除指定 PID 的关系条目。
--*/
VOID
DragonProcessRelationForget(
    _In_ HANDLE ProcessId
    )
{
    ULONG Bucket;
    ULONG Index;
    KIRQL OldIrql;

    if (ProcessId == NULL) {
        return;
    }

    if (g_RelationLockReady == FALSE) {
        return;
    }

    Bucket = DragonRelationBucket(ProcessId);

    KeAcquireSpinLock(&g_RelationLock, &OldIrql);

    for (Index = 0; Index < DRG_RELATION_WAYS; Index++) {
        if (g_Relations[Bucket][Index].ProcessId == ProcessId) {
            RtlZeroMemory(&g_Relations[Bucket][Index], sizeof(DRG_RELATION_ENTRY));
            break;
        }
    }

    KeReleaseSpinLock(&g_RelationLock, OldIrql);
}

/*++
@IRQL: <= APC_LEVEL
@brief 读取进程关系。

       命中后（在 PASSIVE_LEVEL 下）会用实时进程创建时间校验缓存，
       识别 PID 复用并顺手失效脏条目。
--*/
BOOLEAN
DragonProcessRelationGet(
    _In_ HANDLE ProcessId,
    _Out_opt_ PHANDLE ParentProcessId,
    _Out_opt_ PHANDLE CreatorProcessId
    )
{
    ULONG Bucket;
    ULONG Index;
    KIRQL OldIrql;
    DRG_RELATION_ENTRY Snapshot;
    BOOLEAN Found;
    PEPROCESS Process;
    LARGE_INTEGER LiveCreateTime;
    NTSTATUS Status;

    if (ParentProcessId != NULL) {
        *ParentProcessId = NULL;
    }
    if (CreatorProcessId != NULL) {
        *CreatorProcessId = NULL;
    }

    if (ProcessId == NULL || g_Dragon.ProcessGuardReady == FALSE) {
        return FALSE;
    }

    if (g_RelationLockReady == FALSE) {
        return FALSE;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    Bucket = DragonRelationBucket(ProcessId);
    RtlZeroMemory(&Snapshot, sizeof(Snapshot));
    Found = FALSE;

    KeAcquireSpinLock(&g_RelationLock, &OldIrql);

    for (Index = 0; Index < DRG_RELATION_WAYS; Index++) {
        if (g_Relations[Bucket][Index].ProcessId == ProcessId) {
            Snapshot = g_Relations[Bucket][Index];
            Found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_RelationLock, OldIrql);

    if (Found == FALSE) {
        return FALSE;
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

        Process = NULL;
        Status = PsLookupProcessByProcessId(ProcessId, &Process);
        if (!NT_SUCCESS(Status) || Process == NULL) {
            return FALSE;
        }

        LiveCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
        ObDereferenceObject(Process);

        if (LiveCreateTime.QuadPart != Snapshot.CreateTime.QuadPart) {
            DragonProcessRelationForget(ProcessId);
            return FALSE;
        }
    }

    if (ParentProcessId != NULL) {
        *ParentProcessId = Snapshot.ParentProcessId;
    }
    if (CreatorProcessId != NULL) {
        *CreatorProcessId = Snapshot.CreatorProcessId;
    }

    return (Snapshot.ParentProcessId != NULL || Snapshot.CreatorProcessId != NULL) ? TRUE : FALSE;
}

/*=============================================================================
  进程通知回调
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 进程创建/退出通知。

        创建：评估 Process 类别规则，命中则把 CreationStatus 置为
              STATUS_ACCESS_DENIED（内核会因此拒绝创建该进程）；
              未命中则登记父子关系。
        退出：移除关系条目。

@note  处置动作（上报 / 终止）只做入队，真正执行在工作项中完成，
       因此本回调保持短小，符合官方对通知例程的最佳实践要求。
--*/
static
VOID
DragonProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    HANDLE CreatorPid;
    HANDLE ParentPid;
    ULONG RuleCode;
    ULONG Action;

    if (g_Dragon.ProcessGuardReady == FALSE) {
        return;
    }

    if (CreateInfo == NULL) {
        DragonProcessRelationForget(ProcessId);

        /*
         * 进程退出：顺带回收勒索跟踪槽。不回收也不会立刻出错（槽位会被 LRU
         * 淘汰，且创建时间比对能防 PID 复用），但主动回收能让状态查询立刻反映
         * 真实进程数，不必等槽位超时。
         */
        DragonRansomForgetProcess(ProcessId);

        return;
    }

    DragonMetricsBump(DrgMetricProcessCreate, 1);

    if (!NT_SUCCESS(CreateInfo->CreationStatus)) {
        return;
    }

    CreatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
    ParentPid = CreateInfo->ParentProcessId;

    RuleCode = 0;
    Action = DRG_ACTION_REPORT;

    if (DragonEvaluateProcessCreate(
            CreatorPid,
            ParentPid,
            ProcessId,
            CreateInfo->ImageFileName,
            CreateInfo->CommandLine,
            (CreateInfo->FileOpenNameAvailable != FALSE) ? TRUE : FALSE,
            (CreateInfo->IsSubsystemProcess != FALSE) ? TRUE : FALSE,
            &RuleCode,
            &Action) == TRUE) {

        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

        /*
         * 上报 + 按 Action 处置。ImageFileName 允许为空（例如子系统进程），
         * DragonCopyPath 对空路径有显式处理，因此这里统一走同一条通路。
         */
        DragonQueueViolation(
            RuleCode,
            Action,
            CreatorPid,
            (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL)
                ? CreateInfo->ImageFileName->Buffer
                : NULL,
            (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL)
                ? CreateInfo->ImageFileName->Length
                : 0);
    }
    else {
        DragonProcessRelationStore(Process, ProcessId, ParentPid, CreatorPid);
    }
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 启动进程防护（幂等）。
--*/
NTSTATUS
DragonProcessGuardStart(
    VOID
    )
{
    NTSTATUS Status;

    if (g_Dragon.ProcessNotifyRegistered == TRUE) {
        return STATUS_SUCCESS;
    }

    KeInitializeSpinLock(&g_RelationLock);

    /*
     * 关系表约 192 KB。清零动作特意放在自旋锁之外：
     *   · 此刻进程创建通知尚未注册（下一次调用才注册），因此不存在并发访问；
     *   · g_Relations 是永不释放的静态数组，不存在生命周期竞争；
     *   · 在自旋锁内做 192 KB memset 会把 IRQL 抬到 DISPATCH_LEVEL 持续数十微秒，
     *     属于无意义的延迟尖峰，也是 Verifier / 代码审计的常见扣分点。
     */
    RtlZeroMemory(g_Relations, sizeof(g_Relations));
    InterlockedExchange64(&g_RelationSequence, 0);

    g_RelationLockReady = TRUE;

    Status = PsSetCreateProcessNotifyRoutineEx(DragonProcessNotify, FALSE);
    if (!NT_SUCCESS(Status)) {
        /*
         * 注册失败：把表的可用性收回来，避免后续在「没有回调来源」的状态下
         * 仍然对表做读写；这里不清锁本身，只是标记未就绪。
         */
        g_RelationLockReady = FALSE;
        return Status;
    }

    g_Dragon.ProcessNotifyRegistered = TRUE;
    g_Dragon.ProcessGuardReady = TRUE;
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 停止进程防护并清空关系缓存（幂等）。
--*/
VOID
DragonProcessGuardStop(
    VOID
    )
{
    NTSTATUS Status;

    /*
     * 先关评估开关再注销：回调入口会立刻因 ProcessGuardReady == FALSE 直接返回，
     * 因此下面的表清零不会与「有意义的」并发读写重叠。即使有极端情况下仍在
     * 执行的回调写入表项，也只会被这次清零覆盖——静态数组永不释放，
     * 不存在 Use-After-Free，属可控的良性结果。
     */
    g_Dragon.ProcessGuardReady = FALSE;

    if (g_Dragon.ProcessNotifyRegistered == TRUE) {
        Status = PsSetCreateProcessNotifyRoutineEx(DragonProcessNotify, TRUE);
        if (NT_SUCCESS(Status) || Status == STATUS_INVALID_PARAMETER) {
            g_Dragon.ProcessNotifyRegistered = FALSE;
        }
    }

    /*
     * 与 Start 对称：192 KB 的清零同样放在锁外，避免在 DISPATCH_LEVEL 下
     * 长时间持有自旋锁。只有锁确实初始化过才需要清表（否则防护从未启动成功）。
     */
    if (g_RelationLockReady == TRUE) {
        g_RelationLockReady = FALSE;
        RtlZeroMemory(g_Relations, sizeof(g_Relations));
        InterlockedExchange64(&g_RelationSequence, 0);
    }
}
