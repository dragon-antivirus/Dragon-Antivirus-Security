/*++
===============================================================================
 Dragon-Drivers / DragonEvaluate.c

 规则评估层：把「上下文」折算为「命中/不命中 + 处置动作」。

 统一约定：
   · 所有公开评估函数在文件/注册表/进程/内存维度上都只做只读判定，
     不做任何处置动作（处置由 DragonResponse.c 负责排队执行）。
   · 同一维度下遍历全部适用规则，命中的规则共同决定被拒操作集合；
     上报的规则编号取 Priority 最大者（并列时后遍历者胜出）。
   · 上下文能力不足（例如非 PASSIVE_LEVEL 无法解析镜像路径）时按
     「不命中」处理，即放行——与参考行为保持一致，不会误杀。
===============================================================================
--*/

#include "DragonCommon.h"

/*-----------------------------------------------------------------------------
  行为频率统计
-----------------------------------------------------------------------------*/
static DRG_BEHAVIOR_SLOT g_Behavior[DRG_BEHAVIOR_SLOTS];
static KSPIN_LOCK        g_BehaviorLock;
static BOOLEAN           g_BehaviorReady = FALSE;

/*++
@IRQL: PASSIVE_LEVEL
@brief 初始化行为统计槽位与锁。
--*/
VOID
DragonBehaviorInitialize(
    VOID
    )
{
    KeInitializeSpinLock(&g_BehaviorLock);
    RtlZeroMemory(g_Behavior, sizeof(g_Behavior));
    g_BehaviorReady = TRUE;
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 清空行为统计。
--*/
VOID
DragonBehaviorReset(
    VOID
    )
{
    KIRQL OldIrql;

    if (g_BehaviorReady == FALSE) {
        return;
    }

    KeAcquireSpinLock(&g_BehaviorLock, &OldIrql);
    RtlZeroMemory(g_Behavior, sizeof(g_Behavior));
    KeReleaseSpinLock(&g_BehaviorLock, OldIrql);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 取当前进程的创建时间；失败返回 0。
--*/
static
LARGE_INTEGER
DragonCurrentCreateTime(
    VOID
    )
{
    LARGE_INTEGER CreateTime;
    PEPROCESS Process;

    CreateTime.QuadPart = 0;

    Process = PsGetCurrentProcess();
    if (Process != NULL) {
        CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
    }

    return CreateTime;
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 频率阈值判定。

        语义：同一 (进程, 规则编号) 在 TimeWindow 内的命中次数达到 Threshold
              才判为触发；窗口过期自动归零。
        槽位复用顺序：同键命中 -> 空闲槽 -> 已过期槽 -> 最久未活跃槽。

@return TRUE 表示达到阈值。
--*/
static
BOOLEAN
DragonBehaviorTick(
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER CreateTime,
    _In_ ULONG RuleCode,
    _In_ ULONG Threshold,
    _In_ ULONG TimeWindowMs
    )
{
    LARGE_INTEGER Now;
    LARGE_INTEGER Window;
    ULONG Index;
    PDRG_BEHAVIOR_SLOT Slot;
    PDRG_BEHAVIOR_SLOT Target;
    PDRG_BEHAVIOR_SLOT Idle;
    PDRG_BEHAVIOR_SLOT Stale;
    PDRG_BEHAVIOR_SLOT Oldest;
    BOOLEAN Triggered;
    KIRQL OldIrql;

    if (Threshold == 0) {
        return TRUE;
    }

    if (g_BehaviorReady == FALSE) {
        return FALSE;
    }

    Now = DragonNow();
    Window.QuadPart = (LONGLONG)TimeWindowMs * 10000LL;

    Target = NULL;
    Idle = NULL;
    Stale = NULL;
    Oldest = NULL;
    Triggered = FALSE;

    KeAcquireSpinLock(&g_BehaviorLock, &OldIrql);

    for (Index = 0; Index < DRG_BEHAVIOR_SLOTS; Index++) {

        Slot = &g_Behavior[Index];

        if (Oldest == NULL || Slot->LastActivity.QuadPart < Oldest->LastActivity.QuadPart) {
            Oldest = Slot;
        }

        if (Slot->Pid == ProcessId &&
            Slot->RuleCode == RuleCode &&
            Slot->CreateTime.QuadPart == CreateTime.QuadPart) {
            Target = Slot;
            break;
        }

        if (Slot->Pid == NULL) {
            if (Idle == NULL) {
                Idle = Slot;
            }
            continue;
        }

        if (Stale == NULL &&
            (Now.QuadPart - Slot->LastActivity.QuadPart) > Window.QuadPart) {
            Stale = Slot;
        }
    }

    if (Target == NULL) {
        Target = (Idle != NULL) ? Idle : ((Stale != NULL) ? Stale : Oldest);
        if (Target == NULL) {
            KeReleaseSpinLock(&g_BehaviorLock, OldIrql);
            return FALSE;
        }

        Target->Pid = ProcessId;
        Target->RuleCode = RuleCode;
        Target->CreateTime = CreateTime;
        Target->Count = 0;
        Target->LastActivity = Now;
    }
    else {
        if ((Now.QuadPart - Target->LastActivity.QuadPart) > Window.QuadPart) {
            Target->Count = 0;
        }
        Target->LastActivity = Now;
    }

    Target->Count++;

    if (Target->Count >= Threshold) {
        Triggered = TRUE;
    }

    KeReleaseSpinLock(&g_BehaviorLock, OldIrql);
    return Triggered;
}

/*=============================================================================
  上下文解析辅助
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 取进程完整镜像路径；调用方负责 ExFreePool 释放。

@note  使用官方文档化 DDI SeLocateProcessImageName（ntifs.h，PASSIVE_LEVEL）。
--*/
static
BOOLEAN
DragonGetProcessPath(
    _In_ HANDLE ProcessId,
    _Outptr_result_maybenull_ PUNICODE_STRING *OutPath
    )
{
    NTSTATUS Status;
    PEPROCESS Process;

    if (OutPath == NULL) {
        return FALSE;
    }

    *OutPath = NULL;

    if (ProcessId == NULL || DragonAtPassiveLevel() == FALSE) {
        return FALSE;
    }

    Process = NULL;
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status) || Process == NULL) {
        return FALSE;
    }

    Status = SeLocateProcessImageName(Process, OutPath);
    ObDereferenceObject(Process);

    if (!NT_SUCCESS(Status) || *OutPath == NULL || (*OutPath)->Buffer == NULL || (*OutPath)->Length == 0) {
        if (*OutPath != NULL) {
            ExFreePool(*OutPath);
            *OutPath = NULL;
        }
        return FALSE;
    }

    return TRUE;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 释放 DragonGetProcessPath 返回的路径。
--*/
static
VOID
DragonFreeProcessPath(
    _In_opt_ PUNICODE_STRING Path
    )
{
    if (Path != NULL) {
        ExFreePool(Path);
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 扩展名后缀匹配（规则 Extensions 字段）。
--*/
static
BOOLEAN
DragonExtensionMatches(
    _In_opt_ PDRG_PATTERN Head,
    _In_opt_ PCUNICODE_STRING Text
    )
{
    PDRG_PATTERN Cursor;

    if (Head == NULL || Text == NULL || Text->Buffer == NULL) {
        return FALSE;
    }

    for (Cursor = Head; Cursor != NULL; Cursor = Cursor->Next) {
        if (Cursor->Text.Buffer != NULL && DragonHasSuffix(Text, Cursor->Text.Buffer)) {
            return TRUE;
        }
    }

    return FALSE;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 直接父进程匹配。
--*/
static
BOOLEAN
DragonMatchDirectParent(
    _In_ HANDLE ProcessId,
    _In_opt_ PDRG_PATTERN Include,
    _In_opt_ PDRG_PATTERN Exclude
    )
{
    HANDLE ParentPid;
    PUNICODE_STRING ParentPath;
    BOOLEAN Match;

    if (Include == NULL && Exclude == NULL) {
        return TRUE;
    }

    ParentPid = NULL;
    if (DragonProcessRelationGet(ProcessId, &ParentPid, NULL) == FALSE || ParentPid == NULL) {
        return FALSE;
    }

    ParentPath = NULL;
    if (DragonGetProcessPath(ParentPid, &ParentPath) == FALSE) {
        return FALSE;
    }

    Match = DragonPatternListConflict(Include, Exclude, ParentPath);
    DragonFreeProcessPath(ParentPath);
    return Match;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 进程树匹配（自身 + 向上最多 DRG_TREE_MAX_DEPTH 层祖先）。

        Exclude 命中任意一层即整体否决；Include 命中任意一层即满足包含条件。
--*/
static
BOOLEAN
DragonMatchProcessTree(
    _In_ HANDLE ProcessId,
    _In_opt_ PDRG_PATTERN Include,
    _In_opt_ PDRG_PATTERN Exclude
    )
{
    HANDLE Current;
    HANDLE Parent;
    HANDLE Visited[DRG_TREE_MAX_DEPTH];
    ULONG VisitedCount;
    ULONG Depth;
    ULONG Index;
    BOOLEAN Seen;
    PUNICODE_STRING Path;
    BOOLEAN IncludeMatched;

    if (Include == NULL && Exclude == NULL) {
        return TRUE;
    }

    if (ProcessId == NULL) {
        return FALSE;
    }

    RtlZeroMemory(Visited, sizeof(Visited));
    VisitedCount = 0;
    IncludeMatched = (Include == NULL) ? TRUE : FALSE;
    Current = ProcessId;

    for (Depth = 0; Depth < DRG_TREE_MAX_DEPTH; Depth++) {

        Seen = FALSE;
        for (Index = 0; Index < VisitedCount; Index++) {
            if (Visited[Index] == Current) {
                Seen = TRUE;
                break;
            }
        }
        if (Seen == TRUE) {
            break;
        }
        Visited[VisitedCount] = Current;
        VisitedCount++;

        Path = NULL;
        if (DragonGetProcessPath(Current, &Path) == TRUE) {

            if (Exclude != NULL && DragonPatternListMatches(Exclude, Path) == TRUE) {
                DragonFreeProcessPath(Path);
                return FALSE;
            }

            if (Include != NULL && DragonPatternListMatches(Include, Path) == TRUE) {
                IncludeMatched = TRUE;
            }

            DragonFreeProcessPath(Path);
        }

        Parent = NULL;
        if (DragonProcessRelationGet(Current, &Parent, NULL) == FALSE) {
            break;
        }
        if (Parent == NULL || Parent == Current) {
            break;
        }

        Current = Parent;
    }

    return IncludeMatched;
}

/*=============================================================================
  风险评分
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 句柄访问风险评分。
--*/
static
ULONG
DragonRiskAccess(
    _In_ ULONG Operations,
    _In_ ULONG HandleType,
    _In_ ULONG ObjectType
    )
{
    ULONG Score;

    Score = 0;

    if (Operations & DRG_OP_VM_READ)           { Score += 10; }
    if (Operations & DRG_OP_VM_WRITE)          { Score += 35; }
    if (Operations & DRG_OP_VM_OPERATION)      { Score += 20; }
    if (Operations & DRG_OP_CREATE_THREAD)     { Score += 45; }
    if (Operations & DRG_OP_THREAD_SET_CONTEXT){ Score += 50; }
    if (Operations & DRG_OP_THREAD_SET_TOKEN)  { Score += 55; }
    if (Operations & DRG_OP_TERMINATE)         { Score += 40; }
    if (Operations & DRG_OP_SUSPEND_RESUME)    { Score += 25; }
    if (Operations & DRG_OP_DUP_HANDLE)        { Score += 25; }
    if (Operations & DRG_OP_SET_INFORMATION)   { Score += 20; }
    if (Operations & DRG_OP_CREATE_PROCESS)    { Score += 35; }
    if (Operations & DRG_OP_IMPERSONATE)       { Score += 55; }

    if (HandleType == DRG_HANDLE_DUPLICATE) {
        Score += 10;
    }

    if (ObjectType == DRG_OBJECT_THREAD &&
        (Operations & (DRG_OP_THREAD_SET_CONTEXT | DRG_OP_THREAD_SET_TOKEN | DRG_OP_IMPERSONATE))) {
        Score += 10;
    }

    return (Score > DRG_RISK_MAX) ? DRG_RISK_MAX : Score;
}

/*++
@IRQL: <= APC_LEVEL
@brief 跨进程线程创建风险评分。
--*/
static
ULONG
DragonRiskThread(
    _In_ ULONG MemoryType,
    _In_ ULONG MemoryProtection,
    _In_ SIZE_T RegionSize
    )
{
    ULONG Score;

    Score = 20;

    if (MemoryType & DRG_MEMORY_PRIVATE) {
        Score += 40;
    }
    else if (MemoryType & DRG_MEMORY_MAPPED) {
        Score += 20;
    }
    else if (MemoryType & DRG_MEMORY_IMAGE) {
        Score += 5;
    }

    if (MemoryProtection & DRG_PROTECT_EXECUTE_WRITE) {
        Score += 30;
    }
    else if (MemoryProtection & DRG_PROTECT_EXECUTE) {
        Score += 10;
    }

    if (RegionSize > 0 && RegionSize <= (1024 * 1024)) {
        Score += 5;
    }

    return (Score > DRG_RISK_MAX) ? DRG_RISK_MAX : Score;
}

/*++
@IRQL: <= APC_LEVEL
@brief 进程创建风险评分。
--*/
static
ULONG
DragonRiskProcessCreate(
    _In_ HANDLE CreatorPid,
    _In_ HANDLE ParentPid,
    _In_ BOOLEAN IsSubsystemProcess
    )
{
    ULONG Score;

    Score = 0;

    if (CreatorPid != NULL && ParentPid != NULL && CreatorPid != ParentPid) {
        Score += 35;
    }

    if (IsSubsystemProcess == TRUE) {
        Score += 10;
    }

    return Score;
}

/*++
@IRQL: <= APC_LEVEL
@brief 风险分值区间匹配。
--*/
static
BOOLEAN
DragonRiskInRange(
    _In_ PDRG_RULE Rule,
    _In_ ULONG Risk
    )
{
    if (Rule->MinRisk > 0 && Risk < Rule->MinRisk) {
        return FALSE;
    }

    if (Rule->MaxRisk > 0 && Risk > Rule->MaxRisk) {
        return FALSE;
    }

    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 三态条件匹配。
--*/
static
BOOLEAN
DragonTriStateMatches(
    _In_ ULONG Condition,
    _In_ BOOLEAN Value
    )
{
    switch ((DRG_TRI)Condition) {
        case DrgTriAny:
            return TRUE;
        case DrgTriTrue:
            return (Value == TRUE) ? TRUE : FALSE;
        case DrgTriFalse:
            return (Value == FALSE) ? TRUE : FALSE;
        default:
            return TRUE;
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 计算规则在本轮请求中实际命中的操作位。

@note  OperationMatch = All 时要求规则里所有「内存/控制类」操作位都被请求覆盖。
--*/
static
ULONG
DragonMatchedOperations(
    _In_ PDRG_RULE Rule,
    _In_ ULONG Requested
    )
{
    ULONG RuleOperations;
    ULONG Relevant;

    RuleOperations = Rule->Operations & Requested;
    if (RuleOperations == 0) {
        return 0;
    }

    if (Rule->OperationMatch != (ULONG)DrgOpMatchAll) {
        return RuleOperations;
    }

    Relevant = Rule->Operations & (
        DRG_OP_VM_READ |
        DRG_OP_VM_WRITE |
        DRG_OP_VM_OPERATION |
        DRG_OP_CREATE_THREAD |
        DRG_OP_THREAD_SET_CONTEXT |
        DRG_OP_THREAD_SET_TOKEN |
        DRG_OP_TERMINATE |
        DRG_OP_SUSPEND_RESUME |
        DRG_OP_DUP_HANDLE |
        DRG_OP_SET_INFORMATION |
        DRG_OP_CREATE_PROCESS |
        DRG_OP_IMPERSONATE);

    if (Relevant == 0) {
        return 0;
    }

    if ((Requested & Relevant) != Relevant) {
        return 0;
    }

    return Relevant;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 源/目标双端上下文匹配（内存与进程句柄规则共用）。
--*/
static
BOOLEAN
DragonMatchSourceTarget(
    _In_ PDRG_RULE Rule,
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_opt_ PCUNICODE_STRING SourcePath,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_ ULONG HandleType,
    _In_ ULONG ObjectType,
    _In_ ULONG Risk
    )
{
    if (Rule->HandleTypes != 0 && (Rule->HandleTypes & HandleType) == 0) {
        return FALSE;
    }

    if (Rule->ObjectTypes != 0 && (Rule->ObjectTypes & ObjectType) == 0) {
        return FALSE;
    }

    if (DragonRiskInRange(Rule, Risk) == FALSE) {
        return FALSE;
    }

    if (DragonPatternListConflict(Rule->Initiator, Rule->InitiatorExclude, SourcePath) == FALSE) {
        return FALSE;
    }

    if (DragonPatternListConflict(Rule->Target, Rule->TargetExclude, TargetPath) == FALSE) {
        return FALSE;
    }

    if (DragonMatchDirectParent(SourcePid, Rule->InitiatorParent, Rule->InitiatorParentExclude) == FALSE) {
        return FALSE;
    }

    if (DragonMatchProcessTree(SourcePid, Rule->InitiatorTree, Rule->InitiatorTreeExclude) == FALSE) {
        return FALSE;
    }

    if (DragonMatchProcessTree(TargetPid, Rule->TargetTree, Rule->TargetTreeExclude) == FALSE) {
        return FALSE;
    }

    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 由规则得出处置动作。

        规则显式给出 Action 时以它为准；未给出（旧版规则文件只有 Kill）时
        按 Kill 推断：true -> Terminate，false -> Report。这样升级驱动不会
        改变既有规则文件的行为。
--*/
static
ULONG
DragonRuleAction(
    _In_ PDRG_RULE Rule
    )
{
    if (Rule->Action != DRG_ACTION_UNSET) {
        return Rule->Action;
    }

    return (Rule->Kill != FALSE) ? DRG_ACTION_TERMINATE : DRG_ACTION_REPORT;
}

/*=============================================================================
  评估：进程创建（PsSetCreateProcessNotifyRoutineEx 路径）
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估进程创建是否被规则阻断。

@param  OutCode  命中规则编号
@param  OutAction  命中规则要求的处置动作（DRG_ACTION_*）
--*/
BOOLEAN
DragonEvaluateProcessCreate(
    _In_ HANDLE CreatorPid,
    _In_ HANDLE ParentPid,
    _In_ HANDLE TargetPid,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ BOOLEAN FileOpenNameAvailable,
    _In_ BOOLEAN IsSubsystemProcess,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING CreatorPath;
    PUNICODE_STRING ParentPath;
    BOOLEAN ParentMismatch;
    BOOLEAN Blocked;
    ULONG Risk;
    ULONG SelectedPriority;
    BOOLEAN HasSelection;
    PDRG_RULE Rule;

    UNREFERENCED_PARAMETER(TargetPid);

    if (OutCode == NULL || OutAction == NULL || CreatorPid == NULL) {
        return FALSE;
    }

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (DragonIsProcessTrusted(CreatorPid) == TRUE) {
        return FALSE;
    }

    CreatorPath = NULL;
    ParentPath = NULL;

    (VOID)DragonGetProcessPath(CreatorPid, &CreatorPath);
    if (ParentPid != NULL) {
        (VOID)DragonGetProcessPath(ParentPid, &ParentPath);
    }

    ParentMismatch = (CreatorPid != NULL && ParentPid != NULL && CreatorPid != ParentPid) ? TRUE : FALSE;
    Risk = DragonRiskProcessCreate(CreatorPid, ParentPid, IsSubsystemProcess);

    Blocked = FALSE;
    HasSelection = FALSE;
    SelectedPriority = 0;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category != (ULONG)DrgCategoryProcess) {
            continue;
        }
        if ((Rule->Operations & DRG_OP_EXECUTE) == 0) {
            continue;
        }

        if (DragonTriStateMatches(Rule->ParentMismatch, ParentMismatch) == FALSE) {
            continue;
        }
        if (DragonTriStateMatches(Rule->FileOpenNameAvailable, FileOpenNameAvailable) == FALSE) {
            continue;
        }
        if (DragonTriStateMatches(Rule->SubsystemProcess, IsSubsystemProcess) == FALSE) {
            continue;
        }
        if (DragonRiskInRange(Rule, Risk) == FALSE) {
            continue;
        }

        if (DragonPatternListConflict(Rule->Initiator, Rule->InitiatorExclude, CreatorPath) == FALSE) {
            continue;
        }
        if (DragonPatternListConflict(Rule->Creator, Rule->CreatorExclude, CreatorPath) == FALSE) {
            continue;
        }
        if (DragonPatternListConflict(Rule->Parent, Rule->ParentExclude, ParentPath) == FALSE) {
            continue;
        }
        if (DragonPatternListConflict(Rule->Target, Rule->TargetExclude, TargetPath) == FALSE) {
            continue;
        }
        if (Rule->CommandLine != NULL &&
            DragonPatternListMatches(Rule->CommandLine, CommandLine) == FALSE) {
            continue;
        }
        if (Rule->CommandLineExclude != NULL &&
            DragonPatternListMatches(Rule->CommandLineExclude, CommandLine) == TRUE) {
            continue;
        }

        if (DragonMatchDirectParent(CreatorPid, Rule->InitiatorParent, Rule->InitiatorParentExclude) == FALSE) {
            continue;
        }
        if (DragonMatchProcessTree(CreatorPid, Rule->InitiatorTree, Rule->InitiatorTreeExclude) == FALSE) {
            continue;
        }
        if (DragonMatchProcessTree(ParentPid, Rule->TargetTree, Rule->TargetTreeExclude) == FALSE) {
            continue;
        }

        if (DragonBehaviorTick(
                CreatorPid,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == FALSE) {
            continue;
        }

        if (HasSelection == FALSE || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            SelectedPriority = Rule->Priority;
            HasSelection = TRUE;
        }

        Blocked = TRUE;
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(CreatorPath);
    DragonFreeProcessPath(ParentPath);

    return Blocked;
}

/*=============================================================================
  评估：进程 / 线程句柄访问（ObRegisterCallbacks 路径）
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估句柄访问；命中时把被拒操作位写入 DeniedOperations。

@return TRUE 表示存在命中规则（DeniedOperations 非 0 时调用方应剥离权限）。
--*/
BOOLEAN
DragonEvaluateProcessAccess(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ ULONG RequestedOperations,
    _In_ ULONG HandleType,
    _In_ ULONG ObjectType,
    _Out_ PULONG DeniedOperations,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING SourcePath;
    PUNICODE_STRING TargetPath;
    ULONG Risk;
    ULONG SelectedPriority;
    BOOLEAN Matched;
    BOOLEAN HasSelection;
    ULONG CategoryOperations;
    ULONG MatchedOperations;
    ULONG MemoryOperations;
    ULONG ControlOperations;
    PDRG_RULE Rule;

    if (DeniedOperations == NULL || OutCode == NULL || OutAction == NULL) {
        return FALSE;
    }

    *DeniedOperations = 0;
    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (SourcePid == NULL || TargetPid == NULL || RequestedOperations == 0) {
        return FALSE;
    }

    if (DragonIsProcessTrusted(SourcePid) == TRUE) {
        return FALSE;
    }

    SourcePath = NULL;
    TargetPath = NULL;

    (VOID)DragonGetProcessPath(SourcePid, &SourcePath);
    (VOID)DragonGetProcessPath(TargetPid, &TargetPath);

    Risk = DragonRiskAccess(RequestedOperations, HandleType, ObjectType);

    MemoryOperations =
        DRG_OP_VM_READ |
        DRG_OP_VM_WRITE |
        DRG_OP_VM_OPERATION |
        DRG_OP_CREATE_THREAD |
        DRG_OP_THREAD_SET_CONTEXT;

    ControlOperations =
        DRG_OP_THREAD_SET_TOKEN |
        DRG_OP_TERMINATE |
        DRG_OP_SUSPEND_RESUME |
        DRG_OP_DUP_HANDLE |
        DRG_OP_SET_INFORMATION |
        DRG_OP_CREATE_PROCESS |
        DRG_OP_IMPERSONATE;

    Matched = FALSE;
    HasSelection = FALSE;
    SelectedPriority = 0;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category == (ULONG)DrgCategoryMemory) {
            CategoryOperations = RequestedOperations & MemoryOperations;
        }
        else if (Rule->Category == (ULONG)DrgCategoryProcess) {
            CategoryOperations = RequestedOperations & ControlOperations;
        }
        else {
            continue;
        }

        if (CategoryOperations == 0) {
            continue;
        }

        MatchedOperations = DragonMatchedOperations(Rule, CategoryOperations);
        if (MatchedOperations == 0) {
            continue;
        }

        if (DragonMatchSourceTarget(
                Rule,
                SourcePid,
                TargetPid,
                SourcePath,
                TargetPath,
                HandleType,
                ObjectType,
                Risk) == FALSE) {
            continue;
        }

        if (DragonBehaviorTick(
                SourcePid,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == FALSE) {
            continue;
        }

        *DeniedOperations |= MatchedOperations;

        if (HasSelection == FALSE || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            SelectedPriority = Rule->Priority;
            HasSelection = TRUE;
        }

        Matched = TRUE;
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(SourcePath);
    DragonFreeProcessPath(TargetPath);

    return (Matched == TRUE && *DeniedOperations != 0) ? TRUE : FALSE;
}

/*=============================================================================
  评估：跨进程线程创建（内存区域分类）
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估跨进程线程是否命中 Thread 类别规则。
--*/
BOOLEAN
DragonEvaluateThread(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid,
    _In_ ULONG MemoryType,
    _In_ ULONG MemoryProtection,
    _In_ SIZE_T RegionSize,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING SourcePath;
    PUNICODE_STRING TargetPath;
    ULONG Risk;
    ULONG RequiredTypes;
    ULONG RequiredProtections;
    ULONG SelectedPriority;
    BOOLEAN Matched;
    BOOLEAN HasSelection;
    PDRG_RULE Rule;

    if (OutCode == NULL || OutAction == NULL) {
        return FALSE;
    }

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (SourcePid == NULL || TargetPid == NULL) {
        return FALSE;
    }

    if (DragonIsProcessTrusted(SourcePid) == TRUE) {
        return FALSE;
    }

    SourcePath = NULL;
    TargetPath = NULL;

    (VOID)DragonGetProcessPath(SourcePid, &SourcePath);
    (VOID)DragonGetProcessPath(TargetPid, &TargetPath);

    Risk = DragonRiskThread(MemoryType, MemoryProtection, RegionSize);
    Matched = FALSE;
    HasSelection = FALSE;
    SelectedPriority = 0;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category != (ULONG)DrgCategoryThread) {
            continue;
        }
        if ((Rule->Operations & DRG_OP_EXECUTE) == 0) {
            continue;
        }

        RequiredTypes = (Rule->ThreadMemoryTypes != 0)
                            ? Rule->ThreadMemoryTypes
                            : DRG_MEMORY_PRIVATE;
        RequiredProtections = (Rule->ThreadMemoryProtections != 0)
                                  ? Rule->ThreadMemoryProtections
                                  : DRG_PROTECT_EXECUTE;

        if ((RequiredTypes & MemoryType) == 0) {
            continue;
        }
        if ((RequiredProtections & MemoryProtection) == 0) {
            continue;
        }

        if (Rule->MinRegion > 0 && (ULONGLONG)RegionSize < Rule->MinRegion) {
            continue;
        }
        if (Rule->MaxRegion > 0 && (ULONGLONG)RegionSize > Rule->MaxRegion) {
            continue;
        }

        if (DragonMatchSourceTarget(
                Rule,
                SourcePid,
                TargetPid,
                SourcePath,
                TargetPath,
                DRG_HANDLE_CREATE,
                DRG_OBJECT_THREAD,
                Risk) == FALSE) {
            continue;
        }

        if (DragonBehaviorTick(
                SourcePid,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == FALSE) {
            continue;
        }

        if (HasSelection == FALSE || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            SelectedPriority = Rule->Priority;
            HasSelection = TRUE;
        }

        Matched = TRUE;
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(SourcePath);
    DragonFreeProcessPath(TargetPath);

    return Matched;
}

/*=============================================================================
  评估：模块加载
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估镜像加载是否命中 Process 类别 + ImageLoad 操作位规则。
--*/
BOOLEAN
DragonEvaluateImageLoad(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_opt_ PIMAGE_INFO ImageInfo,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING ProcessPath;
    ULONG SelectedPriority;
    BOOLEAN Matched;
    BOOLEAN HasSelection;
    PDRG_RULE Rule;

    if (OutCode == NULL || OutAction == NULL) {
        return FALSE;
    }

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (ProcessId == NULL || ImagePath == NULL || ImagePath->Buffer == NULL || ImageInfo == NULL) {
        return FALSE;
    }

    ProcessPath = NULL;
    (VOID)DragonGetProcessPath(ProcessId, &ProcessPath);

    Matched = FALSE;
    HasSelection = FALSE;
    SelectedPriority = 0;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category != (ULONG)DrgCategoryProcess) {
            continue;
        }
        if ((Rule->Operations & DRG_OP_IMAGE_LOAD) == 0) {
            continue;
        }

        if (DragonPatternListConflict(Rule->Initiator, Rule->InitiatorExclude, ProcessPath) == FALSE) {
            continue;
        }
        if (DragonPatternListConflict(Rule->Target, Rule->TargetExclude, ImagePath) == FALSE) {
            continue;
        }

        if (DragonMatchDirectParent(ProcessId, Rule->InitiatorParent, Rule->InitiatorParentExclude) == FALSE) {
            continue;
        }
        if (DragonMatchProcessTree(ProcessId, Rule->InitiatorTree, Rule->InitiatorTreeExclude) == FALSE) {
            continue;
        }
        if (DragonMatchProcessTree(ProcessId, Rule->TargetTree, Rule->TargetTreeExclude) == FALSE) {
            continue;
        }

        if (Rule->MinRegion > 0 && (ULONGLONG)ImageInfo->ImageSize < Rule->MinRegion) {
            continue;
        }
        if (Rule->MaxRegion > 0 && (ULONGLONG)ImageInfo->ImageSize > Rule->MaxRegion) {
            continue;
        }

        if (DragonBehaviorTick(
                ProcessId,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == FALSE) {
            continue;
        }

        if (HasSelection == FALSE || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            SelectedPriority = Rule->Priority;
            HasSelection = TRUE;
        }

        Matched = TRUE;
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(ProcessPath);

    return Matched;
}

/*=============================================================================
  评估：文件操作
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估文件操作是否命中 File 类别规则。

@note  与进程/内存类不同，文件规则不引入优先级比较——首个命中即生效。
--*/
BOOLEAN
DragonEvaluateFile(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_ ULONG Operation,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING InitiatorPath;
    BOOLEAN Blocked;
    BOOLEAN Match;
    PDRG_RULE Rule;

    if (OutCode == NULL || OutAction == NULL) {
        return FALSE;
    }

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (DragonIsProcessTrusted(ProcessId) == TRUE) {
        return FALSE;
    }

    InitiatorPath = NULL;
    (VOID)DragonGetProcessPath(ProcessId, &InitiatorPath);

    Blocked = FALSE;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category != (ULONG)DrgCategoryFile) {
            continue;
        }
        if ((Rule->Operations & Operation) == 0) {
            continue;
        }

        Match = DragonPatternListConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath);
        if (Match == TRUE) {
            Match = DragonPatternListConflict(Rule->Target, Rule->TargetExclude, TargetPath);
        }
        if (Match == TRUE && Rule->Extensions != NULL) {
            Match = DragonExtensionMatches(Rule->Extensions, TargetPath);
        }

        if (Match == TRUE &&
            DragonBehaviorTick(
                ProcessId,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == TRUE) {

            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            Blocked = TRUE;
            break;
        }
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(InitiatorPath);

    return Blocked;
}

/*=============================================================================
  评估：注册表操作
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估注册表操作是否命中 Registry 类别规则。

@param  ValueName 本次操作涉及的值名；键级操作（建键 / 删键）传 NULL。
--*/
BOOLEAN
DragonEvaluateRegistry(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ ULONG Operation,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING InitiatorPath;
    BOOLEAN Blocked;
    BOOLEAN Match;
    PDRG_RULE Rule;

    if (OutCode == NULL || OutAction == NULL) {
        return FALSE;
    }

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (DragonIsProcessTrusted(ProcessId) == TRUE) {
        return FALSE;
    }

    InitiatorPath = NULL;
    (VOID)DragonGetProcessPath(ProcessId, &InitiatorPath);

    Blocked = FALSE;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category != (ULONG)DrgCategoryRegistry) {
            continue;
        }
        if ((Rule->Operations & Operation) == 0) {
            continue;
        }

        Match = DragonPatternListConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath);
        if (Match == TRUE) {
            Match = DragonPatternListConflict(Rule->Target, Rule->TargetExclude, KeyPath);
        }

        /*
         * 值名维度（第二层约束）。
         *
         * 规则声明了 ValueNames 时，本次操作必须带值名且命中其中之一 ——
         * 键级操作（建键 / 删键）没有值名，直接判为不命中。
         *
         * 为什么需要这一层：同一个 Services\<名称> 键下，改 ImagePath 是服务后门，
         * 而改其它值很可能只是软件在写自己的配置。只靠键路径通配符，要么整键
         * 拦截（误报高），要么放任真后门（漏报）。把值名单独作为可声明的约束，
         * 规则才能精确到「哪个键的哪个值」。
         */
        if (Match == TRUE && Rule->ValueNames != NULL) {
            Match = (ValueName != NULL && ValueName->Buffer != NULL && ValueName->Length > 0)
                        ? DragonPatternListMatches(Rule->ValueNames, ValueName)
                        : FALSE;
        }

        if (Match == TRUE &&
            DragonBehaviorTick(
                ProcessId,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == TRUE) {

            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            Blocked = TRUE;
            break;
        }
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(InitiatorPath);

    return Blocked;
}

/*=============================================================================
  评估：裸设备 IOCTL
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估设备控制操作是否命中 Device 类别规则。
--*/
BOOLEAN
DragonEvaluateDevice(
    _In_ HANDLE ProcessId,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    PUNICODE_STRING InitiatorPath;
    BOOLEAN Blocked;
    PDRG_RULE Rule;

    if (OutCode == NULL || OutAction == NULL) {
        return FALSE;
    }

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    if (DragonIsProcessTrusted(ProcessId) == TRUE) {
        return FALSE;
    }

    InitiatorPath = NULL;
    (VOID)DragonGetProcessPath(ProcessId, &InitiatorPath);

    Blocked = FALSE;

    DragonRulesAcquireShared();

    for (Rule = DragonRulesHead(); Rule != NULL; Rule = Rule->Next) {

        if (Rule->Category != (ULONG)DrgCategoryDevice) {
            continue;
        }
        if ((Rule->Operations & DRG_OP_IOCTL) == 0) {
            continue;
        }

        if (DragonPatternListConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath) == FALSE) {
            continue;
        }

        if (DragonBehaviorTick(
                ProcessId,
                DragonCurrentCreateTime(),
                Rule->Code,
                Rule->Threshold,
                Rule->TimeWindow) == TRUE) {

            *OutCode = Rule->Code;
            *OutAction = DragonRuleAction(Rule);
            Blocked = TRUE;
            break;
        }
    }

    DragonRulesReleaseShared();

    DragonFreeProcessPath(InitiatorPath);

    return Blocked;
}
