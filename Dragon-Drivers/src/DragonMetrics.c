/*++
===============================================================================
 Dragon-Drivers / DragonMetrics.c

 诊断统计：把「内核回调到底有没有被调用、规则有没有命中、处置有没有落地」
 变成可查询的数字。

 动机很实际：实机排障时最难回答的问题不是「为什么拦了」，而是「为什么没拦」
 —— 是回调压根没触发？还是规则没匹配上？还是匹配上了但处置失败？
 没有计数器就只能靠 DbgPrint 一行行猜。这里把每个回调的进入次数、每次判定的
 结果、以及最近一次动作的完整快照都记下来，一条命令就能看清链路走到哪一步。

 计数全部用 Interlocked 累加，任何 IRQL 下都可调用；
 只有「最近动作快照」需要写字符串，用自旋锁保护。
===============================================================================
--*/

#include "DragonCommon.h"

/*=============================================================================
  静态状态
=============================================================================*/

typedef struct _DRG_METRICS_STATE {
    KSPIN_LOCK     Lock;
    volatile LONG64 Counters[DrgMetricCount];
    volatile LONG   LastCallbackKind;
    volatile LONG   LastRuleCode;
    volatile LONG   LastAction;
    volatile LONG   LastProcessId;
    WCHAR           LastPath[DRG_BACKUP_PATH_CHARS];
    BOOLEAN         Ready;
} DRG_METRICS_STATE;

static DRG_METRICS_STATE g_Metrics;

/*=============================================================================
  对外接口
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 初始化统计模块。必须在任何回调注册之前调用。
--*/
VOID
DragonMetricsInitialize(
    VOID
    )
{
    KeInitializeSpinLock(&g_Metrics.Lock);

    RtlZeroMemory((PVOID)g_Metrics.Counters, sizeof(g_Metrics.Counters));
    RtlZeroMemory(g_Metrics.LastPath, sizeof(g_Metrics.LastPath));

    g_Metrics.LastCallbackKind = (LONG)DRG_METRIC_CB_NONE;
    g_Metrics.LastRuleCode = 0;
    g_Metrics.LastAction = (LONG)DRG_ACTION_REPORT;
    g_Metrics.LastProcessId = 0;

    /* 事件通道的计数在 DragonResponse 里维护，这里只做视图映射 */
    g_Metrics.Ready = TRUE;
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 计数器累加。用 Interlocked 实现，无需加锁。
--*/
VOID
DragonMetricsBump(
    _In_ ULONG Counter,
    _In_ ULONGLONG Delta
    )
{
    if (Counter >= (ULONG)DrgMetricCount) {
        return;
    }

    if (Delta == 0) {
        Delta = 1;
    }

    (VOID)InterlockedExchangeAdd64(&g_Metrics.Counters[Counter], (LONG64)Delta);
}

/*++
@IRQL: <= APC_LEVEL
@brief 记录「最近一次动作」快照（不改变计数器）。

        快照只保留最后一条：排障时想看的是「最新一次判定到底怎么走的」，
        保留历史需要环形缓冲与额外内存，收益不划算。
--*/
VOID
DragonMetricsRecordLast(
    _In_ ULONG CallbackKind,
    _In_ ULONG RuleCode,
    _In_ ULONG Action,
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING Path
    )
{
    KIRQL OldIrql;
    ULONG Chars;

    if (g_Metrics.Ready == FALSE) {
        return;
    }

    KeAcquireSpinLock(&g_Metrics.Lock, &OldIrql);

    g_Metrics.LastCallbackKind = (LONG)CallbackKind;
    g_Metrics.LastRuleCode = (LONG)RuleCode;
    g_Metrics.LastAction = (LONG)Action;
    g_Metrics.LastProcessId = (LONG)(ULONG_PTR)ProcessId;

    if (Path != NULL && Path->Buffer != NULL && Path->Length > 0) {

        Chars = (ULONG)(Path->Length / sizeof(WCHAR));

        if (Chars > DRG_BACKUP_PATH_CHARS - 1) {
            Chars = DRG_BACKUP_PATH_CHARS - 1;
        }

        RtlCopyMemory(g_Metrics.LastPath, Path->Buffer, Chars * sizeof(WCHAR));
        g_Metrics.LastPath[Chars] = L'\0';
    }
    else {
        g_Metrics.LastPath[0] = L'\0';
    }

    KeReleaseSpinLock(&g_Metrics.Lock, OldIrql);
}

/*++
@IRQL: <= APC_LEVEL
@brief 填充统计快照。

        非计数器类的字段（规则条数、生效保护条目数、事件通道计数）在调用时
        现取，保证快照与其它查询命令看到的是同一时刻的状态。
--*/
VOID
DragonMetricsQuery(
    _Out_ PDRG_METRICS Metrics
    )
{
    KIRQL OldIrql;
    ULONG Index;
    ULONG RuleCount;

    if (Metrics == NULL) {
        return;
    }

    RtlZeroMemory(Metrics, sizeof(*Metrics));

    Metrics->ProtocolVersion = DRG_PROTOCOL_VERSION;
    Metrics->DriverState = (ULONG)DragonStateGet();
    Metrics->GuardPathCount = DragonSelfProtectGuardPathCount();

    RuleCount = 0;

    DragonRulesAcquireShared();

    {
        PDRG_RULE Rule;

        Rule = DragonRulesHead();

        while (Rule != NULL) {
            RuleCount++;
            Rule = Rule->Next;
        }
    }

    DragonRulesReleaseShared();

    Metrics->RuleCount = RuleCount;

    KeAcquireSpinLock(&g_Metrics.Lock, &OldIrql);

    for (Index = 0; Index < (ULONG)DrgMetricCount; Index++) {

        ULONGLONG Value;

        Value = (ULONGLONG)InterlockedCompareExchange64(&g_Metrics.Counters[Index], 0, 0);

        switch ((DRG_METRIC_COUNTER)Index) {

            case DrgMetricProcessCreate:   Metrics->ProcessCreateCalls = Value; break;
            case DrgMetricProcessAccess:   Metrics->ProcessAccessCalls = Value; break;
            case DrgMetricThreadCreate:    Metrics->ThreadCreateCalls = Value;  break;
            case DrgMetricImageLoad:       Metrics->ImageLoadCalls = Value;     break;
            case DrgMetricFileCreate:      Metrics->FileCreateCalls = Value;    break;
            case DrgMetricFileWrite:       Metrics->FileWriteCalls = Value;     break;
            case DrgMetricFileSetInfo:     Metrics->FileSetInfoCalls = Value;   break;
            case DrgMetricRegistry:        Metrics->RegistryCalls = Value;      break;
            case DrgMetricDeviceIoctl:     Metrics->DeviceIoctlCalls = Value;   break;

            case DrgMetricRulesEvaluated:  Metrics->RulesEvaluated = Value;     break;
            case DrgMetricRulesHit:        Metrics->RulesHit = Value;           break;
            case DrgMetricBlocked:         Metrics->Blocked = Value;            break;
            case DrgMetricTerminated:      Metrics->Terminated = Value;         break;
            case DrgMetricSelfProtectHits: Metrics->SelfProtectHits = Value;    break;
            case DrgMetricRansomBlocks:    Metrics->RansomBlocks = Value;       break;
            case DrgMetricRansomBackups:   Metrics->RansomBackups = Value;      break;
            case DrgMetricRansomRestores:  Metrics->RansomRestores = Value;     break;
            case DrgMetricTrustCacheHits:  Metrics->TrustCacheHits = Value;     break;

            default:
                break;
        }
    }

    Metrics->LastCallbackKind = (ULONG)g_Metrics.LastCallbackKind;
    Metrics->LastRuleCode = (ULONG)g_Metrics.LastRuleCode;
    Metrics->LastAction = (ULONG)g_Metrics.LastAction;
    Metrics->LastProcessId = (ULONG)g_Metrics.LastProcessId;

    RtlCopyMemory(Metrics->LastPath, g_Metrics.LastPath, sizeof(Metrics->LastPath));

    KeReleaseSpinLock(&g_Metrics.Lock, OldIrql);

    /* 事件通道计数由响应模块维护，这里直接取，避免两处各存一份 */
    Metrics->EventsReported =
        (ULONGLONG)InterlockedCompareExchange64(&g_Dragon.EventsReported, 0, 0);
    Metrics->EventsDropped =
        (ULONGLONG)InterlockedCompareExchange64(&g_Dragon.EventsDropped, 0, 0);
}
