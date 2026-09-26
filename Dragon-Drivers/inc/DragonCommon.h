/*++
===============================================================================
 Dragon-Drivers / DragonCommon.h

 天龙神盾 内核防护驱动 —— 内核态内部公共头。

 开发框架 : KMDF 1.31 + Filter Manager (minifilter)
 语言     : 纯 C
 目标系统 : Windows 10 20H2 ~ Windows 11 24H2  (x64)
 规范依据 : KMDF驱动开发强制规范
             · 每个函数头注释标注运行 IRQL
             · DPC/DISPATCH 只用 NonPagedPoolNx
             · 统一 ExAllocatePool2 + PoolTag
             · WDF 对象依靠父对象回收，禁止手动 free
             · WdfRequestComplete 仅一次
             · 定时器/工作项必须在设备卸载前停止
             · 指针 / WDF 句柄解引用前必须判 NULL
             · 资源失败分支统一 goto 清理

 同步原语选型说明（规范「同步锁规范」的落地方式）：
   · WDFWAITLOCK —— 仅用于「确定处于 PASSIVE_LEVEL」的连接状态簿记路径。
   · ERESOURCE   —— 用于规则数据库。原因：Filter Manager / 配置管理器回调
                     允许在 APC_LEVEL 运行，而 WdfWaitLockAcquire 官方要求
                     PASSIVE_LEVEL，用 WDFWAITLOCK 会在合法 IRQL 上触发断言。
                     ExAcquireResourceExclusiveLite 配合 KeEnterCriticalRegion
                     是微软为 <= APC_LEVEL 读写场景设计的原语，属官方文档化 API。
   · KSPIN_LOCK  —— 仅用于 DISPATCH_LEVEL 可达的小结构（作业链表、进程关系表、
                     信任缓存、行为统计），临界区内不做任何分页访问与阻塞调用。
===============================================================================
--*/

#ifndef _DRAGON_COMMON_H_
#define _DRAGON_COMMON_H_

#define DRG_KERNEL_MODE 1

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "DragonProtocol.h"

/*-----------------------------------------------------------------------------
  池标签与常量
-----------------------------------------------------------------------------*/
#define DRG_POOL_TAG            'DRGN'      /* 0x4E475244 */
#define DRG_OB_ALTITUDE         L"328900.0001"
#define DRG_REG_ALTITUDE        L"328900.0002"

/* 事件上报超时（100ns 单位）：PASSIVE_LEVEL 下最多等待 5 秒 */
#define DRG_EVENT_TIMEOUT_100NS (5LL * 1000 * 10000)

/* 工作项排空单轮上限，避免长时间占用工作线程 */
#define DRG_DRAIN_BATCH_LIMIT   64u

/* 卸载时等待工作项收敛的轮询间隔（100ns），10 毫秒 */
#define DRG_SHUTDOWN_POLL_100NS (10LL * 1000)

/* 卸载时等待工作项收敛的最大轮次 */
#define DRG_SHUTDOWN_MAX_POLLS  200u

/* 规则评估用的进程路径缓冲（WCHAR 数） */
#define DRG_PROC_PATH_CHARS     1024

/* 命令 Path 字段允许的最大长度（WCHAR 数，不含 NUL） */
#define DRG_COMMAND_MAX_CHARS   (DRG_PATH_CHARS - 1)

/* MEM_IMAGE 未由内核头文件提供，按官方 MEMORY_BASIC_INFORMATION 文档取值补全 */
#define DRG_MEM_IMAGE_TYPE      0x01000000UL

/*-----------------------------------------------------------------------------
  进程 / 线程访问权限位
  内核头文件（wdm.h / ntddk.h / ntifs.h）不提供这些常量（它们属于 winnt.h），
  这里按官方文档值补全，并以 ifndef 保护避免与第三方头文件冲突。
-----------------------------------------------------------------------------*/
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                 (0x0001)
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD             (0x0002)
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION              (0x0008)
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                   (0x0010)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                  (0x0020)
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE                (0x0040)
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS            (0x0080)
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA                 (0x0100)
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION           (0x0200)
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION         (0x0400)
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME            (0x0800)
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                  (0x0001)
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME             (0x0002)
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION          (0x0040)
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT                (0x0010)
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION            (0x0020)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN           (0x0080)
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE                (0x0100)
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION       (0x0200)
#endif

/*-----------------------------------------------------------------------------
  前向声明
-----------------------------------------------------------------------------*/
typedef struct _DRG_RULE      DRG_RULE, *PDRG_RULE;
typedef struct _DRG_PATTERN   DRG_PATTERN, *PDRG_PATTERN;

/*-----------------------------------------------------------------------------
  作业类型
-----------------------------------------------------------------------------*/
typedef enum _DRG_JOB_KIND {
    DrgJobThreadScan   = 1,   /* 跨进程线程创建 -> 分析线程起始地址所在内存 */
    DrgJobTerminate    = 2,   /* 处置：终止目标进程 */
    DrgJobReport       = 3,   /* 处置：仅上报事件给用户态 */
    DrgJobAccessReport = 4    /* 处置：句柄访问被降权上报（目标路径在工作项中解析） */
} DRG_JOB_KIND;

/* 作业节点：携带发起进程身份（创建时间），执行时比对，避免 PID 复用误伤 */
typedef struct _DRG_JOB {
    LIST_ENTRY  Link;
    ULONG       Kind;
    ULONG       RuleCode;
    ULONG       Action;         /* DRG_ACTION_* */
    HANDLE      SourcePid;
    HANDLE      TargetPid;
    HANDLE      ThreadId;
    LARGE_INTEGER TargetCreateTime;
    USHORT      PathBytes;      /* Path 中有效字节数，不含结尾 NUL */
    USHORT      Reserved;
    PEPROCESS   SourceProcess;  /* 仅线程分析作业持有，由作业释放时归还引用 */
    PEPROCESS   TargetProcess;
    WCHAR       Path[1];
} DRG_JOB, *PDRG_JOB;

#define DRG_JOB_HEADER_SIZE  FIELD_OFFSET(DRG_JOB, Path)

/*-----------------------------------------------------------------------------
  规则：通配符模式链表节点
-----------------------------------------------------------------------------*/
struct _DRG_PATTERN {
    struct _DRG_PATTERN *Next;
    UNICODE_STRING       Text;
};

/*-----------------------------------------------------------------------------
  规则：动态规则条目
  字段语义与规则 JSON 一一对应；未出现的键保持 0 / DrgTriAny。
-----------------------------------------------------------------------------*/
struct _DRG_RULE {
    /* --- 基本属性 --- */
    ULONG            Code;
    BOOLEAN          Kill;              /* 旧版字段，Action 未指定时用于推断处置 */
    ULONG            Action;            /* DRG_ACTION_*，默认 DRG_ACTION_UNSET */
    ULONG            Priority;
    ULONG            Category;          /* DRG_CATEGORY */
    ULONG            Operations;        /* DRG_OP_* 位或 */
    ULONG            OperationMatch;    /* DRG_OPERATION_MATCH */
    BOOLEAN          Invalid;

    /* --- 通配符模式表（Include / Exclude 成对） --- */
    PDRG_PATTERN     Initiator;
    PDRG_PATTERN     InitiatorExclude;
    PDRG_PATTERN     InitiatorParent;
    PDRG_PATTERN     InitiatorParentExclude;
    PDRG_PATTERN     InitiatorTree;
    PDRG_PATTERN     InitiatorTreeExclude;
    PDRG_PATTERN     Target;
    PDRG_PATTERN     TargetExclude;
    PDRG_PATTERN     TargetTree;
    PDRG_PATTERN     TargetTreeExclude;
    PDRG_PATTERN     Creator;
    PDRG_PATTERN     CreatorExclude;
    PDRG_PATTERN     Parent;
    PDRG_PATTERN     ParentExclude;
    PDRG_PATTERN     CommandLine;
    PDRG_PATTERN     CommandLineExclude;
    PDRG_PATTERN     Extensions;

    /*
     * 注册表值名匹配（第二层约束）。
     *
     * 键路径通配符只能表达「哪个键被碰」，而真正决定风险的是「哪个值被改」：
     * 同一个 Services\<名称> 键下，改 ImagePath 是服务后门，改其他值可能只是
     * 正常软件在写自己的配置。没有这一层就只能整键拦截，误报压不下来。
     *
     * 语义：非空时必须命中其中之一；为空则退化为纯键级匹配（旧规则包行为不变）。
     */
    PDRG_PATTERN     ValueNames;

    /* --- 数值约束 --- */
    ULONG            HandleTypes;       /* DRG_HANDLE_* 位或，0 = 不限 */
    ULONG            ObjectTypes;       /* DRG_OBJECT_* 位或，0 = 不限 */
    ULONG            MinRisk;
    ULONG            MaxRisk;
    ULONG            ThreadMemoryTypes;       /* DRG_MEMORY_* 位或 */
    ULONG            ThreadMemoryProtections; /* DRG_PROTECT_* 位或 */
    ULONGLONG        MinRegion;
    ULONGLONG        MaxRegion;
    ULONG            ParentMismatch;          /* DRG_TRI */
    ULONG            FileOpenNameAvailable;   /* DRG_TRI */
    ULONG            SubsystemProcess;        /* DRG_TRI */

    /* --- 频率阈值 --- */
    ULONG            Threshold;
    ULONG            TimeWindow;        /* 毫秒 */

    struct _DRG_RULE *Next;
};

/*-----------------------------------------------------------------------------
  进程信任缓存条目（只存 PID + 创建时间，不持有 EPROCESS 指针，
  彻底规避 Use-After-Free）
-----------------------------------------------------------------------------*/
typedef struct _DRG_TRUST_ENTRY {
    HANDLE        Pid;
    LARGE_INTEGER CreateTime;
    BOOLEAN       Trusted;
    LARGE_INTEGER Stamp;
} DRG_TRUST_ENTRY, *PDRG_TRUST_ENTRY;

/* 行为频率统计槽位（只存 PID + 规则编号，不持有指针） */
typedef struct _DRG_BEHAVIOR_SLOT {
    HANDLE        Pid;
    LARGE_INTEGER CreateTime;
    ULONG         RuleCode;
    ULONG         Count;
    LARGE_INTEGER LastActivity;
} DRG_BEHAVIOR_SLOT, *PDRG_BEHAVIOR_SLOT;

/* 进程关系缓存条目 */
typedef struct _DRG_RELATION_ENTRY {
    HANDLE        ProcessId;
    HANDLE        ParentProcessId;
    HANDLE        CreatorProcessId;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ParentCreateTime;
    ULONGLONG     Sequence;
} DRG_RELATION_ENTRY, *PDRG_RELATION_ENTRY;

/*-----------------------------------------------------------------------------
  驱动全局数据
-----------------------------------------------------------------------------*/
typedef struct _DRG_DRIVER_DATA {
    /* 框架 / 过滤句柄 */
    PDRIVER_OBJECT   DriverObject;
    WDFDRIVER        WdfDriver;
    WDFDEVICE        ControlDevice;      /* 非 PnP KMDF 驱动必备；同时作为工作项父对象 */
    PFLT_FILTER      FilterHandle;

    /* 通信端口 */
    PFLT_PORT        ServerPort;
    PFLT_PORT        ClientPort;
    /*
     * 连接状态锁：使用 WDFSPINLOCK 而非 WDFWAITLOCK。
     *
     * 原因：Filter Manager 的连接/断开回调在官方文档中并未保证一定处于
     * PASSIVE_LEVEL（消息回调更是可能在 APC_LEVEL 之上被调用），而
     * WdfWaitLockAcquire 的官方 IRQL 约束是 PASSIVE_LEVEL——在合法 IRQL 上
     * 误用会直接触发 KMDF 断言（蓝屏）。这里改成自旋锁后，临界区可在任意
     * <= DISPATCH_LEVEL 的上下文安全进入。
     *
     * 代价必须由代码保证：临界区内只做「指针 / PID 原子交换」，
     * 绝不做分页内存访问、绝不调用可阻塞例程。
     */
    WDFSPINLOCK      ConnectionLock;
    volatile LONG    ClientPid;
    LARGE_INTEGER    ClientCreateTime;      /* 客户端进程创建时间：防 PID 复用后被冒名保护 */
    volatile LONG    PortAccepting;
    volatile LONG    ClientClosing;
    EX_RUNDOWN_REF   PortRundown;
    volatile LONG    PortRundownReleased;   /* ExWaitForRundownProtectionRelease 只允许调用一次 */
    KEVENT           ShutdownEvent;

    /* 状态机 */
    volatile LONG    DriverState;
    volatile LONG    UnloadAuthorized;

    /* 自我识别：允许连接 / 免检的客户端镜像路径 */
    UNICODE_STRING   ClientImagePath;
    WCHAR            ClientImageBuffer[DRG_PATH_CHARS];

    /* 其他内核回调句柄 */
    PVOID            ObRegistrationHandle;

    /* 规则引擎 */
    BOOLEAN          Initialized;
    BOOLEAN          RulesEngineReady;
    BOOLEAN          RulesLoadedFromDisk;
    BOOLEAN          ClientIdentityReady;

    /* 各子系统注册状态（用于幂等清理） */
    BOOLEAN          ProcessNotifyRegistered;
    BOOLEAN          ThreadNotifyRegistered;
    BOOLEAN          ImageNotifyRegistered;
    BOOLEAN          RegistryCallbackRegistered;
    BOOLEAN          ProcessGuardReady;
    BOOLEAN          ObjectGuardReady;
    BOOLEAN          BootGuardReady;

    /* 工作项 / 作业队列 */
    WDFWORKITEM      DrainWorkItem;
    LIST_ENTRY       JobQueue;
    KSPIN_LOCK       JobLock;
    volatile LONG    JobCount;
    volatile LONG    DrainScheduled;
    volatile LONG    EnqueueActive;   /* 在途入队临界区计数，卸载时用于收敛判定 */
    volatile LONG    Shutdown;

    /* 诊断计数 */
    volatile LONG64  EventsReported;
    volatile LONG64  EventsDropped;
} DRG_DRIVER_DATA, *PDRG_DRIVER_DATA;

extern DRG_DRIVER_DATA g_Dragon;

/*=============================================================================
  模块：DragonSupport.c
  通用工具（池分配、IRQL 查询、字符串、通配符、时间）
=============================================================================*/
/* @IRQL: <= DISPATCH_LEVEL —— 仅 ExAllocatePool2(NON_PAGED) */
PVOID DragonAllocate(SIZE_T Size);
/* @IRQL: <= DISPATCH_LEVEL */
VOID DragonFree(PVOID Pointer);
/* @IRQL: 任意 —— 判断当前是否处于可分页 IRQL */
BOOLEAN DragonAtPassiveLevel(VOID);
/* @IRQL: 任意 —— 取当前系统时间（100ns） */
LARGE_INTEGER DragonNow(VOID);
/* @IRQL: <= DISPATCH_LEVEL —— 毫秒转 100ns 相对值 */
LONGLONG DragonMillisecondsToRelative(ULONG Milliseconds);
/* @IRQL: <= DISPATCH_LEVEL —— 复制并截断路径字符串，返回有效字节数 */
USHORT DragonCopyPath(PWCHAR Destination, ULONG DestinationChars, PCWSTR Source, USHORT SourceBytes);
/* @IRQL: <= APC_LEVEL —— ASCII 大小写不敏感等值比较 */
BOOLEAN DragonAnsiEqualNoCase(PCSTR Left, PCSTR Right);
/* @IRQL: <= APC_LEVEL —— 宽字符串长度（不含结尾 NUL） */
ULONG DragonWideLength(PCWSTR Text);
/* @IRQL: <= APC_LEVEL —— 宽字符串大小写不敏感前缀判断 */
BOOLEAN DragonWideStartsWithNoCase(PCWSTR Text, PCWSTR Prefix);
/* @IRQL: <= APC_LEVEL —— 通配符匹配（大小写不敏感，* 与 ?） */
BOOLEAN DragonWildcardMatch(PCWSTR Pattern, PCWSTR Text, USHORT TextBytes);
/* @IRQL: <= APC_LEVEL —— 通配符模式的特异性评分（非通配字符数 + 1） */
ULONG DragonPatternSpecificity(PCUNICODE_STRING Pattern);
/* @IRQL: <= APC_LEVEL —— 文本是否以某后缀结尾（大小写不敏感） */
BOOLEAN DragonHasSuffix(PCUNICODE_STRING Text, PCWSTR Suffix);

/*=============================================================================
  模块：DragonJson.c
  最小 JSON 扫描器：仅支持规则文件所需的子集
=============================================================================*/
typedef struct _DRG_JSON_CURSOR {
    PCSTR  Begin;
    PCSTR  End;
    PCSTR  Current;
} DRG_JSON_CURSOR, *PDRG_JSON_CURSOR;

/* @IRQL: <= APC_LEVEL */
VOID    DragonJsonInit(PDRG_JSON_CURSOR Cursor, PCSTR Buffer, ULONG Length);
/* @IRQL: <= APC_LEVEL —— 跳过空白 */
VOID    DragonJsonSkipSpace(PDRG_JSON_CURSOR Cursor);
/* @IRQL: <= APC_LEVEL —— 读取无符号数（十进制或 0x 十六进制） */
ULONGLONG DragonJsonReadUInt64(PDRG_JSON_CURSOR Cursor);
/* @IRQL: <= APC_LEVEL —— 读取 ULONG，溢出饱和 */
ULONG   DragonJsonReadUInt32(PDRG_JSON_CURSOR Cursor);
/* @IRQL: <= APC_LEVEL —— 读取 true/false，成功返回 TRUE */
BOOLEAN DragonJsonReadBoolean(PDRG_JSON_CURSOR Cursor, PBOOLEAN Value);
/* @IRQL: <= APC_LEVEL —— 读取带引号字符串（不处理转义），缓冲不足即失败 */
BOOLEAN DragonJsonReadRawString(PDRG_JSON_CURSOR Cursor, PCHAR Buffer, ULONG BufferChars);
/* @IRQL: <= APC_LEVEL —— 取当前字符，越界返回 0 */
CHAR    DragonJsonPeek(PDRG_JSON_CURSOR Cursor);
/* @IRQL: <= APC_LEVEL —— 跳过任意一个 JSON 值（含嵌套数组/对象） */
VOID    DragonJsonSkipValue(PDRG_JSON_CURSOR Cursor);
/* @IRQL: <= APC_LEVEL —— 定位 "Key" 后紧跟的 ':' 并跳过，成功返回 TRUE */
BOOLEAN DragonJsonSeekKey(PDRG_JSON_CURSOR Cursor, PCSTR Key);
/* @IRQL: <= APC_LEVEL —— JSON 反转义（就地）并返回新字节数 */
ULONG   DragonJsonUnescape(PWCHAR Buffer, ULONG Chars);

/*=============================================================================
  模块：DragonRules.c
  规则数据库：存储、通配符表构建、解析、加载、白名单
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonRulesInitialize(VOID);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonRulesTeardown(VOID);
/* @IRQL: <= APC_LEVEL —— 追加一个模式（去重） */
VOID     DragonPatternListAdd(PDRG_PATTERN *Head, PCUNICODE_STRING Text);
/* @IRQL: <= APC_LEVEL —— 删除匹配的模式 */
VOID     DragonPatternListRemove(PDRG_PATTERN *Head, PCUNICODE_STRING Text);
/* @IRQL: <= APC_LEVEL —— 模式链表中是否存在任一命中 */
BOOLEAN  DragonPatternListMatches(PDRG_PATTERN Head, PCUNICODE_STRING Text);
/* @IRQL: <= APC_LEVEL —— Include / Exclude 特异性裁决 */
BOOLEAN  DragonPatternListConflict(PDRG_PATTERN Include, PDRG_PATTERN Exclude, PCUNICODE_STRING Text);
/* @IRQL: <= APC_LEVEL */
VOID     DragonPatternListFree(PDRG_PATTERN *Head);
/* @IRQL: <= APC_LEVEL —— 释放整条规则 */
VOID     DragonRuleFree(PDRG_RULE Rule);
/* @IRQL: PASSIVE_LEVEL —— 解析 JSON 文本并追加规则，返回新增条数 */
ULONG    DragonRulesParseJson(PCSTR Buffer, ULONG Length);
/* @IRQL: PASSIVE_LEVEL —— 从 NT 路径加载规则文件 */
NTSTATUS DragonRulesLoadFile(PCUNICODE_STRING FilePath);
/* @IRQL: PASSIVE_LEVEL —— 依据驱动 ImagePath 推导路径并加载 */
NTSTATUS DragonRulesLoadFromDisk(PUNICODE_STRING RegistryPath);
/* @IRQL: PASSIVE_LEVEL —— 清空动态规则与行为统计 */
VOID     DragonRulesClear(VOID);
/* @IRQL: PASSIVE_LEVEL —— 白名单增删 */
VOID     DragonTrustedAdd(PUNICODE_STRING Pattern);
VOID     DragonTrustedRemove(PUNICODE_STRING Pattern);
/* @IRQL: <= APC_LEVEL —— 判定进程是否受信任 */
BOOLEAN  DragonIsProcessTrusted(HANDLE ProcessId);
/* @IRQL: <= DISPATCH_LEVEL —— 清空信任缓存 */
VOID     DragonTrustCacheReset(VOID);
/* @IRQL: PASSIVE_LEVEL —— 客户端镜像路径登记 */
NTSTATUS DragonClientIdentityLoad(PUNICODE_STRING RegistryPath);
/* @IRQL: <= APC_LEVEL —— 规则链表遍历（必须成对使用） */
VOID      DragonRulesAcquireShared(VOID);
VOID      DragonRulesReleaseShared(VOID);
PDRG_RULE DragonRulesHead(VOID);

/*=============================================================================
  模块：DragonEvaluate.c —— 行为统计支撑
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
VOID DragonBehaviorInitialize(VOID);
/* @IRQL: <= DISPATCH_LEVEL */
VOID DragonBehaviorReset(VOID);

/*=============================================================================
  模块：DragonEvaluate.c
  规则评估
=============================================================================*/
/* @IRQL: <= APC_LEVEL */
BOOLEAN DragonEvaluateProcessCreate(
    HANDLE CreatorPid, HANDLE ParentPid, HANDLE TargetPid,
    PCUNICODE_STRING TargetPath, PCUNICODE_STRING CommandLine,
    BOOLEAN FileOpenNameAvailable, BOOLEAN IsSubsystemProcess,
    PULONG OutCode, PULONG OutAction);

/* @IRQL: <= APC_LEVEL */
BOOLEAN DragonEvaluateProcessAccess(
    HANDLE SourcePid, HANDLE TargetPid,
    ULONG RequestedOperations, ULONG HandleType, ULONG ObjectType,
    PULONG DeniedOperations, PULONG OutCode, PULONG OutAction);

/* @IRQL: <= APC_LEVEL */
BOOLEAN DragonEvaluateThread(
    HANDLE SourcePid, HANDLE TargetPid, ULONG MemoryType,
    ULONG MemoryProtection, SIZE_T RegionSize,
    PULONG OutCode, PULONG OutAction);

/* @IRQL: <= APC_LEVEL */
BOOLEAN DragonEvaluateImageLoad(
    HANDLE ProcessId, PCUNICODE_STRING ImagePath, PIMAGE_INFO ImageInfo,
    PULONG OutCode, PULONG OutAction);

/* @IRQL: <= APC_LEVEL */
BOOLEAN DragonEvaluateFile(
    HANDLE ProcessId, PCUNICODE_STRING TargetPath, ULONG Operation,
    PULONG OutCode, PULONG OutAction);

/* @IRQL: <= APC_LEVEL —— ValueName 为 NULL 表示键级操作（此时无从匹配值名） */
BOOLEAN DragonEvaluateRegistry(
    HANDLE ProcessId, PCUNICODE_STRING KeyPath, PCUNICODE_STRING ValueName, ULONG Operation,
    PULONG OutCode, PULONG OutAction);

/* @IRQL: <= APC_LEVEL */
BOOLEAN DragonEvaluateDevice(
    HANDLE ProcessId, PULONG OutCode, PULONG OutAction);

/*=============================================================================
  模块：DragonProcessGuard.c
  进程创建/退出通知 + 进程关系缓存
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonProcessGuardStart(VOID);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonProcessGuardStop(VOID);
/* @IRQL: <= DISPATCH_LEVEL —— 读取父子/创建者关系 */
BOOLEAN  DragonProcessRelationGet(HANDLE ProcessId, PHANDLE ParentPid, PHANDLE CreatorPid);
/* @IRQL: <= DISPATCH_LEVEL */
VOID     DragonProcessRelationForget(HANDLE ProcessId);

/*=============================================================================
  模块：DragonRegistryGuard.c
  注册表回调
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonRegistryGuardStart(PDRIVER_OBJECT DriverObject);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonRegistryGuardStop(VOID);

/*=============================================================================
  模块：DragonObjectGuard.c
  对象句柄回调 / 线程通知 / 镜像通知
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonObjectGuardStart(VOID);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonObjectGuardStop(VOID);

/*=============================================================================
  模块：DragonResponse.c
  作业队列（WDF 工作项驱动）：事件上报 / 进程终止 / 线程内存分析
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonResponseInitialize(WDFDRIVER Driver);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonResponseTeardown(VOID);
/* @IRQL: <= APC_LEVEL —— 投递「上报事件」作业 */
VOID DragonQueueReport(ULONG Code, HANDLE ProcessId, PCWSTR Path, USHORT PathBytes);
/* @IRQL: <= APC_LEVEL —— 投递「终止进程」作业 */
VOID DragonQueueTerminate(HANDLE ProcessId);
/* @IRQL: <= APC_LEVEL —— 投递「跨进程线程分析」作业 */
VOID DragonQueueThreadScan(HANDLE SourcePid, HANDLE TargetPid, HANDLE ThreadId);
/* @IRQL: <= APC_LEVEL —— 投递「句柄访问降权」上报作业（目标路径延迟解析） */
VOID DragonQueueAccessReport(
    ULONG Code, ULONG Action, HANDLE SourcePid, HANDLE TargetPid, PCWSTR Fallback, USHORT FallbackBytes);
/* @IRQL: <= APC_LEVEL —— 组合投递：先上报，再按 Action 处置 */
VOID DragonQueueViolation(ULONG Code, ULONG Action, HANDLE ActorPid, PCWSTR Path, USHORT PathBytes);
/* @IRQL: PASSIVE_LEVEL —— 直接发送事件（仅工作项内部使用） */
NTSTATUS DragonSendEvent(ULONG Code, ULONG Action, HANDLE ProcessId, PCWSTR Path, USHORT PathBytes);

/*=============================================================================
  模块：DragonSelfProtect.c
  内置自保护：硬编码 + 安装期配置，不受用户态规则增删影响

  保护面（前三条编译期固化，第四条来自注册表清单）：
    · 驱动自身镜像文件（写 / 删 / 改名 / 设置安全信息）
    · 规则目录内容（同上）
    · 驱动服务注册表键（建子键 / 写值 / 删值 / 删键）
    · 主程序与主程序外置文件（Parameters\GuardPaths，REG_MULTI_SZ 通配符清单）
    · 已连接的客户端进程（从其它进程的期望访问掩码中剥掉处置类权限）
=============================================================================*/
/* 主程序 / 外置文件保护清单：容量上限（编译期固定，避免运行期动态分配） */
#define DRG_GUARD_PATH_SLOTS       32u     /* 最多容纳的清单条目数 */
#define DRG_GUARD_PATH_CHARS       520u    /* 单条最长字符数（含结尾 NUL） */

/* 内部豁免目录：容量上限（登记方是数据面模块，槽位不需要很多） */
#define DRG_SELF_EXEMPT_SLOTS      2u

/* @IRQL: PASSIVE_LEVEL —— 从驱动服务键读取 ImagePath 并推导受保护路径 */
NTSTATUS DragonSelfProtectInitialize(PUNICODE_STRING RegistryPath);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonSelfProtectTeardown(VOID);
/* @IRQL: PASSIVE_LEVEL —— 登记内部豁免目录（当前用于勒索备份区）。

              语义是「仅放行 System 发起的 I/O」而不是「一律放行」：驱动自己的工作项
              运行在 System 上下文，不放行就等于自保护把驱动自己的备份写入也拦掉；
              外部进程碰备份区依然会被拦（防止恶意程序清掉备份）。

              由数据面模块在初始化成功后调用，避免模块之间互相引用头文件。 */
VOID     DragonSelfProtectAddExemptDir(PCUNICODE_STRING Directory);
/* @IRQL: <= APC_LEVEL —— 文件操作自保护判定：返回 0 = 放行，非 0 = 拒绝并回传事件码。

              ProcessId 只在「豁免目录」上有意义：用来区分内核自身发起的写入（放行）
              与外部进程发起的写入（照拦）。 */
ULONG    DragonSelfProtectFile(HANDLE ProcessId, PCUNICODE_STRING FileName, ULONG Operation);
/* @IRQL: <= APC_LEVEL —— 注册表操作自保护判定：返回 0 = 放行，非 0 = 拒绝并回传事件码 */
ULONG    DragonSelfProtectRegistry(PCUNICODE_STRING KeyPath, ULONG Operation);
/* @IRQL: <= APC_LEVEL —— 目标若为「已连接客户端」，返回需要剥离的访问掩码（0 = 无需处理） */
ACCESS_MASK DragonSelfProtectClientMask(PEPROCESS TargetProcess, ULONG ObjectType);
/* @IRQL: <= APC_LEVEL —— 当前生效的主程序/外置文件保护条目数（诊断用） */
ULONG    DragonSelfProtectGuardPathCount(VOID);

/*=============================================================================
  模块：DragonRansom.c
  勒索软件防护：行为评分 + 写前备份 + 一键恢复

  设计要点（与参考实现的差异都是刻意的）：
    · 不终止、不冻结进程 —— 判定成立后直接拒绝该进程后续的文档类文件操作，
      既不需要未文档化 API，也不会留下「忘了恢复」的僵死进程；
    · 备份文件自带头部（DRG_BACKUP_HEADER），原路径写在备份里，
      因此恢复不依赖任何内存状态，重启后依然能还原；
    · 备份文件名为「原路径小写形式的 FNV-1a 64 位哈希」，
      可以由原路径直接反算，不需要维护「路径 → 备份文件」的索引表；
    · 全部使用文档化 API：ZwCreateFile / ZwReadFile / ZwWriteFile /
      ZwQueryInformationFile / ZwSetInformationFile。
=============================================================================*/
/* 备份上限与评分窗口 */
#define DRG_RANSOM_SCORE_THRESHOLD     120u        /* 阻断阈值 */
#define DRG_RANSOM_SCORE_CAP           1000u       /* 评分上限，防止无意义膨胀 */
#define DRG_RANSOM_WINDOW_100NS        (60LL * 10000000LL)   /* 评分时间窗：60 秒 */
#define DRG_RANSOM_BLOCK_TIMEOUT_100NS (60LL * 10000000LL)   /* 无新操作后自动解封：60 秒 */
#define DRG_RANSOM_PROC_SLOTS          64u         /* 同时跟踪的进程上限 */
#define DRG_RANSOM_OP_RING             64u         /* 每进程操作时间戳环容量 */
#define DRG_RANSOM_DIVERSITY_SLOTS     16u         /* 扩展名 / 目录多样性统计槽 */
#define DRG_RANSOM_RECORD_MAX          64u         /* 受影响文件记录条数 */
#define DRG_RANSOM_BACKEDUP_RING       512u        /* 已备份哈希环容量 */
#define DRG_RANSOM_DEFAULT_BACKUP_MAX  (4u * 1024u * 1024u)   /* 单文件备份上限：4MB */
#define DRG_RANSOM_ENTROPY_MIN         512u        /* 高熵采样下限（字节） */
#define DRG_RANSOM_ENTROPY_MAX         4096u       /* 高熵采样上限（字节） */
#define DRG_RANSOM_ENTROPY_STRIDE      3u          /* 每 N 次写才做一次熵采样 */
#define DRG_RANSOM_ENTROPY_THRESHOLD   230u        /* 随机性阈值（0-255） */

/* 文件操作种类（仅用于统计，与 DRG_OP_* 解耦） */
#define DRG_RANSOM_OP_WRITE            1u
#define DRG_RANSOM_OP_DELETE           2u
#define DRG_RANSOM_OP_RENAME           3u
#define DRG_RANSOM_OP_EXT_CHANGE       4u

/* @IRQL: PASSIVE_LEVEL —— 读取服务键配置（备份目录 / 备份上限） */
NTSTATUS DragonRansomInitialize(PUNICODE_STRING RegistryPath);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonRansomTeardown(VOID);
/* @IRQL: <= APC_LEVEL —— 该路径是否属于需要保护的文档类文件 */
BOOLEAN  DragonRansomIsDocument(PCUNICODE_STRING FileName);
/* @IRQL: <= APC_LEVEL —— 该进程当前是否正被勒索阻断（阻断中的操作一律拒绝） */
BOOLEAN  DragonRansomIsBlocked(HANDLE ProcessId);
/* @IRQL: PASSIVE_LEVEL —— 写打开时创建备份，返回 TRUE 表示该文件已有可用备份 */
BOOLEAN  DragonRansomBackup(PCUNICODE_STRING FileName);
/* @IRQL: <= APC_LEVEL —— 记录一次文件操作并重新评分；
                          返回非 0（事件码）表示应阻断本次操作。
                          NewName 仅重命名时非空（重命名后的名字）；
                          WriteBuffer / WriteLength 仅写操作时非空。 */
ULONG    DragonRansomEvaluate(
    HANDLE ProcessId,
    PCUNICODE_STRING FileName,
    _In_opt_ PCUNICODE_STRING NewName,
    ULONG Operation,
    _In_opt_ PVOID WriteBuffer,
    ULONG WriteLength);
/* @IRQL: PASSIVE_LEVEL —— 恢复文件；Mode 取 DRG_RESTORE_MODE_* */
NTSTATUS DragonRansomRestore(PUNICODE_STRING Path, ULONG Mode, PDRG_RESTORE_REPLY Reply);
/* @IRQL: <= APC_LEVEL —— 填充状态快照 */
VOID     DragonRansomQueryStatus(PDRG_RANSOM_STATUS Status);
/* @IRQL: <= APC_LEVEL —— 进程退出时释放跟踪槽 */
VOID     DragonRansomForgetProcess(HANDLE ProcessId);

/*=============================================================================
  模块：DragonMetrics.c
  诊断统计：各回调调用次数、判定与处置计数、最近一次动作快照
=============================================================================*/
typedef enum _DRG_METRIC_COUNTER {
    DrgMetricProcessCreate = 0,
    DrgMetricProcessAccess,
    DrgMetricThreadCreate,
    DrgMetricImageLoad,
    DrgMetricFileCreate,
    DrgMetricFileWrite,
    DrgMetricFileSetInfo,
    DrgMetricRegistry,
    DrgMetricDeviceIoctl,
    DrgMetricRulesEvaluated,
    DrgMetricRulesHit,
    DrgMetricBlocked,
    DrgMetricTerminated,
    DrgMetricSelfProtectHits,
    DrgMetricRansomBlocks,
    DrgMetricRansomBackups,
    DrgMetricRansomRestores,
    DrgMetricTrustCacheHits,
    DrgMetricCount
} DRG_METRIC_COUNTER;

/* @IRQL: PASSIVE_LEVEL */
VOID DragonMetricsInitialize(VOID);
/* @IRQL: <= DISPATCH_LEVEL —— 计数器累加 */
VOID DragonMetricsBump(ULONG Counter, ULONGLONG Delta);
/* @IRQL: <= APC_LEVEL —— 更新「最近一次动作」快照 */
VOID DragonMetricsRecordLast(
    ULONG CallbackKind, ULONG RuleCode, ULONG Action, HANDLE ProcessId, PCUNICODE_STRING Path);
/* @IRQL: <= APC_LEVEL —— 填充统计快照 */
VOID DragonMetricsQuery(PDRG_METRICS Metrics);

/*=============================================================================
  模块：DragonFileGuard.c
  Minifilter 文件操作回调
=============================================================================*/
FLT_PREOP_CALLBACK_STATUS DragonFilePreCreate(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS DragonFilePreWrite(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS DragonFilePreSetInformation(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS DragonFilePreSetSecurity(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS DragonFilePreFileSystemControl(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);

/*=============================================================================
  模块：DragonBootGuard.c
  裸设备 IOCTL 防护（磁盘擦写/分区改写）
=============================================================================*/
FLT_PREOP_CALLBACK_STATUS DragonBootPreDeviceControl(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);

/*=============================================================================
  模块：DragonComms.c
  通信端口 / 命令分发 / 状态机
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonCommsCreate(PDRIVER_OBJECT DriverObject);
/* @IRQL: PASSIVE_LEVEL */
VOID     DragonCommsClose(VOID);
/* @IRQL: <= DISPATCH_LEVEL */
LONG     DragonStateGet(VOID);
/* @IRQL: <= DISPATCH_LEVEL */
VOID     DragonStateSet(LONG State);
/* @IRQL: PASSIVE_LEVEL —— 依据 Flag 决策是否真正卸载 */
NTSTATUS DragonBeginTeardown(BOOLEAN Mandatory);

/*=============================================================================
  模块：DragonEntry.c
  驱动入口与生命周期
=============================================================================*/
/* @IRQL: PASSIVE_LEVEL */
NTSTATUS DragonFullCleanup(BOOLEAN MandatoryUnload);

#endif /* _DRAGON_COMMON_H_ */
