/*++
===============================================================================
 Dragon-Drivers / DragonProtocol.h

 天龙神盾 内核防护驱动 —— 用户态与内核态共享的「数据契约」头文件。

 说明：
   本文件只描述**数据结构与数值语义**，不含任何内核实现逻辑，
   可以被内核态（wdm.h / fltkernel.h 之后）与用户态（windows.h）同时包含。

   内核只包含一次宏开关：
       #define DRG_KERNEL_MODE   1   （由 DragonCommon.h 定义）
       然后 #include "DragonProtocol.h"

   不带该宏时，本文件只要求基础整数类型（ULONG / USHORT / WCHAR / HANDLE）。

 版权：本文件为原创实现，仅保留「功能等价」所需的对外行为约定。
===============================================================================
--*/

#ifndef _DRAGON_PROTOCOL_H_
#define _DRAGON_PROTOCOL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*-----------------------------------------------------------------------------
  版本与标识
-----------------------------------------------------------------------------*/
#define DRG_PROTOCOL_VERSION      3u
#define DRG_BUILD_SIGNATURE       0x312E3056u   /* 'V0.1' 占位，仅用于诊断 */

/* 过滤器通信端口名（用户态 FilterConnectCommunicationPort 使用） */
#define DRG_PORT_NAME             L"\\DragonGuard_Event_Port"

/* 连接上下文校验值：'DRGN' */
#define DRG_CONNECTION_MAGIC      0x4E475244u
#define DRG_CONNECTION_VERSION    1u

/* 路径字符串容量（以 WCHAR 计），含结尾 NUL */
#define DRG_PATH_CHARS            1024

/* 单个规则 JSON 文件最大字节数 */
#define DRG_MAX_RULE_FILE_BYTES   (4u * 1024u * 1024u)

/* 未完成作业队列上限 */
#define DRG_MAX_PENDING_JOBS      256u

/* 进程信任缓存条目数与有效期（秒） */
#define DRG_TRUST_SLOTS           128u
#define DRG_TRUST_TTL_SECONDS     300u

/* 行为频率统计槽位数量 */
#define DRG_BEHAVIOR_SLOTS        128u

/* 进程树向上回溯最大深度（防环） */
#define DRG_TREE_MAX_DEPTH        12u

/* 进程关系缓存：直接映射表 1024 桶 × 4 路 */
#define DRG_RELATION_BUCKETS      1024u
#define DRG_RELATION_WAYS         4u

/* 驱动启动时自动加载的规则文件（相对驱动目录） */
#define DRG_AUTO_RULE_SUBPATH     L"\\Rules\\DragonDriver_DefenderRules.json"

/* 终止受保护进程时使用的占位消息 */
#define DRG_MSG_DISK_WIPER        L"Disk_Wiper_Attempt"
#define DRG_MSG_PROC_HANDLE       L"Process_Handle_Access_Denied"
#define DRG_MSG_THREAD_HANDLE     L"Thread_Handle_Access_Denied"
#define DRG_MSG_REMOTE_THREAD     L"Remote_Executable_Thread_Detected"

/*-----------------------------------------------------------------------------
  处置动作

  规则 JSON 的 "Action" 键取值；未指定时按旧版 "Kill" 字段推断
  （Kill=true -> Terminate，Kill=false -> Report），保证旧规则文件行为不变。

    · Report    —— 仅上报事件（默认）；
    · Terminate —— 内核直接终止发起进程（ZwTerminateProcess，官方文档化 DDI）。
-----------------------------------------------------------------------------*/
#define DRG_ACTION_UNSET          0xFFFFFFFFu   /* 未指定，按 Kill 字段推断 */
#define DRG_ACTION_REPORT         0u            /* 仅上报 */
#define DRG_ACTION_TERMINATE      1u            /* 上报 + 内核终止发起进程 */

/*-----------------------------------------------------------------------------
  自保护事件码（内置、硬编码，不受用户态规则增删影响）

  约定占用 9001-9099 段，与动态规则编号（1000 段）区分开。
-----------------------------------------------------------------------------*/
#define DRG_CODE_SELF_IMAGE        9001u   /* 试图写入/删除/改名驱动自身镜像 */
#define DRG_CODE_SELF_RULE_DIR     9002u   /* 试图写入/删除/改名规则目录内容 */
#define DRG_CODE_SELF_SERVICE_KEY  9003u   /* 试图修改驱动服务注册表键 */
#define DRG_CODE_SELF_CLIENT       9004u   /* 试图终止已连接客户端或剥夺其处置权限 */
#define DRG_CODE_PROTECTED_TARGET  9005u   /* 试图操作受保护名单内的进程 */
#define DRG_CODE_SELF_GUARD        9006u   /* 试图改动主程序 / 外置文件（GuardPaths 清单） */
#define DRG_CODE_SELF_BACKUP       9007u   /* 非内核发起者试图改动勒索备份区 */

/*-----------------------------------------------------------------------------
  勒索防护事件码与检测信号

  事件码约定占用 9200 段；检测信号位用于向用户态说明「为什么判为勒索」，
  多个信号可同时置位。
-----------------------------------------------------------------------------*/
#define DRG_CODE_RANSOM_DETECT     9201u   /* 勒索行为评分达到阻断阈值 */
#define DRG_CODE_RANSOM_RESTORE    9202u   /* 已从备份恢复文件 */

#define DRG_RANSOM_SIG_MASS_MODIFY    0x00000001u   /* 短窗内大量文件修改 */
#define DRG_RANSOM_SIG_MASS_DELETE    0x00000002u   /* 短窗内大量文件删除 */
#define DRG_RANSOM_SIG_MASS_RENAME    0x00000004u   /* 短窗内大量文件重命名 */
#define DRG_RANSOM_SIG_EXT_CHANGE     0x00000008u   /* 扩展名变更（勒索软件特征） */
#define DRG_RANSOM_SIG_ENTROPY        0x00000010u   /* 高随机性写入（疑似加密） */
#define DRG_RANSOM_SIG_TYPE_DIVERSITY 0x00000020u   /* 涉及文件类型过多 */
#define DRG_RANSOM_SIG_DIR_DIVERSITY  0x00000040u   /* 涉及目录过多 */
#define DRG_RANSOM_SIG_RAPID_WRITES   0x00000080u   /* 短窗内写入过于频繁 */

/*-----------------------------------------------------------------------------
  驱动运行状态机
-----------------------------------------------------------------------------*/
typedef enum _DRG_STATE {
    DrgStateCold     = 0,
    DrgStateStarting = 1,
    DrgStateRunning  = 2,
    DrgStateStopping = 3,
    DrgStateRetry    = 4,
    DrgStateStopped  = 5
} DRG_STATE;

/*-----------------------------------------------------------------------------
  用户态 -> 内核态 命令
  数值即线上协议，必须与用户态客户端保持一致。
-----------------------------------------------------------------------------*/
typedef enum _DRG_COMMAND {
    DrgCmdAddWhitelist    = 1,   /* Path = 通配符白名单模式 */
    DrgCmdRemoveWhitelist = 2,   /* Path = 通配符白名单模式 */
    DrgCmdLoadRuleFile    = 3,   /* Path = 规则 JSON 的 NT 路径 (\??\C:\...) */
    DrgCmdClearRules      = 4,
    DrgCmdAuthorizeUnload = 5,
    DrgCmdRevokeUnload    = 6,
    DrgCmdQueryState      = 7,   /* 输出 DRG_STATE_REPLY */
    DrgCmdQueryRansom     = 8,   /* 输出 DRG_RANSOM_STATUS */
    DrgCmdRestoreFiles    = 9,   /* Argument=0 恢复并解封 / Argument=1 仅解封；
                                    Path 为空 = 处理全部记录，非空 = 只处理该路径 */
    DrgCmdQueryMetrics    = 10   /* 输出 DRG_METRICS */
} DRG_COMMAND;

/* DrgCmdRestoreFiles 的 Argument 取值 */
#define DRG_RESTORE_MODE_ROLLBACK    0u   /* 恢复文件 + 解除阻断 */
#define DRG_RESTORE_MODE_RELEASE     1u   /* 仅解除阻断，不动文件 */

/* 命令分发结果附加标志（查询状态时回填） */
#define DRG_FLAG_RULES_LOADED     0x00000001u
#define DRG_FLAG_CLIENT_ATTACHED  0x00000002u

/*-----------------------------------------------------------------------------
  端口消息结构
-----------------------------------------------------------------------------*/
typedef struct _DRG_CONNECTION_CONTEXT {
    ULONG Size;        /* = sizeof(DRG_CONNECTION_CONTEXT) */
    ULONG Version;     /* = DRG_CONNECTION_VERSION */
    ULONG Magic;       /* = DRG_CONNECTION_MAGIC */
    ULONG ProcessId;   /* 连接方 PID，必须等于当前进程 */
} DRG_CONNECTION_CONTEXT, *PDRG_CONNECTION_CONTEXT;

/* 内核 -> 用户态 事件 */
typedef struct _DRG_EVENT {
    ULONG         MessageCode;          /* 规则编号；自保护事件为 9xxx 段 */
    ULONG         Action;               /* DRG_ACTION_*：本条事件的处置动作 */
    ULONG         ProcessId;            /* 事件主体进程（被拦截方/发起方） */
    WCHAR         Path[DRG_PATH_CHARS];
} DRG_EVENT, *PDRG_EVENT;

/* 布局守卫：本结构在用户态由 tools/dragon_client.py 的 ctypes 结构体逐字段镜像，
   增删字段或改动对齐都会让两侧错位。下面的编译期断言会在尺寸变化时直接失败，
   提醒同步客户端（客户端侧也有对应的 sizeof 校验）。 */
typedef char DRG_EVENT_LAYOUT_CHECK[
    (sizeof(DRG_EVENT) == (3u * sizeof(ULONG)) + (DRG_PATH_CHARS * sizeof(WCHAR)))
        ? 1
        : -1];

/* 用户态 -> 内核 命令 */
typedef struct _DRG_COMMAND_MESSAGE {
    ULONG Command;
    ULONG Argument;     /* 命令附加参数；不使用该参数的命令必须传 0 */
    WCHAR Path[DRG_PATH_CHARS];
} DRG_COMMAND_MESSAGE, *PDRG_COMMAND_MESSAGE;

/* 查询状态的回复体 */
typedef struct _DRG_STATE_REPLY {
    ULONG State;
    ULONG Flags;
} DRG_STATE_REPLY, *PDRG_STATE_REPLY;

/*-----------------------------------------------------------------------------
  勒索防护：备份文件头部

  备份文件 = 本头部 + 原始文件字节。头部里带着原始路径，因此「恢复」不需要
  任何内存状态 —— 只要备份文件还在，就能反推出它属于哪个原文件，
  这一点比把路径只记在内存里的做法可靠（重启后依然可恢复）。
-----------------------------------------------------------------------------*/
#define DRG_BACKUP_MAGIC          0x4B424752u   /* 'RGBK' */
#define DRG_BACKUP_VERSION        1u
#define DRG_BACKUP_PATH_CHARS     520u          /* 备份头部中的原路径容量（含 NUL） */

typedef struct _DRG_BACKUP_HEADER {
    ULONG     Magic;                /* = DRG_BACKUP_MAGIC */
    ULONG     Version;              /* = DRG_BACKUP_VERSION */
    ULONG     PathChars;            /* OriginalPath 有效字符数（不含 NUL） */
    ULONG     Reserved;             /* 对齐填充 */
    ULONGLONG OriginalSize;         /* 原始文件字节数 */
    ULONGLONG BackupTime;           /* 备份时间（100ns，1601 起算） */
    WCHAR     OriginalPath[DRG_BACKUP_PATH_CHARS];
} DRG_BACKUP_HEADER, *PDRG_BACKUP_HEADER;

/* 勒索防护状态（DrgCmdQueryRansom 输出） */
typedef struct _DRG_RANSOM_STATUS {
    ULONG Blocking;            /* 当前是否存在阻断中的进程 */
    ULONG BlockedProcesses;    /* 阻断中的进程数 */
    ULONG TrackedProcesses;    /* 跟踪中的进程数 */
    ULONG MaxScore;            /* 当前最高评分 */
    ULONG DetectionFlags;      /* 最高评分对应的置信信号位 */
    ULONG BlockedPid;          /* 最高评分对应的进程 ID（0 = 无） */
    ULONG BackupsCreated;      /* 累计创建备份数 */
    ULONG RestoredFiles;       /* 累计恢复文件数 */
    ULONG Records;             /* 受影响文件记录条数 */
    ULONG BackingOff;          /* 处于阻断后退避（不再评分）状态的进程数 */
    ULONG Reserved[6];
} DRG_RANSOM_STATUS, *PDRG_RANSOM_STATUS;

/* 恢复命令的回复体（DrgCmdRestoreFiles 输出） */
typedef struct _DRG_RESTORE_REPLY {
    ULONG Requested;           /* 本次处理的目标数 */
    ULONG Restored;            /* 成功恢复的文件数 */
    ULONG Failed;              /* 恢复失败数 */
    ULONG Released;            /* 被解除阻断的进程数 */
} DRG_RESTORE_REPLY, *PDRG_RESTORE_REPLY;

/*-----------------------------------------------------------------------------
  诊断统计（DrgCmdQueryMetrics 输出）

  用途：实机排障。内核态回调是否真的被调用、规则是否命中、处置是否落地，
  光看日志很难判断；这里把每个回调的调用次数与最近一次动作原样暴露出来。
-----------------------------------------------------------------------------*/
/* 最近一次动作所属的回调种类 */
#define DRG_METRIC_CB_NONE            0u
#define DRG_METRIC_CB_PROCESS_CREATE  1u
#define DRG_METRIC_CB_PROCESS_ACCESS  2u
#define DRG_METRIC_CB_THREAD_CREATE   3u
#define DRG_METRIC_CB_IMAGE_LOAD      4u
#define DRG_METRIC_CB_FILE_CREATE     5u
#define DRG_METRIC_CB_FILE_WRITE      6u
#define DRG_METRIC_CB_FILE_SETINFO    7u
#define DRG_METRIC_CB_REGISTRY        8u
#define DRG_METRIC_CB_DEVICE_IOCTL    9u

typedef struct _DRG_METRICS {
    ULONG     ProtocolVersion;
    ULONG     DriverState;          /* DRG_STATE */
    ULONG     RuleCount;            /* 当前动态规则条数 */
    ULONG     GuardPathCount;       /* 生效的主程序/外置文件保护条目数 */

    /* 各回调调用次数（进入评估前） */
    ULONGLONG ProcessCreateCalls;
    ULONGLONG ProcessAccessCalls;
    ULONGLONG ThreadCreateCalls;
    ULONGLONG ImageLoadCalls;
    ULONGLONG FileCreateCalls;
    ULONGLONG FileWriteCalls;
    ULONGLONG FileSetInfoCalls;
    ULONGLONG RegistryCalls;
    ULONGLONG DeviceIoctlCalls;

    /* 判定与处置结果 */
    ULONGLONG RulesEvaluated;       /* 实际进入规则评估的次数 */
    ULONGLONG RulesHit;             /* 规则命中次数 */
    ULONGLONG Blocked;              /* 拦截次数（含自保护） */
    ULONGLONG Terminated;           /* 终止作业投递次数 */
    ULONGLONG SelfProtectHits;      /* 自保护命中次数 */
    ULONGLONG RansomBlocks;         /* 勒索阻断次数 */
    ULONGLONG RansomBackups;        /* 备份文件创建次数 */
    ULONGLONG RansomRestores;       /* 恢复文件次数 */
    ULONGLONG TrustCacheHits;       /* 信任缓存命中（跳过评估）次数 */

    /* 事件通道 */
    ULONGLONG EventsReported;
    ULONGLONG EventsDropped;

    /* 最近一次动作快照 */
    ULONG     LastCallbackKind;     /* DRG_METRIC_CB_* */
    ULONG     LastRuleCode;
    ULONG     LastAction;           /* DRG_ACTION_* */
    ULONG     LastProcessId;
    WCHAR     LastPath[DRG_BACKUP_PATH_CHARS];
} DRG_METRICS, *PDRG_METRICS;

/*-----------------------------------------------------------------------------
  规则语义：操作位
-----------------------------------------------------------------------------*/
#define DRG_OP_WRITE                 0x00000001u
#define DRG_OP_DELETE                0x00000002u
#define DRG_OP_CREATE                0x00000004u
#define DRG_OP_EXECUTE               0x00000008u
#define DRG_OP_RENAME                0x00000010u
#define DRG_OP_IOCTL                 0x00000020u
#define DRG_OP_VM_READ               0x00000040u
#define DRG_OP_VM_WRITE              0x00000080u
#define DRG_OP_TERMINATE             0x00000100u
#define DRG_OP_SUSPEND_RESUME        0x00000200u
#define DRG_OP_DUP_HANDLE            0x00000400u
#define DRG_OP_SET_INFORMATION       0x00000800u
#define DRG_OP_VM_OPERATION          0x00001000u
#define DRG_OP_CREATE_THREAD         0x00002000u
#define DRG_OP_THREAD_SET_CONTEXT    0x00004000u
#define DRG_OP_THREAD_SET_TOKEN      0x00008000u
#define DRG_OP_CREATE_PROCESS        0x00010000u
#define DRG_OP_IMAGE_LOAD            0x00020000u
#define DRG_OP_IMPERSONATE           0x00040000u

/* 句柄操作类型 */
#define DRG_HANDLE_CREATE            0x00000001u
#define DRG_HANDLE_DUPLICATE         0x00000002u

/* 对象类型 */
#define DRG_OBJECT_PROCESS           0x00000001u
#define DRG_OBJECT_THREAD            0x00000002u

/* 线程起始地址所在内存类型 */
#define DRG_MEMORY_PRIVATE           0x00000001u
#define DRG_MEMORY_MAPPED            0x00000002u
#define DRG_MEMORY_IMAGE             0x00000004u

/* 线程起始地址所在内存保护属性 */
#define DRG_PROTECT_EXECUTE          0x00000001u
#define DRG_PROTECT_EXECUTE_WRITE    0x00000002u

/*-----------------------------------------------------------------------------
  规则语义：类别
-----------------------------------------------------------------------------*/
typedef enum _DRG_CATEGORY {
    DrgCategoryProcess  = 0,
    DrgCategoryFile     = 1,
    DrgCategoryRegistry = 2,
    DrgCategoryDevice   = 3,
    DrgCategoryMemory   = 4,
    DrgCategoryThread   = 5,
    DrgCategoryUnknown  = 6
} DRG_CATEGORY;

/* 三态条件 */
typedef enum _DRG_TRI {
    DrgTriAny   = 0,
    DrgTriTrue  = 1,
    DrgTriFalse = 2
} DRG_TRI;

/* 多操作匹配方式 */
typedef enum _DRG_OPERATION_MATCH {
    DrgOpMatchAny = 0,
    DrgOpMatchAll = 1
} DRG_OPERATION_MATCH;

/*-----------------------------------------------------------------------------
  风险评分上限
-----------------------------------------------------------------------------*/
#define DRG_RISK_MAX                 100u

/* 默认时间窗口（毫秒），当 Threshold>0 且 TimeWindow==0 时生效 */
#define DRG_DEFAULT_TIME_WINDOW_MS   1000u

#ifdef __cplusplus
}
#endif

#endif /* _DRAGON_PROTOCOL_H_ */
