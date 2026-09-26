/*++
===============================================================================
 Dragon-Drivers / DragonFileGuard.c

 Minifilter 文件操作防护。

 注册的回调（见 DragonEntry.c 的 FLT_OPERATION_REGISTRATION 表）：
   IRP_MJ_CREATE            -> DragonFilePreCreate
   IRP_MJ_WRITE             -> DragonFilePreWrite
   IRP_MJ_SET_INFORMATION   -> DragonFilePreSetInformation
   IRP_MJ_SET_SECURITY      -> DragonFilePreSetSecurity      （策略上不拦截）
   IRP_MJ_FILE_SYSTEM_CONTROL -> DragonFilePreFileSystemControl（策略上不拦截）

 统一守卫（每个回调入口逐条执行）：
   1. RequestorMode == KernelMode 直接放行：内核自身发起的 I/O 不作为用户行为；
   2. IRQL > APC_LEVEL 直接放行：避免在任意线程上下文中做分页/路径解析；
   3. 任何失败分支都释放已获取的文件名信息，绝不泄漏 FILTER_FILE_NAME 引用。

 命中处置：向用户态上报事件 + 按规则 Action 语义投递处置作业，
 并把 IoStatus 置为 STATUS_ACCESS_DENIED 后以 FLT_PREOP_COMPLETE 直接结束请求。
===============================================================================
--*/

#include "DragonCommon.h"

/*++
@IRQL: PASSIVE_LEVEL
@brief 取规范化文件名；失败返回 NULL（调用方无需释放）。

@note  必须在 FltGetFileNameInformation 成功且 FltParseFileNameInformation 成功后
       才能使用返回的 Name 字段。
--*/
static
PFLT_FILE_NAME_INFORMATION
DragonAcquireFileName(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION NameInfo;

    NameInfo = NULL;

    if (Data == NULL) {
        return NULL;
    }

    Status = FltGetFileNameInformation(
                 Data,
                 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                 &NameInfo);
    if (!NT_SUCCESS(Status) || NameInfo == NULL) {
        return NULL;
    }

    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status) || NameInfo->Name.Buffer == NULL || NameInfo->Name.Length == 0) {
        FltReleaseFileNameInformation(NameInfo);
        return NULL;
    }

    return NameInfo;
}

/*++
@IRQL: <= APC_LEVEL
@brief 统一判定入口：内置自保护 -> 动态规则 -> 勒索评分。

        顺序不可颠倒：
          · 自保护在规则之前 —— 动态规则可以被用户态 DrgCmdClearRules 整表清空，
            而内置自保护是编译期固化的；若先判规则，攻击者只要清空规则就能
            反过来修改驱动自身镜像；
          · 勒索评分在规则之后 —— 它统计的是「实际发生的文件操作」，被规则
            拦下的操作压根没落地，不该计入勒索的行为基线。

@param  NewName      仅重命名时非空（重命名后的名字），用于识别扩展名变更
@param  WriteBuffer  仅写操作时非空，用于高熵采样
@return TRUE 表示应拒绝该请求，OutCode / OutAction 给出事件码与处置动作。
--*/
static
BOOLEAN
DragonDecideFile(
    _In_ HANDLE ProcessId,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_opt_ PCUNICODE_STRING NewName,
    _In_ ULONG Operation,
    _In_opt_ PVOID WriteBuffer,
    _In_ ULONG WriteLength,
    _Out_ PULONG OutCode,
    _Out_ PULONG OutAction
    )
{
    ULONG SelfCode;
    ULONG RansomCode;

    *OutCode = 0;
    *OutAction = DRG_ACTION_REPORT;

    /* --- 1. 内置自保护 --- */

    SelfCode = DragonSelfProtectFile(ProcessId, &NameInfo->Name, Operation);
    if (SelfCode != 0) {

        /*
         * 自保护只做「拦截 + 上报」：不对发起者终止。
         * 原因是自保护会在安装/维护脚本误操作时命中，直接终止进程的
         * 破坏性远大于收益。
         */
        DragonMetricsBump(DrgMetricSelfProtectHits, 1);
        DragonMetricsBump(DrgMetricBlocked, 1);
        DragonMetricsRecordLast(
            DRG_METRIC_CB_FILE_CREATE, SelfCode, DRG_ACTION_REPORT, ProcessId, &NameInfo->Name);

        *OutCode = SelfCode;
        return TRUE;
    }

    /* --- 2. 动态规则 --- */

    DragonMetricsBump(DrgMetricRulesEvaluated, 1);

    if (DragonEvaluateFile(ProcessId, &NameInfo->Name, Operation, OutCode, OutAction) == TRUE) {
        DragonMetricsBump(DrgMetricRulesHit, 1);
        return TRUE;
    }

    /* --- 3. 勒索评分 --- */

    RansomCode = DragonRansomEvaluate(
                     ProcessId, &NameInfo->Name, NewName, Operation, WriteBuffer, WriteLength);

    if (RansomCode != 0) {

        /*
         * 勒索判定成立时只拒绝操作、不终止进程。
         *
         * 理由：判定是基于行为统计的，存在统计意义上的误判可能；而终止进程
         * 不可撤销。拒绝操作已经能阻止加密链继续，配合写前备份还能回滚，
         * 收益足够而风险可控。是否终止交给用户态按策略决定。
         */
        DragonMetricsBump(DrgMetricBlocked, 1);
        DragonMetricsRecordLast(
            DRG_METRIC_CB_FILE_WRITE, RansomCode, DRG_ACTION_REPORT, ProcessId, &NameInfo->Name);

        *OutCode = RansomCode;
        *OutAction = DRG_ACTION_REPORT;
        return TRUE;
    }

    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 命中规则时的统一处置。
--*/
static
FLT_PREOP_CALLBACK_STATUS
DragonBlockFileRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ HANDLE ProcessId,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ULONG RuleCode,
    _In_ ULONG Action
    )
{
    DragonQueueViolation(
        RuleCode,
        Action,
        ProcessId,
        NameInfo->Name.Buffer,
        NameInfo->Name.Length);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/*++
@IRQL: PASSIVE_LEVEL  (Filter Manager 前回调，实际上限 APC_LEVEL)
@brief IRP_MJ_CREATE 前回调：按「创建 / 写入 / 删除」意图匹配 File 类别规则。
--*/
FLT_PREOP_CALLBACK_STATUS
DragonFilePreCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION NameInfo;
    PACCESS_MASK DesiredAccess;
    ULONG CreateDisposition;
    ULONG Operation;
    ULONG RuleCode;
    ULONG Action;
    HANDLE ProcessId;
    FLT_PREOP_CALLBACK_STATUS Result;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NameInfo = DragonAcquireFileName(Data);
    if (NameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DragonMetricsBump(DrgMetricFileCreate, 1);

    CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFFu;

    DesiredAccess = NULL;
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        DesiredAccess = &Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    Operation = 0;

    if (CreateDisposition == FILE_SUPERSEDE ||
        CreateDisposition == FILE_CREATE ||
        CreateDisposition == FILE_OPEN_IF ||
        CreateDisposition == FILE_OVERWRITE ||
        CreateDisposition == FILE_OVERWRITE_IF) {
        Operation |= DRG_OP_CREATE;
    }

    if (DesiredAccess != NULL) {
        if ((*DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                               WRITE_DAC | WRITE_OWNER | GENERIC_WRITE)) != 0) {
            Operation |= DRG_OP_WRITE;
        }

        if ((*DesiredAccess & (DELETE | FILE_DELETE_CHILD)) != 0) {
            Operation |= DRG_OP_DELETE;
        }
    }

    Result = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (Operation != 0) {

        ProcessId = PsGetCurrentProcessId();
        RuleCode = 0;
        Action = DRG_ACTION_REPORT;

        /*
         * 写打开时先做一次勒索备份。
         *
         * 为什么选在这个点：IRP_MJ_CREATE 是「内容即将被改写」的第一个可观测
         * 位置，此刻原文件还是完整的。挪到 WRITE 回调再做就已经晚了一步 ——
         * 改写可能在同一批次里就发生了。
         *
         * 只对「打开已有文件且带写意图」的请求做：FILE_CREATE 的新文件没有原始
         * 内容可备份。另外要求 PASSIVE_LEVEL —— 文件复制是阻塞 I/O。
         */
        if ((Operation & DRG_OP_WRITE) != 0 &&
            CreateDisposition != FILE_CREATE &&
            KeGetCurrentIrql() == PASSIVE_LEVEL) {

            (VOID)DragonRansomBackup(&NameInfo->Name);
        }

        if (DragonDecideFile(ProcessId, NameInfo, NULL, Operation, NULL, 0,
                             &RuleCode, &Action) == TRUE) {
            Result = DragonBlockFileRequest(Data, ProcessId, NameInfo, RuleCode, Action);
        }
    }

    FltReleaseFileNameInformation(NameInfo);
    return Result;
}

/*++
@IRQL: PASSIVE_LEVEL  (Filter Manager 前回调，实际上限 APC_LEVEL)
@brief IRP_MJ_WRITE 前回调。

@note  只拦截用户发起、非分页/非缓存路径的写请求；
       规则引擎不解析写入内容，因此这里不锁定用户缓冲区——既满足
       「不做无谓的权限提升」也避免在回调中引入额外失败点。
--*/
FLT_PREOP_CALLBACK_STATUS
DragonFilePreWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION NameInfo;
    PVOID WriteBuffer;
    ULONG RuleCode;
    ULONG Action;
    HANDLE ProcessId;
    FLT_PREOP_CALLBACK_STATUS Result;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if ((Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)) != 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DragonMetricsBump(DrgMetricFileWrite, 1);

    if (Data->Iopb->Parameters.Write.Length == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NameInfo = DragonAcquireFileName(Data);
    if (NameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ProcessId = PsGetCurrentProcessId();
    RuleCode = 0;
    Action = DRG_ACTION_REPORT;
    Result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    WriteBuffer = NULL;

    /*
     * 高熵采样只在带 MDL 的写请求上做。
     *
     * MDL 描述的页面已被内存管理器锁定，内核可以直接访问；而没有 MDL 的写
     * 请求其缓冲区是用户态地址，在内核回调里读它需要额外的探测与 SEH 包装，
     * 收益不足以抵消复杂度与风险。实测文件写入绝大多数都带 MDL。
     */
    if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
        WriteBuffer = MmGetSystemAddressForMdlSafe(
                          Data->Iopb->Parameters.Write.MdlAddress,
                          NormalPagePriority | MdlMappingNoExecute);
    }

    if (DragonDecideFile(ProcessId, NameInfo, NULL, DRG_OP_WRITE,
                         WriteBuffer, Data->Iopb->Parameters.Write.Length,
                         &RuleCode, &Action) == TRUE) {
        Result = DragonBlockFileRequest(Data, ProcessId, NameInfo, RuleCode, Action);
    }

    FltReleaseFileNameInformation(NameInfo);
    return Result;
}

/*++
@IRQL: PASSIVE_LEVEL  (Filter Manager 前回调，实际上限 APC_LEVEL)
@brief IRP_MJ_SET_INFORMATION 前回调：只关心「删除」与「重命名」。
--*/
FLT_PREOP_CALLBACK_STATUS
DragonFilePreSetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION NameInfo;
    FILE_INFORMATION_CLASS InformationClass;
    UNICODE_STRING NewName;
    PCUNICODE_STRING NewNamePtr;
    ULONG Operation;
    ULONG RuleCode;
    ULONG Action;
    HANDLE ProcessId;
    FLT_PREOP_CALLBACK_STATUS Result;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DragonMetricsBump(DrgMetricFileSetInfo, 1);

    InformationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (InformationClass == FileDispositionInformation) {
        Operation = DRG_OP_DELETE;
    }
    else if (InformationClass == FileRenameInformation ||
             InformationClass == FileRenameInformationEx) {
        Operation = DRG_OP_RENAME;
    }
    else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NameInfo = DragonAcquireFileName(Data);
    if (NameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NewNamePtr = NULL;

    /*
     * 取重命名后的名字，用于识别「扩展名变更」—— 这是单个操作里信号最强的
     * 勒索特征（.doc → .doc.locked 这类命名正常软件不会做）。
     *
     * FileRenameInformation 的 InfoBuffer 里 FileName 字段就是新名字；它可能是
     * 相对名（取决于 RootDirectory），但判定扩展名足够用。
     */
    if (InformationClass == FileRenameInformation ||
        InformationClass == FileRenameInformationEx) {

        PFILE_RENAME_INFORMATION RenameInfo;
        ULONG NameBytes;

        RenameInfo = (PFILE_RENAME_INFORMATION)
                         Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (RenameInfo != NULL && RenameInfo->FileNameLength > 0) {

            NameBytes = RenameInfo->FileNameLength;

            if (NameBytes > (DRG_BACKUP_PATH_CHARS - 1) * sizeof(WCHAR)) {
                NameBytes = (DRG_BACKUP_PATH_CHARS - 1) * sizeof(WCHAR);
            }

            NewName.Buffer = RenameInfo->FileName;
            NewName.Length = (USHORT)NameBytes;
            NewName.MaximumLength = (USHORT)NameBytes;
            NewNamePtr = &NewName;
        }
    }

    ProcessId = PsGetCurrentProcessId();
    RuleCode = 0;
    Action = DRG_ACTION_REPORT;
    Result = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (DragonDecideFile(ProcessId, NameInfo, NewNamePtr, Operation, NULL, 0,
                         &RuleCode, &Action) == TRUE) {
        Result = DragonBlockFileRequest(Data, ProcessId, NameInfo, RuleCode, Action);
    }

    FltReleaseFileNameInformation(NameInfo);
    return Result;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief IRP_MJ_SET_SECURITY 前回调。

        参考实现对该操作不做策略拦截，这里保持一致：仅返回成功，
        不注册后回调，避免增加无意义开销。
--*/
FLT_PREOP_CALLBACK_STATUS
DragonFilePreSetSecurity(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief IRP_MJ_FILE_SYSTEM_CONTROL 前回调。

        参考实现同样为空实现；保留注册位以便后续扩展（bypass-IO 类控制码等），
        当前不做任何判断。
--*/
FLT_PREOP_CALLBACK_STATUS
DragonFilePreFileSystemControl(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
