/*++
===============================================================================
 Dragon-Drivers / DragonRules.c

 规则数据库：
   · 通配符模式链表管理
   · 规则 JSON 解析（键名即对外数据契约）
   · 规则文件加载（自动推导路径 / 用户态下发）
   · 进程白名单与信任缓存

 并发模型：
   · g_RuleLock（ERESOURCE）保护「规则链表 + 白名单链表」，允许 APC_LEVEL
     调用方以共享方式读取——这正是 Filter Manager / 配置管理器回调的合法 IRQL。
   · g_TrustLock（KSPIN_LOCK）保护信任缓存，临界区内只做非分页内存访问。
===============================================================================
--*/

#include "DragonCommon.h"

#define DRG_ENUM_NAME_MAX    32

/*-----------------------------------------------------------------------------
  全局状态
-----------------------------------------------------------------------------*/
static ERESOURCE      g_RuleLock;
static BOOLEAN        g_RuleLockReady = FALSE;
static PDRG_RULE      g_RuleHead = NULL;
static PDRG_PATTERN   g_TrustedHead = NULL;

static DRG_TRUST_ENTRY g_TrustSlots[DRG_TRUST_SLOTS];
static KSPIN_LOCK      g_TrustLock;
static BOOLEAN         g_TrustReady = FALSE;

/*=============================================================================
  内部：JSON 字符串跨度扫描（零拷贝）
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 扫描一个带引号字符串，返回内部内容的跨度（不复制）。

@param  OutStart   指向内容首字节
@param  OutLength  内容字节数
--*/
static
BOOLEAN
DragonJsonScanStringSpan(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_ PCSTR *OutStart,
    _Out_ PULONG OutLength
    )
{
    PCSTR Start;
    BOOLEAN Escaped;
    CHAR Ch;

    *OutStart = NULL;
    *OutLength = 0;

    DragonJsonSkipSpace(Cursor);

    if (DragonJsonPeek(Cursor) != '"') {
        return FALSE;
    }

    Cursor->Current++;
    Start = Cursor->Current;
    Escaped = FALSE;

    while (Cursor->Current < Cursor->End) {
        Ch = *Cursor->Current;

        if (Ch == '"' && Escaped == FALSE) {
            *OutStart = Start;
            *OutLength = (ULONG)(Cursor->Current - Start);
            Cursor->Current++;
            return TRUE;
        }

        if (Ch == '\\' && Escaped == FALSE) {
            Escaped = TRUE;
        }
        else {
            Escaped = FALSE;
        }

        Cursor->Current++;
    }

    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 把 JSON 字符串跨度转换为宽字符模式串（UTF-8 -> UTF-16 + 反转义）。

@return 成功返回已分配的宽字符缓冲；失败返回 NULL（调用方负责 DragonFree）。
--*/
static
PWCHAR
DragonJsonSpanToWide(
    _In_reads_(Length) PCSTR Start,
    _In_ ULONG Length,
    _Out_ PULONG OutChars
    )
{
    ULONG WideBytes;
    ULONG ResultBytes;
    ULONG FinalBytes;
    PWCHAR Buffer;
    NTSTATUS Status;

    *OutChars = 0;

    if (Length == 0) {
        return NULL;
    }

    WideBytes = 0;
    Status = RtlUTF8ToUnicodeN(NULL, 0, &WideBytes, Start, Length);
    if (!NT_SUCCESS(Status) || WideBytes == 0) {
        return NULL;
    }

    /* 保守上限，避免异常长度导致超大分配 */
    if (WideBytes > (ULONG)(0xFFFC - sizeof(WCHAR))) {
        return NULL;
    }

    Buffer = (PWCHAR)DragonAllocate((SIZE_T)WideBytes + sizeof(WCHAR));
    if (Buffer == NULL) {
        return NULL;
    }

    ResultBytes = 0;
    Status = RtlUTF8ToUnicodeN(Buffer, WideBytes, &ResultBytes, Start, Length);
    if (!NT_SUCCESS(Status)) {
        DragonFree(Buffer);
        return NULL;
    }

    FinalBytes = DragonJsonUnescape(Buffer, ResultBytes / sizeof(WCHAR));
    *OutChars = FinalBytes / sizeof(WCHAR);
    return Buffer;
}

/*++
@IRQL: <= APC_LEVEL
@brief 读取 enum 名称（小写不敏感比较用），存入栈上小缓冲。
--*/
static
BOOLEAN
DragonJsonReadEnumName(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_writes_(NameChars) PCHAR Name,
    _In_ ULONG NameChars
    )
{
    PCSTR Start;
    ULONG Length;
    ULONG Index;

    Name[0] = '\0';

    if (DragonJsonScanStringSpan(Cursor, &Start, &Length) == FALSE) {
        return FALSE;
    }

    if (Length == 0 || Length >= NameChars) {
        return FALSE;
    }

    for (Index = 0; Index < Length; Index++) {
        Name[Index] = Start[Index];
    }
    Name[Length] = '\0';
    return TRUE;
}

/*=============================================================================
  通配符模式链表
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 释放整条模式链表。
--*/
VOID
DragonPatternListFree(
    _Inout_ PDRG_PATTERN *Head
    )
{
    PDRG_PATTERN Current;
    PDRG_PATTERN Next;

    if (Head == NULL) {
        return;
    }

    Current = *Head;
    while (Current != NULL) {
        Next = Current->Next;
        if (Current->Text.Buffer != NULL) {
            DragonFree(Current->Text.Buffer);
            Current->Text.Buffer = NULL;
        }
        DragonFree(Current);
        Current = Next;
    }

    *Head = NULL;
}

/*++
@IRQL: <= APC_LEVEL
@brief 追加模式（大小写不敏感去重）；分配失败静默忽略。
--*/
VOID
DragonPatternListAdd(
    _Inout_ PDRG_PATTERN *Head,
    _In_ PCUNICODE_STRING Text
    )
{
    PDRG_PATTERN Cursor;
    PDRG_PATTERN Node;
    SIZE_T Bytes;

    if (Head == NULL || Text == NULL || Text->Buffer == NULL || Text->Length == 0) {
        return;
    }

    for (Cursor = *Head; Cursor != NULL; Cursor = Cursor->Next) {
        if (RtlEqualUnicodeString(&Cursor->Text, Text, TRUE)) {
            return;
        }
    }

    Node = (PDRG_PATTERN)DragonAllocate(sizeof(DRG_PATTERN));
    if (Node == NULL) {
        return;
    }

    Bytes = (SIZE_T)Text->Length + sizeof(WCHAR);
    Node->Text.Buffer = (PWCHAR)DragonAllocate(Bytes);
    if (Node->Text.Buffer == NULL) {
        DragonFree(Node);
        return;
    }

    RtlCopyMemory(Node->Text.Buffer, Text->Buffer, Text->Length);
    Node->Text.Buffer[Text->Length / sizeof(WCHAR)] = L'\0';
    Node->Text.Length = Text->Length;
    Node->Text.MaximumLength = (USHORT)Bytes;

    Node->Next = *Head;
    *Head = Node;
}

/*++
@IRQL: <= APC_LEVEL
@brief 删除全部匹配的模式（大小写不敏感）。
--*/
VOID
DragonPatternListRemove(
    _Inout_ PDRG_PATTERN *Head,
    _In_ PCUNICODE_STRING Text
    )
{
    PDRG_PATTERN Current;
    PDRG_PATTERN Previous;
    PDRG_PATTERN Victim;

    if (Head == NULL || Text == NULL || Text->Buffer == NULL) {
        return;
    }

    Previous = NULL;
    Current = *Head;

    while (Current != NULL) {
        if (RtlEqualUnicodeString(&Current->Text, Text, TRUE)) {
            Victim = Current;
            Current = Current->Next;

            if (Previous != NULL) {
                Previous->Next = Current;
            }
            else {
                *Head = Current;
            }

            if (Victim->Text.Buffer != NULL) {
                DragonFree(Victim->Text.Buffer);
            }
            DragonFree(Victim);
            continue;
        }

        Previous = Current;
        Current = Current->Next;
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 模式链表中是否存在任一命中。
--*/
BOOLEAN
DragonPatternListMatches(
    _In_opt_ PDRG_PATTERN Head,
    _In_opt_ PCUNICODE_STRING Text
    )
{
    PDRG_PATTERN Cursor;

    if (Head == NULL || Text == NULL || Text->Buffer == NULL) {
        return FALSE;
    }

    for (Cursor = Head; Cursor != NULL; Cursor = Cursor->Next) {
        if (DragonWildcardMatch(Cursor->Text.Buffer, Text->Buffer, Text->Length)) {
            return TRUE;
        }
    }

    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 模式链表中命中的最高特异性评分；未命中返回 0。
--*/
static
ULONG
DragonPatternListBestScore(
    _In_opt_ PDRG_PATTERN Head,
    _In_opt_ PCUNICODE_STRING Text
    )
{
    PDRG_PATTERN Cursor;
    ULONG Best;
    ULONG Score;

    if (Head == NULL || Text == NULL || Text->Buffer == NULL) {
        return 0;
    }

    Best = 0;
    for (Cursor = Head; Cursor != NULL; Cursor = Cursor->Next) {
        if (DragonWildcardMatch(Cursor->Text.Buffer, Text->Buffer, Text->Length)) {
            Score = DragonPatternSpecificity(&Cursor->Text);
            if (Score > Best) {
                Best = Score;
            }
        }
    }

    return Best;
}

/*++
@IRQL: <= APC_LEVEL
@brief Include / Exclude 冲突裁决。

        规则：Exclude 的特异性评分 >= Include 的评分时判为「被排除」。
        Text 为 NULL 表示该维度无上下文，此时只要存在 Include 即视为不匹配。
--*/
BOOLEAN
DragonPatternListConflict(
    _In_opt_ PDRG_PATTERN Include,
    _In_opt_ PDRG_PATTERN Exclude,
    _In_opt_ PCUNICODE_STRING Text
    )
{
    ULONG IncludeScore;
    ULONG ExcludeScore;

    if (Text == NULL) {
        return (Include == NULL) ? TRUE : FALSE;
    }

    if (Include != NULL) {
        IncludeScore = DragonPatternListBestScore(Include, Text);
        if (IncludeScore == 0) {
            return FALSE;
        }
    }
    else {
        IncludeScore = 0;
    }

    if (Exclude != NULL) {
        ExcludeScore = DragonPatternListBestScore(Exclude, Text);
        if (ExcludeScore > 0 && ExcludeScore >= ((Include != NULL) ? IncludeScore : 1)) {
            return FALSE;
        }
    }

    return TRUE;
}

/*=============================================================================
  规则释放
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 释放单条规则及其全部模式链表。
--*/
VOID
DragonRuleFree(
    _In_opt_ PDRG_RULE Rule
    )
{
    if (Rule == NULL) {
        return;
    }

    DragonPatternListFree(&Rule->Initiator);
    DragonPatternListFree(&Rule->InitiatorExclude);
    DragonPatternListFree(&Rule->InitiatorParent);
    DragonPatternListFree(&Rule->InitiatorParentExclude);
    DragonPatternListFree(&Rule->InitiatorTree);
    DragonPatternListFree(&Rule->InitiatorTreeExclude);
    DragonPatternListFree(&Rule->Target);
    DragonPatternListFree(&Rule->TargetExclude);
    DragonPatternListFree(&Rule->TargetTree);
    DragonPatternListFree(&Rule->TargetTreeExclude);
    DragonPatternListFree(&Rule->Creator);
    DragonPatternListFree(&Rule->CreatorExclude);
    DragonPatternListFree(&Rule->Parent);
    DragonPatternListFree(&Rule->ParentExclude);
    DragonPatternListFree(&Rule->CommandLine);
    DragonPatternListFree(&Rule->CommandLineExclude);
    DragonPatternListFree(&Rule->Extensions);
    DragonPatternListFree(&Rule->ValueNames);

    DragonFree(Rule);
}

/*=============================================================================
  规则 JSON 解析
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 解析字符串数组为模式链表。
--*/
static
VOID
DragonJsonParsePatternArray(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Outptr_result_maybenull_ PDRG_PATTERN *Head
    )
{
    PCSTR Start;
    ULONG Length;
    PWCHAR Wide;
    ULONG WideChars;
    UNICODE_STRING Value;

    DragonJsonSkipSpace(Cursor);

    if (DragonJsonPeek(Cursor) != '[') {
        return;
    }
    Cursor->Current++;

    for (;;) {
        DragonJsonSkipSpace(Cursor);

        if (Cursor->Current >= Cursor->End) {
            return;
        }

        if (DragonJsonPeek(Cursor) == ']') {
            Cursor->Current++;
            return;
        }

        if (DragonJsonPeek(Cursor) != '"') {
            /* 数组内出现非字符串项：消费一个值后继续 */
            DragonJsonSkipValue(Cursor);
            DragonJsonSkipSpace(Cursor);
            if (DragonJsonPeek(Cursor) == ',') {
                Cursor->Current++;
            }
            continue;
        }

        if (DragonJsonScanStringSpan(Cursor, &Start, &Length) == TRUE) {
            Wide = DragonJsonSpanToWide(Start, Length, &WideChars);
            if (Wide != NULL && WideChars > 0) {
                Value.Buffer = Wide;
                Value.Length = (USHORT)(WideChars * sizeof(WCHAR));
                Value.MaximumLength = Value.Length;
                DragonPatternListAdd(Head, &Value);
            }
            if (Wide != NULL) {
                DragonFree(Wide);
            }
        }

        DragonJsonSkipSpace(Cursor);
        if (DragonJsonPeek(Cursor) == ',') {
            Cursor->Current++;
        }
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 解析字符串数组并按映射表折算为位掩码。

@return TRUE 表示数组内所有名称均被识别。
--*/
static
BOOLEAN
DragonJsonParseMaskArray(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_ PULONG Mask,
    _In_opt_ const PCSTR *Names,
    _In_opt_ const ULONG *Bits,
    _In_ ULONG EntryCount,
    _In_ BOOLEAN AllowUnlimited
    )
{
    CHAR Name[DRG_ENUM_NAME_MAX];
    ULONG Index;
    ULONG Matched;
    BOOLEAN Valid;

    *Mask = 0;

    DragonJsonSkipSpace(Cursor);

    if (DragonJsonPeek(Cursor) != '[') {
        if (AllowUnlimited == TRUE) {
            return TRUE;
        }
        return FALSE;
    }
    Cursor->Current++;

    Valid = TRUE;
    Matched = 0;

    for (;;) {
        DragonJsonSkipSpace(Cursor);

        if (Cursor->Current >= Cursor->End) {
            break;
        }

        if (DragonJsonPeek(Cursor) == ']') {
            Cursor->Current++;
            break;
        }

        if (DragonJsonPeek(Cursor) != '"') {
            DragonJsonSkipValue(Cursor);
            DragonJsonSkipSpace(Cursor);
            if (DragonJsonPeek(Cursor) == ',') {
                Cursor->Current++;
            }
            continue;
        }

        if (DragonJsonReadEnumName(Cursor, Name, RTL_NUMBER_OF(Name)) == TRUE) {
            Matched = 0;
            for (Index = 0; Index < EntryCount; Index++) {
                if (DragonAnsiEqualNoCase(Name, Names[Index]) == TRUE) {
                    *Mask |= Bits[Index];
                    Matched = 1;
                    break;
                }
            }
            if (Matched == 0) {
                Valid = FALSE;
            }
        }
        else {
            Valid = FALSE;
        }

        DragonJsonSkipSpace(Cursor);
        if (DragonJsonPeek(Cursor) == ',') {
            Cursor->Current++;
        }
    }

    return Valid;
}

/*++
@IRQL: <= APC_LEVEL
@brief 解析三态（true / false）；无法解析时置 Parsed = FALSE。
--*/
static
ULONG
DragonJsonParseTriState(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_ PBOOLEAN Parsed
    )
{
    BOOLEAN Value;

    *Parsed = FALSE;
    Value = FALSE;

    if (DragonJsonReadBoolean(Cursor, &Value) == FALSE) {
        return (ULONG)DrgTriAny;
    }

    *Parsed = TRUE;
    return Value ? (ULONG)DrgTriTrue : (ULONG)DrgTriFalse;
}

/*++
@IRQL: <= APC_LEVEL
@brief 解析 OperationMatch（"Any" / "All"）。
--*/
static
ULONG
DragonJsonParseOperationMatch(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_ PBOOLEAN Parsed
    )
{
    CHAR Name[DRG_ENUM_NAME_MAX];

    *Parsed = FALSE;

    if (DragonJsonReadEnumName(Cursor, Name, RTL_NUMBER_OF(Name)) == FALSE) {
        return (ULONG)DrgOpMatchAny;
    }

    if (DragonAnsiEqualNoCase(Name, "Any") == TRUE) {
        *Parsed = TRUE;
        return (ULONG)DrgOpMatchAny;
    }

    if (DragonAnsiEqualNoCase(Name, "All") == TRUE) {
        *Parsed = TRUE;
        return (ULONG)DrgOpMatchAll;
    }

    return (ULONG)DrgOpMatchAny;
}

/*++
@IRQL: <= APC_LEVEL
@brief 解析 Category。
--*/
static
ULONG
DragonJsonParseCategory(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    CHAR Name[DRG_ENUM_NAME_MAX];

    if (DragonJsonReadEnumName(Cursor, Name, RTL_NUMBER_OF(Name)) == FALSE) {
        return (ULONG)DrgCategoryUnknown;
    }

    if (DragonAnsiEqualNoCase(Name, "Process") == TRUE)  { return (ULONG)DrgCategoryProcess; }
    if (DragonAnsiEqualNoCase(Name, "File") == TRUE)     { return (ULONG)DrgCategoryFile; }
    if (DragonAnsiEqualNoCase(Name, "Registry") == TRUE) { return (ULONG)DrgCategoryRegistry; }
    if (DragonAnsiEqualNoCase(Name, "Device") == TRUE)   { return (ULONG)DrgCategoryDevice; }
    if (DragonAnsiEqualNoCase(Name, "Memory") == TRUE)   { return (ULONG)DrgCategoryMemory; }
    if (DragonAnsiEqualNoCase(Name, "Thread") == TRUE)   { return (ULONG)DrgCategoryThread; }

    return (ULONG)DrgCategoryUnknown;
}

/*++
@IRQL: <= APC_LEVEL
@brief 键名比较（大小写敏感的 ASCII 精确匹配）。
--*/
static
BOOLEAN
DragonKeyEquals(
    _In_reads_(KeyLength) PCSTR Key,
    _In_ ULONG KeyLength,
    _In_ PCSTR Expected
    )
{
    SIZE_T ExpectedLength;

    ExpectedLength = 0;
    while (Expected[ExpectedLength] != '\0') {
        ExpectedLength++;
    }

    if ((SIZE_T)KeyLength != ExpectedLength) {
        return FALSE;
    }

    return (RtlCompareMemory(Key, Expected, ExpectedLength) == ExpectedLength) ? TRUE : FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 规则有效性校验（与类别相关的操作位约束、阈值默认值、区间合理性）。
--*/
static
BOOLEAN
DragonRuleValidate(
    _Inout_ PDRG_RULE Rule
    )
{
    ULONG Allowed;

    if (Rule == NULL || Rule->Invalid == TRUE) {
        return FALSE;
    }

    if (Rule->Code == 0 || Rule->Category == (ULONG)DrgCategoryUnknown || Rule->Operations == 0) {
        return FALSE;
    }

    Allowed = 0;
    switch ((DRG_CATEGORY)Rule->Category) {
        case DrgCategoryProcess:
            Allowed = DRG_OP_EXECUTE | DRG_OP_TERMINATE | DRG_OP_SUSPEND_RESUME |
                      DRG_OP_DUP_HANDLE | DRG_OP_SET_INFORMATION | DRG_OP_THREAD_SET_TOKEN |
                      DRG_OP_CREATE_PROCESS | DRG_OP_IMAGE_LOAD | DRG_OP_IMPERSONATE;
            break;
        case DrgCategoryMemory:
            Allowed = DRG_OP_VM_READ | DRG_OP_VM_WRITE | DRG_OP_VM_OPERATION |
                      DRG_OP_CREATE_THREAD | DRG_OP_THREAD_SET_CONTEXT;
            break;
        case DrgCategoryThread:
            Allowed = DRG_OP_EXECUTE;
            break;
        case DrgCategoryFile:
            Allowed = DRG_OP_WRITE | DRG_OP_DELETE | DRG_OP_CREATE | DRG_OP_EXECUTE | DRG_OP_RENAME;
            break;
        case DrgCategoryRegistry:
            Allowed = DRG_OP_WRITE | DRG_OP_DELETE | DRG_OP_CREATE;
            break;
        case DrgCategoryDevice:
            Allowed = DRG_OP_IOCTL;
            break;
        default:
            return FALSE;
    }

    if ((Rule->Operations & ~Allowed) != 0) {
        return FALSE;
    }

    if (Rule->Threshold > 0 && Rule->TimeWindow == 0) {
        Rule->TimeWindow = DRG_DEFAULT_TIME_WINDOW_MS;
    }

    if (Rule->MaxRisk > 0 && Rule->MaxRisk < Rule->MinRisk) {
        return FALSE;
    }

    if (Rule->MaxRegion > 0 && Rule->MaxRegion < Rule->MinRegion) {
        return FALSE;
    }

    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 解析单个规则对象；返回已填充的规则（未通过校验返回 NULL 并已释放）。
--*/
static
PDRG_RULE
DragonJsonParseRuleObject(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    static const PCSTR OperationNames[] = {
        "Write", "Delete", "Create", "Execute", "Rename", "Ioctl",
        "VmRead", "VmWrite", "WriteMemory", "VmOperation",
        "CreateThread", "CreateRemoteThread", "SetThreadContext",
        "SetThreadToken", "Terminate", "SuspendResume", "DuplicateHandle",
        "SetInformation", "CreateProcess", "ImageLoad", "Impersonate"
    };
    static const ULONG OperationBits[] = {
        DRG_OP_WRITE, DRG_OP_DELETE, DRG_OP_CREATE, DRG_OP_EXECUTE, DRG_OP_RENAME, DRG_OP_IOCTL,
        DRG_OP_VM_READ,
        DRG_OP_VM_WRITE | DRG_OP_VM_OPERATION | DRG_OP_CREATE_THREAD | DRG_OP_THREAD_SET_CONTEXT,
        DRG_OP_VM_WRITE, DRG_OP_VM_OPERATION,
        DRG_OP_CREATE_THREAD, DRG_OP_CREATE_THREAD, DRG_OP_THREAD_SET_CONTEXT,
        DRG_OP_THREAD_SET_TOKEN, DRG_OP_TERMINATE, DRG_OP_SUSPEND_RESUME, DRG_OP_DUP_HANDLE,
        DRG_OP_SET_INFORMATION, DRG_OP_CREATE_PROCESS, DRG_OP_IMAGE_LOAD, DRG_OP_IMPERSONATE
    };
    static const PCSTR HandleNames[] = { "Create", "Duplicate" };
    static const ULONG HandleBits[]   = { DRG_HANDLE_CREATE, DRG_HANDLE_DUPLICATE };
    static const PCSTR ObjectNames[]  = { "Process", "Thread" };
    static const ULONG ObjectBits[]   = { DRG_OBJECT_PROCESS, DRG_OBJECT_THREAD };
    static const PCSTR MemTypeNames[] = { "Private", "Mapped", "Image" };
    static const ULONG MemTypeBits[]  = { DRG_MEMORY_PRIVATE, DRG_MEMORY_MAPPED, DRG_MEMORY_IMAGE };
    static const PCSTR ProtectNames[] = { "Execute", "ExecuteWrite" };
    static const ULONG ProtectBits[]  = { DRG_PROTECT_EXECUTE, DRG_PROTECT_EXECUTE_WRITE };

    PDRG_RULE Rule;
    PCSTR KeyStart;
    ULONG KeyLength;
    CHAR Probe;
    BOOLEAN Parsed;

    Rule = (PDRG_RULE)DragonAllocate(sizeof(DRG_RULE));
    if (Rule == NULL) {
        DragonJsonSkipValue(Cursor);
        return NULL;
    }

    Rule->Category = (ULONG)DrgCategoryUnknown;
    Rule->OperationMatch = (ULONG)DrgOpMatchAny;
    Rule->ParentMismatch = (ULONG)DrgTriAny;
    Rule->FileOpenNameAvailable = (ULONG)DrgTriAny;
    Rule->SubsystemProcess = (ULONG)DrgTriAny;

    /* 动作未指定：0 是合法取值（DRG_ACTION_REPORT），必须显式写成 UNSET，
       否则旧规则文件会从「按 Kill 推断」变成「一律只上报」，行为被静默改变。 */
    Rule->Action = DRG_ACTION_UNSET;

    for (;;) {
        DragonJsonSkipSpace(Cursor);

        if (Cursor->Current >= Cursor->End) {
            break;
        }

        Probe = DragonJsonPeek(Cursor);

        if (Probe == '}') {
            Cursor->Current++;
            break;
        }

        if (Probe != '"') {
            Cursor->Current++;
            continue;
        }

        if (DragonJsonScanStringSpan(Cursor, &KeyStart, &KeyLength) == FALSE) {
            break;
        }

        DragonJsonSkipSpace(Cursor);
        if (DragonJsonPeek(Cursor) != ':') {
            DragonJsonSkipValue(Cursor);
            continue;
        }
        Cursor->Current++;
        DragonJsonSkipSpace(Cursor);

        if (DragonKeyEquals(KeyStart, KeyLength, "Code")) {
            Rule->Code = DragonJsonReadUInt32(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Kill")) {
            if (DragonJsonReadBoolean(Cursor, &Rule->Kill) == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Action")) {
            CHAR ActionName[32];

            RtlZeroMemory(ActionName, sizeof(ActionName));

            if (DragonJsonReadRawString(Cursor, ActionName, RTL_NUMBER_OF(ActionName)) == FALSE) {
                Rule->Invalid = TRUE;
            }
            else if (DragonAnsiEqualNoCase(ActionName, "Report") == TRUE) {
                Rule->Action = DRG_ACTION_REPORT;
            }
            else if (DragonAnsiEqualNoCase(ActionName, "Terminate") == TRUE) {
                Rule->Action = DRG_ACTION_TERMINATE;
            }
            else {
                /* 未知动作按「规则非法」处理，避免静默降级成仅上报 */
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Priority")) {
            Rule->Priority = DragonJsonReadUInt32(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Threshold")) {
            Rule->Threshold = DragonJsonReadUInt32(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "TimeWindow")) {
            Rule->TimeWindow = DragonJsonReadUInt32(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "MinimumRiskScore")) {
            Rule->MinRisk = DragonJsonReadUInt32(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "MaximumRiskScore")) {
            Rule->MaxRisk = DragonJsonReadUInt32(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "MinimumRegionSize")) {
            Rule->MinRegion = DragonJsonReadUInt64(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "MaximumRegionSize")) {
            Rule->MaxRegion = DragonJsonReadUInt64(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Category")) {
            Rule->Category = DragonJsonParseCategory(Cursor);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "OperationMatch")) {
            Rule->OperationMatch = DragonJsonParseOperationMatch(Cursor, &Parsed);
            if (Parsed == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "ParentMismatch")) {
            Rule->ParentMismatch = DragonJsonParseTriState(Cursor, &Parsed);
            if (Parsed == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "FileOpenNameAvailable")) {
            Rule->FileOpenNameAvailable = DragonJsonParseTriState(Cursor, &Parsed);
            if (Parsed == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "SubsystemProcess")) {
            Rule->SubsystemProcess = DragonJsonParseTriState(Cursor, &Parsed);
            if (Parsed == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Initiator")) {
            DragonJsonParsePatternArray(Cursor, &Rule->Initiator);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "InitiatorExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->InitiatorExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "InitiatorParent")) {
            DragonJsonParsePatternArray(Cursor, &Rule->InitiatorParent);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "InitiatorParentExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->InitiatorParentExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "InitiatorProcessTree")) {
            DragonJsonParsePatternArray(Cursor, &Rule->InitiatorTree);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "InitiatorProcessTreeExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->InitiatorTreeExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Target")) {
            DragonJsonParsePatternArray(Cursor, &Rule->Target);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "TargetExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->TargetExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "TargetProcessTree")) {
            DragonJsonParsePatternArray(Cursor, &Rule->TargetTree);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "TargetProcessTreeExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->TargetTreeExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Creator")) {
            DragonJsonParsePatternArray(Cursor, &Rule->Creator);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "CreatorExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->CreatorExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Parent")) {
            DragonJsonParsePatternArray(Cursor, &Rule->Parent);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "ParentExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->ParentExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "CommandLine")) {
            DragonJsonParsePatternArray(Cursor, &Rule->CommandLine);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "CommandLineExclude")) {
            DragonJsonParsePatternArray(Cursor, &Rule->CommandLineExclude);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Extensions")) {
            DragonJsonParsePatternArray(Cursor, &Rule->Extensions);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "ValueNames")) {
            /*
             * 注册表规则的第二层约束：值名。
             *
             * 与 Target 的键路径通配符相互独立 —— 键路径回答「哪个键被碰」，
             * ValueNames 回答「哪个值被改」。两者同时声明时必须都命中。
             * 旧规则不写这个键，行为与之前完全一致。
             */
            DragonJsonParsePatternArray(Cursor, &Rule->ValueNames);
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "Operations")) {
            if (DragonJsonParseMaskArray(
                    Cursor,
                    &Rule->Operations,
                    OperationNames,
                    OperationBits,
                    RTL_NUMBER_OF(OperationNames),
                    FALSE) == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "HandleTypes")) {
            if (DragonJsonParseMaskArray(
                    Cursor,
                    &Rule->HandleTypes,
                    HandleNames,
                    HandleBits,
                    RTL_NUMBER_OF(HandleNames),
                    TRUE) == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "ObjectTypes")) {
            if (DragonJsonParseMaskArray(
                    Cursor,
                    &Rule->ObjectTypes,
                    ObjectNames,
                    ObjectBits,
                    RTL_NUMBER_OF(ObjectNames),
                    TRUE) == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "ThreadMemoryTypes")) {
            if (DragonJsonParseMaskArray(
                    Cursor,
                    &Rule->ThreadMemoryTypes,
                    MemTypeNames,
                    MemTypeBits,
                    RTL_NUMBER_OF(MemTypeNames),
                    TRUE) == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else if (DragonKeyEquals(KeyStart, KeyLength, "ThreadMemoryProtections")) {
            if (DragonJsonParseMaskArray(
                    Cursor,
                    &Rule->ThreadMemoryProtections,
                    ProtectNames,
                    ProtectBits,
                    RTL_NUMBER_OF(ProtectNames),
                    TRUE) == FALSE) {
                Rule->Invalid = TRUE;
            }
        }
        else {
            DragonJsonSkipValue(Cursor);
        }

        DragonJsonSkipSpace(Cursor);
        if (DragonJsonPeek(Cursor) == ',') {
            Cursor->Current++;
        }
    }

    if (DragonRuleValidate(Rule) == FALSE) {
        DragonRuleFree(Rule);
        return NULL;
    }

    return Rule;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 解析规则 JSON 文本，把有效规则挂到全局链表头部。

@return 新增的规则条数。
--*/
ULONG
DragonRulesParseJson(
    _In_ PCSTR Buffer,
    _In_ ULONG Length
    )
{
    static const CHAR RulesKey[] = "\"DynamicRules\"";
    DRG_JSON_CURSOR Cursor;
    PDRG_RULE Rule;
    ULONG Added;
    CHAR Probe;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    DragonJsonInit(&Cursor, Buffer, Length);

    if (DragonJsonSeekKey(&Cursor, RulesKey) == FALSE) {
        return 0;
    }

    if (DragonJsonPeek(&Cursor) != '[') {
        return 0;
    }
    Cursor.Current++;

    Added = 0;

    for (;;) {
        DragonJsonSkipSpace(&Cursor);

        if (Cursor.Current >= Cursor.End) {
            break;
        }

        Probe = DragonJsonPeek(&Cursor);

        if (Probe == ']') {
            Cursor.Current++;
            break;
        }

        if (Probe != '{') {
            Cursor.Current++;
            continue;
        }

        Cursor.Current++;
        Rule = DragonJsonParseRuleObject(&Cursor);
        if (Rule != NULL) {
            Rule->Next = g_RuleHead;
            g_RuleHead = Rule;
            Added++;
        }
    }

    return Added;
}

/*=============================================================================
  规则文件加载
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 读取并解析一个规则 JSON 文件（FilePath 必须是已带 \??\ 前缀的 NT 路径）。
--*/
NTSTATUS
DragonRulesLoadFile(
    _In_ PCUNICODE_STRING FilePath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE FileHandle;
    FILE_STANDARD_INFORMATION FileInfo;
    PVOID FileBuffer;
    ULONG FileSize;
    PDRG_RULE PreviousHead;
    ULONG Added;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * ZwCreateFile / ZwReadFile / ZwQueryInformationFile 的官方 IRQL 约束是
     * PASSIVE_LEVEL。本函数只由两条 PASSIVE 路径调用（驱动启动时的自动加载、
     * 通信端口命令 3），此处做显式断言以便未来调用点变化时立即暴露问题。
     */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    Status = STATUS_SUCCESS;
    FileHandle = NULL;
    FileBuffer = NULL;
    FileSize = 0;

    InitializeObjectAttributes(
        &Attributes,
        (PUNICODE_STRING)FilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &FileHandle,
                 GENERIC_READ | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ,
                 FILE_OPEN,
                 FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    RtlZeroMemory(&FileInfo, sizeof(FileInfo));
    Status = ZwQueryInformationFile(
                 FileHandle,
                 &IoStatus,
                 &FileInfo,
                 sizeof(FileInfo),
                 FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    if (FileInfo.EndOfFile.HighPart != 0) {
        Status = STATUS_FILE_TOO_LARGE;
        goto Exit;
    }

    if (FileInfo.EndOfFile.LowPart > DRG_MAX_RULE_FILE_BYTES) {
        Status = STATUS_FILE_TOO_LARGE;
        goto Exit;
    }

    FileSize = FileInfo.EndOfFile.LowPart;
    if (FileSize == 0) {
        Status = STATUS_END_OF_FILE;
        goto Exit;
    }

    FileBuffer = DragonAllocate((SIZE_T)FileSize + sizeof(CHAR));
    if (FileBuffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(&IoStatus, sizeof(IoStatus));
    Status = ZwReadFile(
                 FileHandle,
                 NULL,
                 NULL,
                 NULL,
                 &IoStatus,
                 FileBuffer,
                 FileSize,
                 NULL,
                 NULL);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    if (IoStatus.Information != FileSize) {
        Status = STATUS_END_OF_FILE;
        goto Exit;
    }

    ((PCHAR)FileBuffer)[FileSize] = '\0';

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&g_RuleLock, TRUE);

    PreviousHead = g_RuleHead;
    Added = DragonRulesParseJson((PCSTR)FileBuffer, FileSize);
    if (g_RuleHead == PreviousHead) {
        Status = (Added == 0) ? STATUS_DATA_ERROR : STATUS_SUCCESS;
    }
    else {
        Status = STATUS_SUCCESS;
    }

    ExReleaseResourceLite(&g_RuleLock);
    KeLeaveCriticalRegion();

Exit:
    if (FileBuffer != NULL) {
        DragonFree(FileBuffer);
    }

    if (FileHandle != NULL) {
        ZwClose(FileHandle);
    }

    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 从驱动服务的 ImagePath 推导规则文件路径并加载。

        推导规则：取 ImagePath，去掉最后一段文件名；若此时以 "\Filter" 结尾
        则再剥掉该目录；最后追加 DRG_AUTO_RULE_SUBPATH。
        缺失 \??\ / \SystemRoot / \DosDevices\ 前缀时补 \??\。
--*/
NTSTATUS
DragonRulesLoadFromDisk(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES KeyAttributes;
    HANDLE KeyHandle;
    ULONG ResultLength;
    ULONG ProbeLength;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    UNICODE_STRING ValueName;
    PWCHAR PathBuffer;
    SIZE_T PathBufferBytes;
    PWCHAR LastSeparator;
    PWCHAR Cursor;
    SIZE_T PathChars;
    SIZE_T TailChars;
    PCWSTR Prefix;
    UNICODE_STRING FinalPath;
    static const WCHAR FilterSuffix[] = L"\\Filter";

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = STATUS_SUCCESS;
    KeyHandle = NULL;
    Info = NULL;
    PathBuffer = NULL;
    FinalPath.Buffer = NULL;
    FinalPath.Length = 0;
    FinalPath.MaximumLength = 0;

    RtlInitUnicodeString(&ValueName, L"ImagePath");

    InitializeObjectAttributes(
        &KeyAttributes,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &KeyAttributes);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    ResultLength = 0;
    Status = ZwQueryValueKey(
                 KeyHandle,
                 &ValueName,
                 KeyValuePartialInformation,
                 NULL,
                 0,
                 &ResultLength);
    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) {
        goto Exit;
    }

    if (ResultLength == 0 || ResultLength > 0x10000) {
        Status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }

    Info = (PKEY_VALUE_PARTIAL_INFORMATION)DragonAllocate(ResultLength);
    if (Info == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    ProbeLength = ResultLength;
    Status = ZwQueryValueKey(
                 KeyHandle,
                 &ValueName,
                 KeyValuePartialInformation,
                 Info,
                 ProbeLength,
                 &ResultLength);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    if (Info->Type != REG_SZ && Info->Type != REG_EXPAND_SZ) {
        Status = STATUS_OBJECT_TYPE_MISMATCH;
        goto Exit;
    }

    if (Info->DataLength == 0 || (Info->DataLength % sizeof(WCHAR)) != 0) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    /* 预留 +1024 字节用于追加子路径与前缀改写 */
    PathBufferBytes = (SIZE_T)Info->DataLength + (SIZE_T)1024 * sizeof(WCHAR);
    PathBuffer = (PWCHAR)DragonAllocate(PathBufferBytes);
    if (PathBuffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(PathBuffer, PathBufferBytes);
    RtlCopyMemory(PathBuffer, Info->Data, Info->DataLength);

    LastSeparator = NULL;
    Cursor = PathBuffer;
    while (*Cursor != L'\0') {
        if (*Cursor == L'\\') {
            LastSeparator = Cursor;
        }
        Cursor++;
    }

    if (LastSeparator == NULL) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *LastSeparator = L'\0';

    PathChars = 0;
    while (PathBuffer[PathChars] != L'\0') {
        PathChars++;
    }

    TailChars = (sizeof(FilterSuffix) / sizeof(WCHAR)) - 1;
    if (PathChars >= TailChars) {
        PWCHAR Tail = PathBuffer + (PathChars - TailChars);
        SIZE_T Index;
        BOOLEAN Same = TRUE;

        for (Index = 0; Index < TailChars; Index++) {
            if (RtlDowncaseUnicodeChar(Tail[Index]) != RtlDowncaseUnicodeChar(FilterSuffix[Index])) {
                Same = FALSE;
                break;
            }
        }

        if (Same == TRUE) {
            *Tail = L'\0';
        }
    }

    Status = RtlStringCbCatW(PathBuffer, PathBufferBytes, DRG_AUTO_RULE_SUBPATH);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    /*
     * 路径前缀补全。
     *
     * 驱动服务 ImagePath 有三种常见形态，必须分别处理，否则规则文件必然读不到：
     *   · NT 设备路径（\??\ 开头）或 \SystemRoot\ / \DosDevices\ 开头 —— 原样使用；
     *   · 带盘符的绝对路径（C:\Windows\...）—— 补 \??\ 后成为有效 NT 路径；
     *   · 相对 SystemRoot 的路径（system32\drivers\x.sys）—— 必须补 \SystemRoot\，
     *     若错补成 \??\system32\... 会指向不存在的设备名。
     */
    Prefix = NULL;

    if (DragonWideStartsWithNoCase(PathBuffer, L"\\??\\") == TRUE ||
        DragonWideStartsWithNoCase(PathBuffer, L"\\SystemRoot") == TRUE ||
        DragonWideStartsWithNoCase(PathBuffer, L"\\DosDevices\\") == TRUE) {

        Prefix = NULL;
    }
    else if (PathBuffer[0] != L'\0' && PathBuffer[1] == L':') {
        Prefix = L"\\??\\";
    }
    else {
        Prefix = L"\\SystemRoot\\";
    }

    if (Prefix != NULL) {
        SIZE_T PrefixChars;
        SIZE_T PrefixBytes;
        PWCHAR Prefixed;

        PrefixChars = 0;
        while (Prefix[PrefixChars] != L'\0') {
            PrefixChars++;
        }
        PrefixBytes = (PrefixChars + 1) * sizeof(WCHAR);

        Prefixed = (PWCHAR)DragonAllocate(PathBufferBytes + PrefixBytes);
        if (Prefixed == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        RtlZeroMemory(Prefixed, PathBufferBytes + PrefixBytes);
        Status = RtlStringCbCopyW(Prefixed, PathBufferBytes + PrefixBytes, Prefix);
        if (NT_SUCCESS(Status)) {
            Status = RtlStringCbCatW(Prefixed, PathBufferBytes + PrefixBytes, PathBuffer);
        }

        DragonFree(PathBuffer);
        PathBuffer = Prefixed;

        if (!NT_SUCCESS(Status)) {
            goto Exit;
        }
    }

    {
        UNICODE_STRING LogPath;
        RtlInitUnicodeString(&LogPath, PathBuffer);
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "Dragon-Drivers: rule file path = %wZ\n",
            &LogPath);
    }

    RtlInitUnicodeString(&FinalPath, PathBuffer);

    Status = DragonRulesLoadFile(&FinalPath);
    if (NT_SUCCESS(Status)) {
        g_Dragon.RulesLoadedFromDisk = TRUE;
    }

Exit:
    if (PathBuffer != NULL) {
        DragonFree(PathBuffer);
    }

    if (Info != NULL) {
        DragonFree(Info);
    }

    if (KeyHandle != NULL) {
        ZwClose(KeyHandle);
    }

    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 清空动态规则、行为统计与信任缓存。
--*/
VOID
DragonRulesClear(
    VOID
    )
{
    PDRG_RULE Current;
    PDRG_RULE Next;

    if (g_RuleLockReady == FALSE) {
        return;
    }

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&g_RuleLock, TRUE);

    Current = g_RuleHead;
    while (Current != NULL) {
        Next = Current->Next;
        DragonRuleFree(Current);
        Current = Next;
    }
    g_RuleHead = NULL;

    ExReleaseResourceLite(&g_RuleLock);
    KeLeaveCriticalRegion();

    g_Dragon.RulesLoadedFromDisk = FALSE;

    DragonBehaviorReset();
    DragonTrustCacheReset();
}

/*=============================================================================
  规则遍历（供 DragonEvaluate.c 使用）
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 以共享方式获取规则数据库锁；调用方必须配套调用 Release。
--*/
VOID
DragonRulesAcquireShared(
    VOID
    )
{
    if (g_RuleLockReady == FALSE) {
        return;
    }

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceSharedLite(&g_RuleLock, TRUE);
}

/*++
@IRQL: <= APC_LEVEL
@brief 释放规则数据库锁。
--*/
VOID
DragonRulesReleaseShared(
    VOID
    )
{
    if (g_RuleLockReady == FALSE) {
        return;
    }

    ExReleaseResourceLite(&g_RuleLock);
    KeLeaveCriticalRegion();
}

/*++
@IRQL: <= APC_LEVEL
@brief 取规则链表头（必须在持有共享锁期间使用）。
--*/
PDRG_RULE
DragonRulesHead(
    VOID
    )
{
    return g_RuleHead;
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 初始化规则引擎（锁、缓存）。
--*/
NTSTATUS
DragonRulesInitialize(
    VOID
    )
{
    NTSTATUS Status;

    if (g_RuleLockReady == TRUE) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_RuleLock, sizeof(g_RuleLock));
    Status = ExInitializeResourceLite(&g_RuleLock);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    g_RuleLockReady = TRUE;

    KeInitializeSpinLock(&g_TrustLock);
    RtlZeroMemory(g_TrustSlots, sizeof(g_TrustSlots));
    g_TrustReady = TRUE;

    g_RuleHead = NULL;
    g_TrustedHead = NULL;

    DragonBehaviorInitialize();

    g_Dragon.RulesEngineReady = TRUE;
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 反初始化规则引擎（必须在所有回调注销之后调用）。
--*/
VOID
DragonRulesTeardown(
    VOID
    )
{
    if (g_RuleLockReady == FALSE) {
        return;
    }

    DragonRulesClear();

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&g_RuleLock, TRUE);
    DragonPatternListFree(&g_TrustedHead);
    ExReleaseResourceLite(&g_RuleLock);
    KeLeaveCriticalRegion();

    g_TrustReady = FALSE;
    g_RuleLockReady = FALSE;
    g_Dragon.RulesEngineReady = FALSE;

    ExDeleteResourceLite(&g_RuleLock);
}

/*=============================================================================
  白名单
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 追加白名单模式并失效信任缓存。
--*/
VOID
DragonTrustedAdd(
    _In_ PUNICODE_STRING Pattern
    )
{
    if (g_RuleLockReady == FALSE || Pattern == NULL || Pattern->Buffer == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&g_RuleLock, TRUE);
    DragonPatternListAdd(&g_TrustedHead, Pattern);
    ExReleaseResourceLite(&g_RuleLock);
    KeLeaveCriticalRegion();

    DragonTrustCacheReset();
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 删除白名单模式并失效信任缓存。
--*/
VOID
DragonTrustedRemove(
    _In_ PUNICODE_STRING Pattern
    )
{
    if (g_RuleLockReady == FALSE || Pattern == NULL || Pattern->Buffer == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&g_RuleLock, TRUE);
    DragonPatternListRemove(&g_TrustedHead, Pattern);
    ExReleaseResourceLite(&g_RuleLock);
    KeLeaveCriticalRegion();

    DragonTrustCacheReset();
}

/*=============================================================================
  信任缓存
=============================================================================*/

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 清空信任缓存。
--*/
VOID
DragonTrustCacheReset(
    VOID
    )
{
    KIRQL OldIrql;

    if (g_TrustReady == FALSE) {
        return;
    }

    KeAcquireSpinLock(&g_TrustLock, &OldIrql);
    RtlZeroMemory(g_TrustSlots, sizeof(g_TrustSlots));
    KeReleaseSpinLock(&g_TrustLock, OldIrql);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 缓存槽下标：PID 低位散列。
--*/
static
ULONG
DragonTrustSlotIndex(
    _In_ HANDLE ProcessId
    )
{
    return (((ULONG)(ULONG_PTR)ProcessId) >> 2) & (DRG_TRUST_SLOTS - 1);
}

/*++
@IRQL: <= APC_LEVEL
@brief 判定进程是否受信任。

        受信任的三种情形：
          1. 系统 Idle(0) / System(4)；
          2. 已连接的客户端进程；
          3. 镜像路径命中白名单通配符。

        缓存只保存 PID + 创建时间，命中时重新按 PID 解析进程对象并比对创建时间，
        因此不存在悬挂的 EPROCESS 指针。
--*/
BOOLEAN
DragonIsProcessTrusted(
    _In_ HANDLE ProcessId
    )
{
    ULONG PidValue;
    PEPROCESS Process;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER Now;
    ULONG Slot;
    BOOLEAN Cached;
    BOOLEAN Result;
    PUNICODE_STRING ImagePath;
    NTSTATUS Status;
    KIRQL OldIrql;

    PidValue = (ULONG)(ULONG_PTR)ProcessId;

    if (PidValue == 0 || PidValue == 4) {
        return TRUE;
    }

    if (PidValue == (ULONG)InterlockedCompareExchange(&g_Dragon.ClientPid, 0, 0) &&
        PidValue != 0) {
        return TRUE;
    }

    if (DragonAtPassiveLevel() == FALSE) {
        /* 非 PASSIVE 无法解析镜像路径，按「不受信任」处理 */
        return FALSE;
    }

    Process = NULL;
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status) || Process == NULL) {
        return FALSE;
    }

    CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
    Now = DragonNow();
    Slot = DragonTrustSlotIndex(ProcessId);

    Cached = FALSE;
    Result = FALSE;

    KeAcquireSpinLock(&g_TrustLock, &OldIrql);
    if (g_TrustSlots[Slot].Pid == ProcessId &&
        g_TrustSlots[Slot].CreateTime.QuadPart == CreateTime.QuadPart &&
        (Now.QuadPart - g_TrustSlots[Slot].Stamp.QuadPart) <
            ((LONGLONG)DRG_TRUST_TTL_SECONDS * 10000000LL)) {
        Result = g_TrustSlots[Slot].Trusted;
        Cached = TRUE;
    }
    KeReleaseSpinLock(&g_TrustLock, OldIrql);

    if (Cached == TRUE) {
        ObDereferenceObject(Process);
        return Result;
    }

    ImagePath = NULL;
    Result = FALSE;

    Status = SeLocateProcessImageName(Process, &ImagePath);
    if (NT_SUCCESS(Status) && ImagePath != NULL && ImagePath->Buffer != NULL && ImagePath->Length > 0) {

        if (g_RuleLockReady == TRUE) {
            KeEnterCriticalRegion();
            (VOID)ExAcquireResourceSharedLite(&g_RuleLock, TRUE);
            Result = DragonPatternListMatches(g_TrustedHead, ImagePath);
            ExReleaseResourceLite(&g_RuleLock);
            KeLeaveCriticalRegion();
        }
    }

    if (ImagePath != NULL) {
        ExFreePool(ImagePath);
    }

    if (g_TrustReady == TRUE) {
        KeAcquireSpinLock(&g_TrustLock, &OldIrql);
        g_TrustSlots[Slot].Pid = ProcessId;
        g_TrustSlots[Slot].CreateTime = CreateTime;
        g_TrustSlots[Slot].Trusted = Result;
        g_TrustSlots[Slot].Stamp = Now;
        KeReleaseSpinLock(&g_TrustLock, OldIrql);
    }

    ObDereferenceObject(Process);
    return Result;
}

/*=============================================================================
  客户端身份（免检镜像路径）
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 从已打开的注册表键读取 ClientImagePath 值并登记为客户端身份。

        安全要点：
          · 只接受 REG_SZ / REG_EXPAND_SZ；
          · 长度必须是 WCHAR 的整数倍且不超过内部缓冲；
          · 去除尾部 NUL 后重新计算 Length，避免长度欺骗。
--*/
static
NTSTATUS
DragonReadClientImageValue(
    _In_ HANDLE KeyHandle
    )
{
    NTSTATUS Status;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    ULONG ProbeLength;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG Chars;

    Info = NULL;
    Status = STATUS_SUCCESS;

    RtlInitUnicodeString(&ValueName, L"ClientImagePath");

    ResultLength = 0;
    Status = ZwQueryValueKey(
                 KeyHandle,
                 &ValueName,
                 KeyValuePartialInformation,
                 NULL,
                 0,
                 &ResultLength);
    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) {
        goto Exit;
    }

    if (ResultLength == 0 ||
        ResultLength > (ULONG)(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                               g_Dragon.ClientImagePath.MaximumLength)) {
        Status = STATUS_NAME_TOO_LONG;
        goto Exit;
    }

    Info = (PKEY_VALUE_PARTIAL_INFORMATION)DragonAllocate(ResultLength);
    if (Info == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    ProbeLength = ResultLength;
    Status = ZwQueryValueKey(
                 KeyHandle,
                 &ValueName,
                 KeyValuePartialInformation,
                 Info,
                 ProbeLength,
                 &ResultLength);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    if ((Info->Type != REG_SZ && Info->Type != REG_EXPAND_SZ) ||
        Info->DataLength < sizeof(WCHAR) ||
        (Info->DataLength % sizeof(WCHAR)) != 0 ||
        Info->DataLength >= g_Dragon.ClientImagePath.MaximumLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RtlZeroMemory(g_Dragon.ClientImagePath.Buffer, g_Dragon.ClientImagePath.MaximumLength);
    RtlCopyMemory(g_Dragon.ClientImagePath.Buffer, Info->Data, Info->DataLength);

    Chars = Info->DataLength / sizeof(WCHAR);
    while (Chars > 0 && g_Dragon.ClientImagePath.Buffer[Chars - 1] == L'\0') {
        Chars--;
    }

    if (Chars == 0) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    g_Dragon.ClientImagePath.Buffer[Chars] = L'\0';
    g_Dragon.ClientImagePath.Length = (USHORT)(Chars * sizeof(WCHAR));
    g_Dragon.ClientIdentityReady = TRUE;
    Status = STATUS_SUCCESS;

Exit:
    if (Info != NULL) {
        DragonFree(Info);
    }

    if (!NT_SUCCESS(Status)) {
        /* 取值失败：清空记录，避免留下半截状态让授权判断误放行 */
        RtlZeroMemory(g_Dragon.ClientImagePath.Buffer, g_Dragon.ClientImagePath.MaximumLength);
        g_Dragon.ClientImagePath.Length = 0;
        g_Dragon.ClientIdentityReady = FALSE;
    }

    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 定位并加载客户端身份登记。

        查找顺序（两种部署写法都支持）：
          1. <服务键>\Parameters\ClientImagePath —— INF 与部署脚本写入的位置；
          2. <服务键>\ClientImagePath            —— 手工部署时可能写在这里。

        两处都取不到时驱动仍照常加载并在内核侧执行规则，但通信端口会拒绝
        一切连接（DragonIsAuthorizedClient 在登记为空时直接返回 FALSE）。
--*/
NTSTATUS
DragonClientIdentityLoad(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    OBJECT_ATTRIBUTES ParametersAttributes;
    HANDLE KeyHandle;
    HANDLE ParametersHandle;
    UNICODE_STRING ParametersName;

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_Dragon.ClientImagePath.Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeyHandle = NULL;
    ParametersHandle = NULL;
    Status = STATUS_SUCCESS;

    InitializeObjectAttributes(
        &Attributes,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &Attributes);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    RtlInitUnicodeString(&ParametersName, L"Parameters");
    InitializeObjectAttributes(
        &ParametersAttributes,
        &ParametersName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        KeyHandle,
        NULL);

    Status = ZwOpenKey(&ParametersHandle, KEY_READ, &ParametersAttributes);
    if (NT_SUCCESS(Status)) {
        Status = DragonReadClientImageValue(ParametersHandle);
    }
    else {
        ParametersHandle = NULL;
    }

    if (!NT_SUCCESS(Status)) {
        Status = DragonReadClientImageValue(KeyHandle);
    }

Exit:
    if (ParametersHandle != NULL) {
        ZwClose(ParametersHandle);
    }

    if (KeyHandle != NULL) {
        ZwClose(KeyHandle);
    }

    return Status;
}
