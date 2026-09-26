/*++
===============================================================================
 Dragon-Drivers / DragonSelfProtect.c

 天龙神盾 内核防护驱动 —— 内置自保护。

 与动态规则的本质区别（这是本模块存在的理由）：
   · 动态规则由用户态经通信端口下发，DrgCmdClearRules 可以整表清空；
     若把自身防护交给规则文件，攻击者只需清空规则即可解除自保护。
   · 本模块的全部保护面在编译期固化，受保护路径在启动时从服务键 ImagePath
     推导（支持任意安装位置），用户态无法增删改。

 保护面：
   1. 驱动自身镜像文件      —— 写 / 覆盖 / 删 / 改名 一律拒绝；
   2. 规则目录（…\Rules\）  —— 同上；
   3. 驱动服务注册表键      —— 建子键 / 写值 / 删值 / 删键 一律拒绝；
   4. 已连接的客户端进程    —— 从其它进程的期望访问掩码中剥掉处置类权限
                               （PROCESS_TERMINATE / PROCESS_SUSPEND_RESUME、
                                 THREAD_TERMINATE / THREAD_SUSPEND_RESUME），
                               属于防御性收敛：只削减别人能对它做什么。

 不设例外：
   连登记的客户端也不放行 1/2/3 —— 升级自身必须先停掉驱动（停掉后过滤回调
   随过滤器反注册一起消失，自保护自然失效）。这样就不存在「把恶意程序放到
   客户端路径即可绕过自保护」的缺口。

 路径比较策略：
   先去掉「卷 / 盘符 / 设备名」前缀，再做**整体等值**比较，而不是后缀比较，
   避免把其它卷上的同名路径误判为自身镜像而误拦。
===============================================================================
--*/

#include "DragonCommon.h"

/*-----------------------------------------------------------------------------
  受保护路径：全部保存为「去卷前缀」后的规范化形式
-----------------------------------------------------------------------------*/
typedef struct _DRG_SELF_STATE {
    BOOLEAN Ready;
    ULONG   ImageChars;
    WCHAR   Image[DRG_PATH_CHARS];
    ULONG   RuleDirChars;
    WCHAR   RuleDir[DRG_PATH_CHARS];
    ULONG   ServiceKeyChars;
    WCHAR   ServiceKey[DRG_PATH_CHARS];

    /* 主程序 / 主程序外置文件保护清单（来自 <服务键>\Parameters\GuardPaths） */
    ULONG   GuardPathCount;
    WCHAR   GuardPaths[DRG_GUARD_PATH_SLOTS][DRG_GUARD_PATH_CHARS];

    /*
     * 内部豁免目录（由数据面模块登记，当前只有勒索备份区）。
     *
     * 这些目录的共同特征是：驱动自身必须往里写，同时又可能落在 GuardPaths
     * 的覆盖范围内 —— 而自保护只按路径判定、不看发起者，不豁免就等于把驱动
     * 自己的备份写入一并挡掉（现场表现是「评分正常、备份数恒为 0」）。
     * 因此按「内核自身放行、外部发起者照拦」处理，而不是无条件放行。
     */
    ULONG   ExemptCount;
    ULONG   ExemptChars[DRG_SELF_EXEMPT_SLOTS];
    WCHAR   ExemptDirs[DRG_SELF_EXEMPT_SLOTS][DRG_PATH_CHARS];
} DRG_SELF_STATE;

static DRG_SELF_STATE g_Self;

/* System 进程（ntoskrnl 的内核部分）的 PID —— 内核自身发起的 I/O 都记在它名下 */
#define DRG_SELF_SYSTEM_PID  4u

/* 触发自保护的文件操作位 */
#define DRG_SELF_FILE_OPS  (DRG_OP_WRITE | DRG_OP_DELETE | DRG_OP_RENAME | \
                            DRG_OP_CREATE | DRG_OP_SET_INFORMATION)

/* 触发自保护的注册表操作位（读 / 打开不拦，避免影响 SCM 与服务查询） */
#define DRG_SELF_REG_OPS   (DRG_OP_WRITE | DRG_OP_DELETE | DRG_OP_CREATE | \
                            DRG_OP_SET_INFORMATION)

/* 规则目录名（与 DRG_AUTO_RULE_SUBPATH 的第一段保持一致） */
static const WCHAR g_SelfRuleDirName[] = L"\\Rules\\";

/* GuardPaths 注册表值允许的最大字节数（防御异常大的值） */
#define DRG_SELF_GUARD_VALUE_MAX_BYTES  (256u * 1024u)

static const WCHAR g_SelfImagePrefix[]  = L"\\??\\";
static const WCHAR g_SelfDosPrefix[]    = L"\\DosDevices\\";
static const WCHAR g_SelfDevicePrefix[] = L"\\Device\\";
static const WCHAR g_SelfRootPrefix[]   = L"\\SystemRoot";
static const WCHAR g_SelfWindowsName[]  = L"\\Windows";

/*=============================================================================
  字符串比较（全部带显式长度，不依赖结尾 NUL）
=============================================================================*/

/*++
@IRQL: 任意
@brief 定长、大小写不敏感的前缀判断。
--*/
static
BOOLEAN
DragonSelfPrefixNoCase(
    _In_reads_(TextChars) PCWSTR Text,
    _In_ ULONG TextChars,
    _In_reads_(PrefixChars) PCWSTR Prefix,
    _In_ ULONG PrefixChars
    )
{
    ULONG Index;

    if (TextChars < PrefixChars) {
        return FALSE;
    }

    for (Index = 0; Index < PrefixChars; Index++) {
        if (RtlDowncaseUnicodeChar(Text[Index]) != RtlDowncaseUnicodeChar(Prefix[Index])) {
            return FALSE;
        }
    }

    return TRUE;
}

/*++
@IRQL: 任意
@brief 定长、大小写不敏感的等值判断。
--*/
static
BOOLEAN
DragonSelfEqualNoCase(
    _In_reads_(LeftChars) PCWSTR Left,
    _In_ ULONG LeftChars,
    _In_reads_(RightChars) PCWSTR Right,
    _In_ ULONG RightChars
    )
{
    ULONG Index;

    if (LeftChars != RightChars) {
        return FALSE;
    }

    for (Index = 0; Index < LeftChars; Index++) {
        if (RtlDowncaseUnicodeChar(Left[Index]) != RtlDowncaseUnicodeChar(Right[Index])) {
            return FALSE;
        }
    }

    return TRUE;
}

/*=============================================================================
  路径规范化
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 去掉「卷 / 盘符 / 设备名」前缀，输出规范化路径。

        支持的输入形态：
          \??\C:\Windows\...            -> \Windows\...
          \DosDevices\C:\Windows\...    -> \Windows\...
          \Device\HarddiskVolume3\...   -> \Windows\...
          \SystemRoot\System32\...      -> \Windows\System32\...
          C:\Windows\...                -> \Windows\...
          \Registry\Machine\...         -> 原样（注册表键路径）
          system32\drivers\x.sys        -> \system32\drivers\x.sys（相对路径补前导反斜杠）

@return TRUE 表示 OutChars 有效。
--*/
static
BOOLEAN
DragonSelfNormalize(
    _In_ PCUNICODE_STRING Path,
    _Out_writes_(Capacity) PWCHAR Buffer,
    _In_ ULONG Capacity,
    _Out_ PULONG OutChars
    )
{
    ULONG Chars;
    ULONG Start;
    ULONG Index;
    ULONG Out;
    BOOLEAN SystemRoot;

    if (Path == NULL || Path->Buffer == NULL || Buffer == NULL || OutChars == NULL) {
        return FALSE;
    }

    if (Capacity < 2) {
        return FALSE;
    }

    Chars = Path->Length / sizeof(WCHAR);
    if (Chars == 0) {
        return FALSE;
    }

    Start = 0;
    SystemRoot = FALSE;

    if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfImagePrefix, 4) == TRUE) {
        Start = 4;
    }
    else if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfDosPrefix, 12) == TRUE) {
        Start = 12;
    }
    else if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfDevicePrefix, 8) == TRUE) {

        /* \Device\<设备名>\... —— 跳到设备名之后的反斜杠 */
        Index = 8;
        while (Index < Chars && Path->Buffer[Index] != L'\\') {
            Index++;
        }
        Start = Index;
    }
    else if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfRootPrefix, 11) == TRUE) {

        /* \SystemRoot 等价于 Windows 目录，替换为 \Windows 后继续 */
        Start = 11;
        SystemRoot = TRUE;
    }

    /* 盘符：可能出现在 \??\ / \DosDevices\ 之后，也可能出现在最前面 */
    if (SystemRoot == FALSE &&
        (Start + 1) < Chars &&
        Path->Buffer[Start + 1] == L':') {
        Start += 2;
    }

    Out = 0;

    if (SystemRoot == TRUE) {
        while (Out < 8 && Out + 1 < Capacity) {
            Buffer[Out] = g_SelfWindowsName[Out];
            Out++;
        }
    }
    else if (Path->Buffer[Start] != L'\\') {
        /* 相对路径：补一个前导反斜杠，保证与绝对路径尾部对齐 */
        Buffer[Out] = L'\\';
        Out++;
    }

    while (Start < Chars && (Out + 1) < Capacity) {
        Buffer[Out] = Path->Buffer[Start];
        Out++;
        Start++;
    }

    Buffer[Out] = L'\0';
    *OutChars = Out;
    return TRUE;
}

/*=============================================================================
  受保护路径推导
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 从驱动服务键读取 ImagePath。

@note  与 DragonRulesLoadFromDisk 读取的是同一个值；这里独立实现是为了让
       自保护模块不依赖规则模块的加载结果（规则文件可以缺失，但自保护必须生效）。
--*/
static
NTSTATUS
DragonSelfReadImagePath(
    _In_ PUNICODE_STRING RegistryPath,
    _Out_writes_(BufferBytes) PWCHAR Buffer,
    _In_ ULONG BufferBytes,
    _Out_ PULONG OutChars
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE KeyHandle;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    ULONG ProbeLength;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG Chars;

    KeyHandle = NULL;
    Info = NULL;

    RtlInitUnicodeString(&ValueName, L"ImagePath");

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

    if ((Info->Type != REG_SZ && Info->Type != REG_EXPAND_SZ) ||
        Info->DataLength < sizeof(WCHAR) ||
        (Info->DataLength % sizeof(WCHAR)) != 0) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RtlZeroMemory(Buffer, BufferBytes);
    Chars = Info->DataLength / sizeof(WCHAR);
    if (Chars > ((BufferBytes / sizeof(WCHAR)) - 1)) {
        Chars = (BufferBytes / sizeof(WCHAR)) - 1;
    }

    RtlCopyMemory(Buffer, Info->Data, Chars * sizeof(WCHAR));
    Buffer[Chars] = L'\0';

    /* 去掉尾部多余 NUL */
    while (Chars > 0 && Buffer[Chars - 1] == L'\0') {
        Chars--;
        Buffer[Chars] = L'\0';
    }

    if (Chars == 0) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *OutChars = Chars;
    Status = STATUS_SUCCESS;

Exit:
    if (Info != NULL) {
        DragonFree(Info);
    }

    if (KeyHandle != NULL) {
        ZwClose(KeyHandle);
    }

    return Status;
}

/*++
@IRQL: <= APC_LEVEL
@brief 取「去掉卷 / 盘符 / 设备名前缀」后的起始下标（以 WCHAR 计）。

        只做指针偏移，不拷贝任何内容 —— 本函数位于文件 / 注册表回调的热路径上，
        既不能在栈上放 2KB 的路径缓冲，也不该每次操作都去分配非分页池。

@return TRUE 表示 OutStart 有效且剩余部分以反斜杠开头（可与绝对路径对齐）。
--*/
static
BOOLEAN
DragonSelfSkipVolume(
    _In_ PCUNICODE_STRING Path,
    _Out_ PULONG OutStart
    )
{
    ULONG Chars;
    ULONG Start;
    ULONG Index;

    if (Path == NULL || Path->Buffer == NULL || OutStart == NULL) {
        return FALSE;
    }

    Chars = Path->Length / sizeof(WCHAR);
    if (Chars == 0) {
        return FALSE;
    }

    Start = 0;

    if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfImagePrefix, 4) == TRUE) {
        Start = 4;
    }
    else if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfDosPrefix, 12) == TRUE) {
        Start = 12;
    }
    else if (DragonSelfPrefixNoCase(Path->Buffer, Chars, g_SelfDevicePrefix, 8) == TRUE) {

        /* \Device\<设备名>\... —— 跳到设备名之后的反斜杠 */
        Index = 8;
        while (Index < Chars && Path->Buffer[Index] != L'\\') {
            Index++;
        }
        Start = Index;
    }

    /* 盘符：可能出现在 \??\ / \DosDevices\ 之后，也可能出现在最前面 */
    if ((Start + 1) < Chars && Path->Buffer[Start + 1] == L':') {
        Start += 2;
    }

    if (Start >= Chars || Path->Buffer[Start] != L'\\') {
        return FALSE;
    }

    *OutStart = Start;
    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 把待检查路径与「已规范化的受保护路径」做比较（零拷贝）。

@param  PrefixMatch  TRUE = 前缀匹配（目录），FALSE = 整体等值（文件）。
--*/
static
BOOLEAN
DragonSelfPathMatch(
    _In_ PCUNICODE_STRING Path,
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars,
    _In_ BOOLEAN PrefixMatch
    )
{
    ULONG Start;
    ULONG Remain;

    if (DragonSelfSkipVolume(Path, &Start) == FALSE) {
        return FALSE;
    }

    Remain = (Path->Length / sizeof(WCHAR)) - Start;

    if (PrefixMatch == TRUE) {
        return DragonSelfPrefixNoCase(Path->Buffer + Start, Remain, Target, TargetChars);
    }

    return DragonSelfEqualNoCase(Path->Buffer + Start, Remain, Target, TargetChars);
}

/*=============================================================================
  主程序 / 主程序外置文件保护清单
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 规范化一条清单模式。

        与路径规范化同源，唯一差别：对通配符模式**不补前导反斜杠**。
        清单允许两种写法：

          · 绝对路径（可含通配符）：C:\Program Files\Dragon\*
              -> \Program Files\Dragon\*（与文件回调给出的规范化路径对齐）
          · 非锚定模式：*\Dragon-Antivirus\*
              -> 原样保留（开头的 * 表示不限卷）
--*/
static
BOOLEAN
DragonSelfNormalizePattern(
    _In_ PCUNICODE_STRING Raw,
    _Out_writes_(Capacity) PWCHAR Buffer,
    _In_ ULONG Capacity,
    _Out_ PULONG OutChars
    )
{
    ULONG Chars;
    ULONG Index;

    if (Raw == NULL || Raw->Buffer == NULL || Buffer == NULL || OutChars == NULL) {
        return FALSE;
    }

    Chars = Raw->Length / sizeof(WCHAR);
    if (Chars == 0 || Capacity < 2) {
        return FALSE;
    }

    if (Raw->Buffer[0] == L'*' || Raw->Buffer[0] == L'?') {

        if (Chars > (Capacity - 1)) {
            Chars = Capacity - 1;
        }

        for (Index = 0; Index < Chars; Index++) {
            Buffer[Index] = Raw->Buffer[Index];
        }
        Buffer[Chars] = L'\0';
        *OutChars = Chars;
        return TRUE;
    }

    return DragonSelfNormalize(Raw, Buffer, Capacity, OutChars);
}

/*++
@IRQL: 任意
@brief 清单条目是否可用（丢弃会把整机写死的危险模式）。

        规则：非通配符字符总数至少 4 个。
        `*`、`\*`、`*?*`、`\Wi*` 这类几乎等于「全盘锁死」的写法会被丢弃，
        避免一条配置失误让系统无法正常写入任何文件。
--*/
static
BOOLEAN
DragonSelfGuardPatternUsable(
    _In_reads_(Chars) PCWSTR Pattern,
    _In_ ULONG Chars
    )
{
    ULONG Index;
    ULONG Literals;

    Literals = 0;

    for (Index = 0; Index < Chars; Index++) {
        if (Pattern[Index] != L'*' && Pattern[Index] != L'?') {
            Literals++;
        }
    }

    return (Literals >= 4) ? TRUE : FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 规范化后的文件路径是否命中某条清单模式。
--*/
static
BOOLEAN
DragonSelfGuardMatch(
    _In_ PCWSTR Pattern,
    _In_reads_(TextChars) PCWSTR Text,
    _In_ ULONG TextChars
    )
{
    ULONG PatternChars;

    if (Pattern == NULL || Text == NULL || TextChars == 0 || TextChars > 0xFFFF) {
        return FALSE;
    }

    if (DragonWildcardMatch(Pattern, Text, (USHORT)(TextChars * sizeof(WCHAR))) == TRUE) {
        return TRUE;
    }

    /*
     * 模式形如 `…\*` 时，连带保护该目录本身 —— 通配符的 `*` 通常要求
     * 至少匹配一个字符，删除 / 改名目录自身时不会命中 `…\*`。
     */
    PatternChars = DragonWideLength(Pattern);
    if (PatternChars >= 2 &&
        Pattern[PatternChars - 1] == L'*' &&
        Pattern[PatternChars - 2] == L'\\') {

        return DragonSelfEqualNoCase(Text, TextChars, Pattern, PatternChars - 2);
    }

    return FALSE;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 读取 <服务键>\Parameters\GuardPaths（REG_MULTI_SZ），规范化后装载清单。

        取值失败 / 键不存在 / 值不存在都按「清单为空」处理：自保护的前三条
        （驱动镜像、规则目录、服务键）是编译期固化的，不依赖本清单。

@note  清单在安装期写入。驱动运行时自保护会拦住对该服务键的写入，因此修改
       清单同样需要「先停驱动」——与 ClientImagePath 的约束一致。
--*/
static
VOID
DragonSelfLoadGuardPaths(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    OBJECT_ATTRIBUTES ParametersAttributes;
    HANDLE KeyHandle;
    HANDLE ParametersHandle;
    UNICODE_STRING ParametersName;
    UNICODE_STRING ValueName;
    UNICODE_STRING Entry;
    ULONG ResultLength;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    PWCHAR Cursor;
    ULONG Remaining;
    ULONG EntryChars;
    ULONG NormalizedChars;

    KeyHandle = NULL;
    ParametersHandle = NULL;
    Info = NULL;

    RtlInitUnicodeString(&ParametersName, L"Parameters");
    RtlInitUnicodeString(&ValueName, L"GuardPaths");

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

    InitializeObjectAttributes(
        &ParametersAttributes,
        &ParametersName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        KeyHandle,
        NULL);

    Status = ZwOpenKey(&ParametersHandle, KEY_READ, &ParametersAttributes);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    ResultLength = 0;
    Status = ZwQueryValueKey(
                 ParametersHandle,
                 &ValueName,
                 KeyValuePartialInformation,
                 NULL,
                 0,
                 &ResultLength);
    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) {
        goto Exit;
    }

    if (ResultLength == 0 || ResultLength > DRG_SELF_GUARD_VALUE_MAX_BYTES) {
        goto Exit;
    }

    Info = (PKEY_VALUE_PARTIAL_INFORMATION)DragonAllocate(ResultLength);
    if (Info == NULL) {
        goto Exit;
    }

    Status = ZwQueryValueKey(
                 ParametersHandle,
                 &ValueName,
                 KeyValuePartialInformation,
                 Info,
                 ResultLength,
                 &ResultLength);
    if (!NT_SUCCESS(Status) || Info->Type != REG_MULTI_SZ || Info->DataLength < sizeof(WCHAR)) {
        goto Exit;
    }

    Cursor = (PWCHAR)Info->Data;
    Remaining = Info->DataLength / sizeof(WCHAR);

    while (Remaining > 0 && g_Self.GuardPathCount < DRG_GUARD_PATH_SLOTS) {

        EntryChars = 0;
        while (EntryChars < Remaining && Cursor[EntryChars] != L'\0') {
            EntryChars++;
        }

        if (EntryChars == 0) {
            break;      /* REG_MULTI_SZ 的双 NUL 终止 */
        }

        if (EntryChars < DRG_GUARD_PATH_CHARS) {

            Entry.Buffer = Cursor;
            Entry.Length = (USHORT)(EntryChars * sizeof(WCHAR));
            Entry.MaximumLength = Entry.Length;

            NormalizedChars = 0;

            if (DragonSelfNormalizePattern(
                    &Entry,
                    g_Self.GuardPaths[g_Self.GuardPathCount],
                    DRG_GUARD_PATH_CHARS,
                    &NormalizedChars) == TRUE &&
                DragonSelfGuardPatternUsable(
                    g_Self.GuardPaths[g_Self.GuardPathCount],
                    NormalizedChars) == TRUE) {

                g_Self.GuardPathCount++;
            }
        }

        Cursor += (EntryChars + 1);
        Remaining -= (EntryChars + 1);
    }

Exit:
    if (Info != NULL) {
        DragonFree(Info);
    }

    if (ParametersHandle != NULL) {
        ZwClose(ParametersHandle);
    }

    if (KeyHandle != NULL) {
        ZwClose(KeyHandle);
    }
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 推导并缓存受保护路径。

        三处来源：
          · 自身镜像     <- 服务键 ImagePath（去掉卷前缀）
          · 规则目录     <- 镜像所在目录 + \Rules\
          · 服务键路径   <- DriverEntry 直接给出的 RegistryPath
--*/
NTSTATUS
DragonSelfProtectInitialize(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    UNICODE_STRING ImageNt;
    WCHAR ImageRaw[DRG_PATH_CHARS];
    WCHAR Prefixed[DRG_PATH_CHARS];
    ULONG ImageChars;
    ULONG Index;
    ULONG LastSeparator;
    ULONG OutChars;

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&g_Self, sizeof(g_Self));
    RtlZeroMemory(ImageRaw, sizeof(ImageRaw));
    RtlZeroMemory(Prefixed, sizeof(Prefixed));

    ImageChars = 0;
    Status = DragonSelfReadImagePath(RegistryPath, ImageRaw, sizeof(ImageRaw), &ImageChars);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* 相对路径按「相对 SystemRoot」补全，与规则文件路径的解析规则保持一致 */
    if (DragonWideStartsWithNoCase(ImageRaw, L"\\??\\") == TRUE ||
        DragonWideStartsWithNoCase(ImageRaw, L"\\SystemRoot") == TRUE ||
        DragonWideStartsWithNoCase(ImageRaw, L"\\DosDevices\\") == TRUE ||
        (ImageChars >= 2 && ImageRaw[1] == L':')) {

        Status = RtlStringCchCopyW(Prefixed, RTL_NUMBER_OF(Prefixed), ImageRaw);
    }
    else {
        Status = RtlStringCchCopyW(Prefixed, RTL_NUMBER_OF(Prefixed), L"\\SystemRoot\\");
        if (NT_SUCCESS(Status)) {
            Status = RtlStringCchCatW(Prefixed, RTL_NUMBER_OF(Prefixed), ImageRaw);
        }
    }

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitUnicodeString(&ImageNt, Prefixed);

    if (DragonSelfNormalize(&ImageNt, g_Self.Image, DRG_PATH_CHARS, &OutChars) == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    g_Self.ImageChars = OutChars;

    /* 规则目录 = 镜像所在目录 + \Rules\ */
    LastSeparator = 0;
    for (Index = 0; Index < g_Self.ImageChars; Index++) {
        if (g_Self.Image[Index] == L'\\') {
            LastSeparator = Index;
        }
    }

    if (LastSeparator == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    g_Self.RuleDirChars = LastSeparator;
    RtlZeroMemory(g_Self.RuleDir, sizeof(g_Self.RuleDir));
    RtlCopyMemory(g_Self.RuleDir, g_Self.Image, LastSeparator * sizeof(WCHAR));

    for (Index = 0; g_SelfRuleDirName[Index] != L'\0'; Index++) {
        if ((g_Self.RuleDirChars + 1) >= DRG_PATH_CHARS) {
            return STATUS_INVALID_PARAMETER;
        }
        g_Self.RuleDir[g_Self.RuleDirChars] = g_SelfRuleDirName[Index];
        g_Self.RuleDirChars++;
    }

    /* 服务键路径：DriverEntry 给的就是 \Registry\Machine\...\Services\<服务名> */
    if (DragonSelfNormalize(RegistryPath, g_Self.ServiceKey, DRG_PATH_CHARS, &OutChars) == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    g_Self.ServiceKeyChars = OutChars;

    /* 主程序 / 外置文件保护清单（可选：缺失时仅失去这一层） */
    DragonSelfLoadGuardPaths(RegistryPath);

    g_Self.Ready = TRUE;
    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 清空受保护路径（卸载时调用，之后自保护判定一律返回「不拦」）。
--*/
VOID
DragonSelfProtectTeardown(
    VOID
    )
{
    RtlZeroMemory(&g_Self, sizeof(g_Self));
}

/*=============================================================================
  文件操作判定
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 该文件操作是否触碰受保护对象。

        FileName 来自 FltGetFileNameInformation 的 Name 字段（已解析的规范名）。
        比较前先去掉卷前缀，再整体等值 / 前缀比较。

@return 0 = 放行；非 0 = 拒绝，返回值为上报用的事件码（DRG_CODE_SELF_*）。
--*/
/*++
@IRQL: PASSIVE_LEVEL
@brief 登记内部豁免目录（当前由勒索防护模块登记自己的备份区）。

        存在意义：备份区默认就在驱动镜像所在目录里，而这个目录很可能被安装期
        配置的 GuardPaths 覆盖；自保护只按路径判定、不看发起者，不豁免就会把
        驱动自己的备份写入一并挡掉。

        豁免**不等于放行** —— 只有发起者是内核自身（System 上下文的工作项，
        PID 4）时才放行；外部进程碰同一目录依然会被拦，避免恶意程序清掉备份。

        路径按与受保护路径同源的方式规范化（去卷 / 盘符 / 设备名前缀），
        否则与文件回调给出的路径对不上，匹配必然失败。

@note  重复登记会被忽略；槽位用尽时丢弃并打一条警告 —— 豁免目录是内部约定，
        配错应该在开发期暴露，不该影响运行期判定逻辑。
--*/
VOID
DragonSelfProtectAddExemptDir(
    _In_ PCUNICODE_STRING Directory
    )
{
    WCHAR Normalized[DRG_PATH_CHARS];
    UNICODE_STRING ExemptDisplay;
    ULONG Chars;
    ULONG Index;

    if (g_Self.Ready == FALSE) {
        /*
         * 自保护尚未就绪：此时登记的豁免没有意义（判定函数在 Ready 为假时
         * 一律放行），而且说明调用方的初始化顺序反了 —— 与其静默登记，
         * 不如打一条日志把顺序问题暴露在开发期。
         */
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: exempt dir registered before self-protect ready, ignored\n");
        return;
    }

    if (Directory == NULL || Directory->Buffer == NULL || Directory->Length == 0) {
        return;
    }

    Chars = 0;

    if (DragonSelfNormalize(Directory, Normalized, DRG_PATH_CHARS, &Chars) == FALSE) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: exempt dir not normalized, skipped\n");
        return;
    }

    for (Index = 0; Index < g_Self.ExemptCount; Index++) {
        if (g_Self.ExemptChars[Index] == Chars &&
            RtlEqualMemory(g_Self.ExemptDirs[Index], Normalized,
                           Chars * sizeof(WCHAR)) == TRUE) {
            return;
        }
    }

    if (g_Self.ExemptCount >= DRG_SELF_EXEMPT_SLOTS) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: self-protect exempt slots exhausted, entry dropped\n");
        return;
    }

    Index = g_Self.ExemptCount;

    RtlZeroMemory(g_Self.ExemptDirs[Index], sizeof(g_Self.ExemptDirs[Index]));
    RtlCopyMemory(g_Self.ExemptDirs[Index], Normalized, Chars * sizeof(WCHAR));
    g_Self.ExemptChars[Index] = Chars;

    g_Self.ExemptCount++;

    /* 内核 DbgPrint 不认 %ws，宽字符串统一按 %wZ + UNICODE_STRING 输出 */
    ExemptDisplay.Buffer = Normalized;
    ExemptDisplay.Length = (USHORT)(Chars * sizeof(WCHAR));
    ExemptDisplay.MaximumLength = ExemptDisplay.Length;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "Dragon-Drivers: self-protect exempt dir (kernel-write-only) = %wZ\n",
        &ExemptDisplay);
}

ULONG
DragonSelfProtectFile(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName,
    _In_ ULONG Operation
    )
{
    ULONG Start;
    ULONG Remain;
    ULONG Index;

    if (g_Self.Ready == FALSE) {
        return 0;
    }

    if ((Operation & DRG_SELF_FILE_OPS) == 0) {
        return 0;
    }

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return 0;
    }

    /* 自身镜像：整体等值（避免其它卷上的同名路径被误拦） */
    if (DragonSelfPathMatch(FileName, g_Self.Image, g_Self.ImageChars, FALSE) == TRUE) {
        return DRG_CODE_SELF_IMAGE;
    }

    /* 规则目录：前缀匹配 */
    if (DragonSelfPathMatch(FileName, g_Self.RuleDir, g_Self.RuleDirChars, TRUE) == TRUE) {
        return DRG_CODE_SELF_RULE_DIR;
    }

    /*
     * 豁免目录：**必须放在 GuardPaths 之前**判。
     *
     * 备份区完全可能落在被 GuardPaths 覆盖的驱动目录内，顺序反了豁免就形同虚设。
     * 命中后按发起者分流：内核自身的写入（驱动自己的工作项跑在 System 上下文）
     * 放行，其余一律拦下。
     */
    for (Index = 0; Index < g_Self.ExemptCount; Index++) {

        if (DragonSelfPathMatch(
                FileName,
                g_Self.ExemptDirs[Index],
                g_Self.ExemptChars[Index],
                TRUE) == FALSE) {
            continue;
        }

        if (ProcessId != NULL &&
            (ULONG)(ULONG_PTR)ProcessId == DRG_SELF_SYSTEM_PID) {
            return 0;
        }

        return DRG_CODE_SELF_BACKUP;
    }

    /*
     * 主程序 / 主程序外置文件：按安装期写入的通配符清单匹配。
     * 清单为空（未配置）时整段跳过，零开销。
     */
    if (g_Self.GuardPathCount > 0 &&
        DragonSelfSkipVolume(FileName, &Start) == TRUE) {

        Remain = (FileName->Length / sizeof(WCHAR)) - Start;

        for (Index = 0; Index < g_Self.GuardPathCount; Index++) {
            if (DragonSelfGuardMatch(
                    g_Self.GuardPaths[Index],
                    FileName->Buffer + Start,
                    Remain) == TRUE) {

                return DRG_CODE_SELF_GUARD;
            }
        }
    }

    return 0;
}

/*=============================================================================
  注册表操作判定
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 该注册表操作是否触碰驱动服务键（含全部子键）。

        读 / 打开放行，只拦会改变键与值的操作，避免影响 SCM 查询。

@return 0 = 放行；非 0 = 拒绝，返回值为上报用的事件码。
--*/
ULONG
DragonSelfProtectRegistry(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG Operation
    )
{
    if (g_Self.Ready == FALSE) {
        return 0;
    }

    if ((Operation & DRG_SELF_REG_OPS) == 0) {
        return 0;
    }

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return 0;
    }

    /* 注册表键路径本身不含卷前缀，前缀匹配即可覆盖其全部子键 */
    if (DragonSelfPathMatch(KeyPath, g_Self.ServiceKey, g_Self.ServiceKeyChars, TRUE) == TRUE) {
        return DRG_CODE_SELF_SERVICE_KEY;
    }

    return 0;
}

/*++
@IRQL: <= APC_LEVEL
@brief 当前生效的主程序 / 外置文件保护条目数（供诊断打印）。
--*/
ULONG
DragonSelfProtectGuardPathCount(
    VOID
    )
{
    return g_Self.GuardPathCount;
}

/*=============================================================================
  客户端进程保护
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 目标是「已连接的客户端进程」时，返回需要从 DesiredAccess 中剥离的掩码。

        判定依据是连接建立时记录的 PID（连接握手已校过镜像路径），
        进程对象再叠加创建时间校验，防止 PID 复用后被冒名保护。

@note  线程对象只按所属进程 PID 判定：客户端进程存活期间其 PID 不可能被复用，
       因此这里不需要（也拿不到不引入额外引用的）线程所属进程创建时间。
--*/
ACCESS_MASK
DragonSelfProtectClientMask(
    _In_ PEPROCESS TargetProcess,
    _In_ ULONG ObjectType
    )
{
    HANDLE TargetPid;
    LONG ClientPid;

    if (TargetProcess == NULL) {
        return 0;
    }

    ClientPid = InterlockedCompareExchange(&g_Dragon.ClientPid, 0, 0);
    if (ClientPid == 0) {
        return 0;
    }

    if (ObjectType == DRG_OBJECT_PROCESS) {
        TargetPid = PsGetProcessId(TargetProcess);
    }
    else if (ObjectType == DRG_OBJECT_THREAD) {
        TargetPid = PsGetThreadProcessId((PETHREAD)TargetProcess);
    }
    else {
        return 0;
    }

    if (TargetPid == NULL || (LONG)(ULONG_PTR)TargetPid != ClientPid) {
        return 0;
    }

    if (ObjectType == DRG_OBJECT_PROCESS) {

        if (g_Dragon.ClientCreateTime.QuadPart != 0 &&
            PsGetProcessCreateTimeQuadPart(TargetProcess) != g_Dragon.ClientCreateTime.QuadPart) {
            return 0;
        }

        return (ACCESS_MASK)PROCESS_TERMINATE | (ACCESS_MASK)PROCESS_SUSPEND_RESUME;
    }

    return (ACCESS_MASK)THREAD_TERMINATE | (ACCESS_MASK)THREAD_SUSPEND_RESUME;
}
