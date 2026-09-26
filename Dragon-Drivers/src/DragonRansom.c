/*++
===============================================================================
 Dragon-Drivers / DragonRansom.c

 勒索软件防护：行为评分 + 写前备份 + 一键恢复。

 三层职责：
   1. 识别 —— 只对「值得保护的文件」下手：常见文档 / 图片 / 音视频 / 压缩包，
      数据库文件与驱动自己的备份目录明确排除；
   2. 判定 —— 对单个进程累计 8 项信号（批量改 / 删 / 改名、扩展名变更、高熵写入、
      类型多样性、目录多样性、写入频度），60 秒时间窗内总分达到阈值即判定成立；
   3. 处置 —— 判定成立后：
        · 拒绝该进程后续的文档类文件操作（不终止、不冻结，进程照常活着）；
        · 写打开时先把原文件备份到备份目录（带自描述头部）；
        · 用户可随时下发恢复命令，从备份原样还原。

 与「冻结进程 + 等用户决策」的路线相比，这里刻意选择「直接拒绝 + 事后可回滚」：
   · 不需要任何未文档化 API；
   · 不会出现「冻结后用户迟迟不点、进程僵死」的中间态；
   · 勒索软件即使拿到了判定之前的少数几个文件，也能从备份里还原。

 备份文件格式（见 DragonProtocol.h 的 DRG_BACKUP_HEADER）：
     [DRG_BACKUP_HEADER][原始文件字节]
   头部里带着原路径，因此恢复完全不依赖内存状态 —— 驱动重启、机器重启之后，
   只要备份文件还在就能还原。备份文件名 = 原路径小写形式的 FNV-1a 64 位哈希，
   可以由原路径直接反算，不需要维护任何索引。

 全部文件 I/O 使用文档化 API：
   ZwCreateFile / ZwReadFile / ZwWriteFile / ZwQueryInformationFile /
   ZwSetInformationFile / ZwClose。
===============================================================================
--*/

#include "DragonCommon.h"

/*=============================================================================
  常量
=============================================================================*/

/* 备份目录的相对默认位置（无法从注册表读到配置时使用：驱动镜像同级 RansomBackup\） */
#define DRG_RANSOM_BACKUP_SUBDIR      L"RansomBackup"

/* 注册表配置项 */
#define DRG_RANSOM_VALUE_BACKUP_DIR   L"RansomBackupDir"
#define DRG_RANSOM_VALUE_BACKUP_MAX   L"RansomBackupMaxBytes"

/* 备份读写块大小 */
#define DRG_RANSOM_CHUNK_BYTES        4096u

/* 单个进程槽的过期时间（无操作后） */
#define DRG_RANSOM_SLOT_EXPIRE_100NS  (300LL * 10000000LL)

/* FNV-1a 64 位 */
#define DRG_FNV_BASIS                 14695981039346656037ULL
#define DRG_FNV_PRIME                 1099511628211ULL

/* 记分参数 */
#define DRG_SCORE_RAPID_WRITE_BASE    10u
#define DRG_SCORE_MASS_MODIFY_BASE    20u
#define DRG_SCORE_MASS_DELETE_BASE    15u
#define DRG_SCORE_MASS_RENAME_BASE    25u
#define DRG_SCORE_EXT_CHANGE_PER      30u
#define DRG_SCORE_ENTROPY_PER         8u
#define DRG_SCORE_ENTROPY_MAX         40u
#define DRG_SCORE_TYPE_DIVERSITY      15u
#define DRG_SCORE_DIR_DIVERSITY       10u

/* 触发各项信号的计数量 */
#define DRG_TRIGGER_MASS_MODIFY       10u
#define DRG_TRIGGER_MASS_DELETE       8u
#define DRG_TRIGGER_MASS_RENAME       5u
#define DRG_TRIGGER_TYPE_DIVERSITY    5u
#define DRG_TRIGGER_DIR_DIVERSITY     8u
#define DRG_TRIGGER_RAPID_WRITES      30u

/*=============================================================================
  数据结构
=============================================================================*/

typedef struct _DRG_RANSOM_OP {
    LARGE_INTEGER Time;
    ULONG         Kind;      /* DRG_RANSOM_OP_* */
    ULONG         Flags;     /* 附加标志，如本次写入被判为高熵 */
} DRG_RANSOM_OP, *PDRG_RANSOM_OP;

typedef struct _DRG_RANSOM_PROC {
    HANDLE        Pid;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastActivity;
    LARGE_INTEGER BlockTime;
    ULONG         Score;
    ULONG         Flags;             /* DRG_RANSOM_SIG_* 位或 */
    ULONG         OpHead;            /* 时间戳环写指针 */
    ULONG         WriteTotal;        /* 累计写入次数，用于熵采样抽稀 */
    ULONG         ExtSlotCount;      /* 已占用的扩展名多样性槽 */
    ULONG         DirSlotCount;      /* 已占用的目录多样性槽 */
    BOOLEAN       Active;
    BOOLEAN       Blocked;
    BOOLEAN       Reported;          /* 本进程的检测事件是否已上报过（去重） */
    UCHAR         Pad;
    ULONG         ExtSlots[DRG_RANSOM_DIVERSITY_SLOTS];
    ULONG         DirSlots[DRG_RANSOM_DIVERSITY_SLOTS];
    DRG_RANSOM_OP Ops[DRG_RANSOM_OP_RING];
} DRG_RANSOM_PROC, *PDRG_RANSOM_PROC;

typedef struct _DRG_RANSOM_RECORD {
    LARGE_INTEGER Time;
    HANDLE        Pid;
    ULONG         Operation;
    ULONG         Reserved;
    WCHAR         Path[DRG_BACKUP_PATH_CHARS];
} DRG_RANSOM_RECORD, *PDRG_RANSOM_RECORD;

typedef struct _DRG_RANSOM_STATE {
    KSPIN_LOCK         Lock;
    BOOLEAN            Ready;
    BOOLEAN            BackupDirReady;
    ULONG              BackupMaxBytes;
    UNICODE_STRING     BackupDir;          /* 含结尾反斜杠的 NT 路径 */
    WCHAR              BackupDirBuffer[DRG_BACKUP_PATH_CHARS];
    DRG_RANSOM_PROC    Procs[DRG_RANSOM_PROC_SLOTS];
    DRG_RANSOM_RECORD  Records[DRG_RANSOM_RECORD_MAX];
    ULONG              RecordHead;
    ULONG              RecordCount;
    ULONGLONG          BackedUpRing[DRG_RANSOM_BACKEDUP_RING];
    ULONG              BackedUpHead;
    ULONG              BackedUpCount;
    volatile LONG64    BackupsCreated;
    volatile LONG64    RestoredFiles;
    volatile LONG64    BlockEvents;
} DRG_RANSOM_STATE;

/*=============================================================================
  静态状态与内置表
=============================================================================*/

static DRG_RANSOM_STATE g_Ransom;

/* 需要保护的文档类扩展名（全部小写，比较时统一转小写） */
static const PCWSTR g_RansomDocExtensions[] = {
    L".doc",  L".docx", L".xls",  L".xlsx", L".ppt",  L".pptx",
    L".pdf",  L".txt",  L".rtf",  L".csv",  L".md",
    L".wps",  L".et",   L".dps",
    L".odt",  L".ods",  L".odp",
    L".eml",  L".msg",  L".pst",  L".one",  L".vsd",  L".vsdx",
    L".jpg",  L".jpeg", L".png",  L".bmp",  L".gif",  L".tiff",
    L".mp3",  L".mp4",  L".avi",  L".mkv",
    L".zip",  L".rar",  L".7z"
};

/* 数据库类扩展名：体量大、写入频繁、通常有自带的事务机制，不纳入防勒索范围 */
static const PCWSTR g_RansomExcludedExtensions[] = {
    L".sql", L".db", L".dbf", L".mdb", L".accdb"
};

/* 自身已是压缩/高熵容器：跳过熵判定，否则正常保存就会被判为「疑似加密」 */
static const PCWSTR g_RansomCompressedExtensions[] = {
    L".docx", L".xlsx", L".pptx", L".pdf",  L".zip",  L".rar",  L".7z",
    L".jpg",  L".jpeg", L".png",  L".gif",  L".mp3",  L".mp4",  L".avi",
    L".mkv",  L".wps",  L".et",   L".dps",  L".odt",  L".ods",  L".odp"
};

/*
 * 不参与评分的系统进程：它们的文件写入属于系统自身运作（索引、更新、日志轮转），
 * 若纳入统计会持续抬高基线分。用子串匹配而不是全等，是因为
 * 内核提供短名缓冲的那个例程只给 15 字节，长进程名会被截断。
 */
static const PCSTR g_RansomSystemProcesses[] = {
    "System", "Registry", "MemCompression",
    "svchost.exe", "explorer.exe", "dwm.exe", "lsass.exe", "winlogon.exe",
    "services.exe", "csrss.exe", "smss.exe", "wininit.exe", "audiodg.exe",
    "fontdrvhost.exe", "ctfmon.exe", "sihost.exe", "taskhostw.exe",
    "conhost.exe", "RuntimeBroker.exe",
    "SearchIndexer", "SearchProtocol", "SearchFilter",
    "MsMpEng.exe", "OneDrive.exe", "backgroundTaskHost",
    "WmiPrvSE.exe", "spoolsv.exe", "dllhost.exe"
};

#define DRG_RANSOM_DOC_EXT_COUNT     (sizeof(g_RansomDocExtensions) / sizeof(g_RansomDocExtensions[0]))
#define DRG_RANSOM_EXCLUDED_COUNT    (sizeof(g_RansomExcludedExtensions) / sizeof(g_RansomExcludedExtensions[0]))
#define DRG_RANSOM_COMPRESSED_COUNT  (sizeof(g_RansomCompressedExtensions) / sizeof(g_RansomCompressedExtensions[0]))
#define DRG_RANSOM_SYSPROC_COUNT     (sizeof(g_RansomSystemProcesses) / sizeof(g_RansomSystemProcesses[0]))

/*=============================================================================
  工具：字符串与哈希
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 计算路径小写形式的 FNV-1a 64 位哈希。

        备份文件名由它导出（16 位十六进制），因此「原路径 → 备份文件」是
        可反算的，不需要索引表。用 64 位而不是 32 位是为了让碰撞概率低到
        可以忽略（512 个条目量级下 32 位已开始有实际碰撞风险）。
--*/
static
ULONGLONG
DragonRansomHashPath(
    _In_ PCUNICODE_STRING Path
    )
{
    ULONGLONG Hash;
    ULONG Index;
    ULONG Chars;
    WCHAR Character;

    Hash = DRG_FNV_BASIS;

    if (Path == NULL || Path->Buffer == NULL) {
        return Hash;
    }

    Chars = (ULONG)(Path->Length / sizeof(WCHAR));

    for (Index = 0; Index < Chars; Index++) {

        Character = Path->Buffer[Index];

        /* 统一按小写参与哈希，避免大小写差异导致同一文件产生两个备份 */
        if (Character >= L'A' && Character <= L'Z') {
            Character = (WCHAR)(Character + (L'a' - L'A'));
        }

        Hash ^= (ULONGLONG)Character;
        Hash *= DRG_FNV_PRIME;
    }

    return Hash;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 把勒索恢复的输入路径规范化为「卷设备路径」形式（\Device\HarddiskVolumeN\...）。

       备份头部永远以这种形式存储 OriginalPath，恢复侧必须与之对齐，否则
       FNV-1a 哈希与 RtlEqualUnicodeString 比对会失配（典型表现：客户端用 Win32
       路径 \??\D:\... 下发恢复，而备份里是 NT 设备路径 \Device\HarddiskVolumeN\...）。

       实现：
         - 输入已是卷设备路径则原样返回（幂等；「恢复全部」记录里的路径本就是这种形式）；
         - 否则（DOS/Win32 路径）打开该文件取得其卷设备对象，用 ObQueryNameString
           取卷的 NT 设备名，再拼接相对路径。打开失败（如文件已被删除）时退化为原样
           拷贝，由上层按原逻辑判定。

       仅使用文档化 API；Output->Buffer 由调用方预分配（DRG_BACKUP_PATH_CHARS 容量）。
--*/
static
NTSTATUS
DragonRansomCanonPath(
    _In_ PCUNICODE_STRING Input,
    _Out_ PUNICODE_STRING Output
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    OBJECT_ATTRIBUTES Oa;
    IO_STATUS_BLOCK Ios;
    UCHAR FniBuf[sizeof(FILE_NAME_INFORMATION) + DRG_BACKUP_PATH_CHARS * sizeof(WCHAR)];
    PFILE_NAME_INFORMATION Fni = (PFILE_NAME_INFORMATION)FniBuf;

    if (Input == NULL || Input->Buffer == NULL || Input->Length == 0 ||
        Output == NULL || Output->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 已是卷设备路径：直接拷贝（幂等；「恢复全部」记录的路径本就是这种形式） */
    if (Input->Length >= (sizeof(L"\\Device\\") - sizeof(WCHAR)) &&
        Input->Buffer[0] == L'\\' && Input->Buffer[1] == L'D' &&
        Input->Buffer[2] == L'e' && Input->Buffer[3] == L'v' &&
        Input->Buffer[4] == L'i' && Input->Buffer[5] == L'c' &&
        Input->Buffer[6] == L'e' && Input->Buffer[7] == L'\\') {
        if (Input->Length > Output->MaximumLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyUnicodeString(Output, (PUNICODE_STRING)Input);
        return STATUS_SUCCESS;
    }

    /* DOS/Win32 路径：打开文件后用 FileNormalizedNameInformation 取完整 NT 设备路径
       （例如 \Device\HarddiskVolume3\Dragon-Antivirus\...\doc9.txt）。该 API 文档化、
       无需未文档化接口；打开失败（文件已被删除）时退化为原样拷贝。 */
    InitializeObjectAttributes(&Oa,
                               (PUNICODE_STRING)Input,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    Status = ZwCreateFile(&FileHandle,
                          FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                          &Oa,
                          &Ios,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status)) {
        goto Fallback;
    }

    Status = ZwQueryInformationFile(FileHandle,
                                    &Ios,
                                    Fni,
                                    sizeof(FniBuf),
                                    FileNormalizedNameInformation);
    if (!NT_SUCCESS(Status) || Fni->FileNameLength == 0) {
        goto Fallback;
    }

    if (Fni->FileNameLength > Output->MaximumLength) {
        goto Fallback;
    }

    RtlCopyMemory(Output->Buffer, Fni->FileName, Fni->FileNameLength);
    Output->Length = (USHORT)Fni->FileNameLength;
    ZwClose(FileHandle);
    return STATUS_SUCCESS;

Fallback:
    if (FileHandle != NULL) {
        ZwClose(FileHandle);
    }
    if (Input->Length <= Output->MaximumLength) {
        RtlCopyUnicodeString(Output, (PUNICODE_STRING)Input);
        return STATUS_SUCCESS;
    }
    return STATUS_BUFFER_TOO_SMALL;
}

/*++
@IRQL: <= APC_LEVEL
@brief 在扩展名表中查找（大小写不敏感）。

@return 命中返回其在表中的下标，未命中返回 (ULONG)-1。
--*/
static
ULONG
DragonRansomLookupExtension(
    _In_ PCUNICODE_STRING Path,
    _In_reads_(Count) const PCWSTR *Table,
    _In_ ULONG Count
    )
{
    ULONG Index;

    for (Index = 0; Index < Count; Index++) {
        if (DragonHasSuffix(Path, Table[Index]) == TRUE) {
            return Index;
        }
    }

    return (ULONG)-1;
}

/*++
@IRQL: <= APC_LEVEL
@brief 提取最后一个 '.' 之后的扩展名（含点），写入调用方缓冲。

        只认最后一个路径分隔符之后的点，避免把目录名里的点当成扩展名。
--*/
static
BOOLEAN
DragonRansomExtractExtension(
    _In_ PCUNICODE_STRING Path,
    _Out_writes_(Chars) PWCHAR Buffer,
    _In_ ULONG Chars
    )
{
    ULONG Length;
    ULONG Index;
    ULONG DotIndex;
    ULONG Count;

    if (Path == NULL || Path->Buffer == NULL || Buffer == NULL || Chars < 2) {
        return FALSE;
    }

    Length = (ULONG)(Path->Length / sizeof(WCHAR));
    DotIndex = (ULONG)-1;

    for (Index = 0; Index < Length; Index++) {

        if (Path->Buffer[Index] == L'\\' || Path->Buffer[Index] == L'/') {
            DotIndex = (ULONG)-1;
            continue;
        }

        if (Path->Buffer[Index] == L'.') {
            DotIndex = Index;
        }
    }

    if (DotIndex == (ULONG)-1 || DotIndex + 1 >= Length) {
        return FALSE;
    }

    Count = Length - DotIndex;
    if (Count >= Chars) {
        Count = Chars - 1;
    }

    RtlCopyMemory(Buffer, &Path->Buffer[DotIndex], Count * sizeof(WCHAR));
    Buffer[Count] = L'\0';

    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 计算「文件所在目录」的哈希（路径中最后一个分隔符之前的部分）。
--*/
static
ULONG
DragonRansomHashDirectory(
    _In_ PCUNICODE_STRING Path
    )
{
    ULONGLONG Hash;
    ULONG Index;
    ULONG Length;

    Hash = DRG_FNV_BASIS;
    Length = (ULONG)(Path->Length / sizeof(WCHAR));

    for (Index = 0; Index < Length; Index++) {

        if (Path->Buffer[Index] == L'\\' || Path->Buffer[Index] == L'/') {
            break;
        }

        Hash ^= (ULONGLONG)Path->Buffer[Index];
        Hash *= DRG_FNV_PRIME;
    }

    return (ULONG)(Hash ^ (Hash >> 32));
}

/*++
@IRQL: <= APC_LEVEL
@brief 当前进程是否属于「不参与评分」的系统进程。
--*/
/*++
@IRQL: <= APC_LEVEL
@brief 大小写不敏感的子串查找：宽字符串文本 + ASCII 针。

        不用短名缓冲、改成在完整镜像路径上
        做子串匹配，判断系统进程时不会因为进程名太长而被漏掉。
--*/
static
BOOLEAN
DragonRansomContainsAscii(
    _In_ PCUNICODE_STRING Text,
    _In_ PCSTR Needle
    )
{
    ULONG Index;
    ULONG Scan;
    ULONG NeedleLength;
    ULONG TextChars;

    NeedleLength = (ULONG)strlen(Needle);

    if (NeedleLength == 0 || Text == NULL || Text->Buffer == NULL) {
        return FALSE;
    }

    TextChars = (ULONG)(Text->Length / sizeof(WCHAR));

    if (TextChars < NeedleLength) {
        return FALSE;
    }

    for (Scan = 0; Scan + NeedleLength <= TextChars; Scan++) {

        for (Index = 0; Index < NeedleLength; Index++) {

            WCHAR Left;
            WCHAR Right;

            Left = Text->Buffer[Scan + Index];
            Right = (WCHAR)Needle[Index];

            if (Left >= L'A' && Left <= L'Z') {
                Left = (WCHAR)(Left + (L'a' - L'A'));
            }
            if (Right >= L'A' && Right <= L'Z') {
                Right = (WCHAR)(Right + (L'a' - L'A'));
            }

            if (Left != Right) {
                break;
            }
        }

        if (Index == NeedleLength) {
            return TRUE;
        }
    }

    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 当前进程是否属于「不参与评分」的系统进程。

        用 SeLocateProcessImageName 拿完整镜像路径（官方文档化 DDI），
        而不是依赖 15 字节的短名缓冲 —— 那会把 SearchProtocolHost.exe 这类
        长名字截断成 SearchProtocol，按名字建表就得迁就截断，容易出错。

@note  该 API 要求 PASSIVE_LEVEL，而本函数走在文件回调路径上（回调上限是
        APC_LEVEL）。高于 PASSIVE 时**不判定、直接按「系统进程」返回**：
        漏评一个系统进程没有实际损失（它们本就不该参与勒索评分），
        而在 APC_LEVEL 调用一个允许阻塞的 API 会直接蓝屏 —— 两者代价不对等，
        选择保守的一侧。
--*/
static
BOOLEAN
DragonRansomIsSystemProcess(
    VOID
    )
{
    PUNICODE_STRING ImagePath;
    NTSTATUS Status;
    BOOLEAN Result;
    ULONG Index;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }

    ImagePath = NULL;
    Result = FALSE;

    Status = SeLocateProcessImageName(PsGetCurrentProcess(), &ImagePath);
    if (!NT_SUCCESS(Status) || ImagePath == NULL || ImagePath->Buffer == NULL) {
        return FALSE;
    }

    for (Index = 0; Index < DRG_RANSOM_SYSPROC_COUNT; Index++) {

        if (DragonRansomContainsAscii(ImagePath, g_RansomSystemProcesses[Index]) == TRUE) {
            Result = TRUE;
            break;
        }
    }

    ExFreePool(ImagePath);

    return Result;
}

/*=============================================================================
  工具：随机性评估
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 评估缓冲区的「随机性」，取值 0-255，越接近均匀分布分越高。

        判定依据：加密后的数据在 0-255 上接近均匀分布，而文本、结构化数据会
        集中在少数字节值上。这里不计算香农熵 —— 熵需要浮点对数运算，而内核态
        使用浮点必须保存/恢复 MMX 状态，代价与风险都不划算。改用两个等价的
        整数观测量合成：

          ① 出现过的字节值种类数（0-128 分）；
          ② 出现频次最高的那个值是否接近平均值（0-127 分）。

        均匀随机数据两项都会拿满，文本数据第一项就只有十几分。
--*/
static
ULONG
DragonRansomRandomness(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
    )
{
    ULONG Counts[256];
    ULONG Index;
    ULONG Unique;
    ULONG MaxFreq;
    ULONG Expected;
    ULONG Score;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    RtlZeroMemory(Counts, sizeof(Counts));

    for (Index = 0; Index < Length; Index++) {
        Counts[Buffer[Index]]++;
    }

    Unique = 0;
    MaxFreq = 0;

    for (Index = 0; Index < 256; Index++) {
        if (Counts[Index] != 0) {
            Unique++;
        }
        if (Counts[Index] > MaxFreq) {
            MaxFreq = Counts[Index];
        }
    }

    Score = (Unique * 128u) / 256u;

    Expected = Length / 256u;
    if (Expected == 0) {
        Expected = 1;
    }

    if (MaxFreq <= Expected * 2u) {
        Score += 127u;
    }
    else if (MaxFreq <= Expected * 4u) {
        Score += 80u;
    }
    else if (MaxFreq <= Expected * 8u) {
        Score += 40u;
    }

    if (Score > 255u) {
        Score = 255u;
    }

    return Score;
}

/*=============================================================================
  进程槽管理（全部在自旋锁内调用）
=============================================================================*/

/*++
@IRQL: <= DISPATCH_LEVEL（调用方持锁）
@brief 查找进程槽；PID 相同但创建时间不同时视为旧槽已失效，就地清零并返回 NULL。

        创建时间比对是防 PID 复用的关键：Windows 会回收 PID，若不比对，
        新启动的良性进程可能继承上一个勒索进程的评分与阻断标记。
--*/
static
PDRG_RANSOM_PROC
DragonRansomFindSlotLocked(
    _In_ HANDLE Pid,
    _In_ LONGLONG CreateTime
    )
{
    ULONG Index;
    PDRG_RANSOM_PROC Slot;

    for (Index = 0; Index < DRG_RANSOM_PROC_SLOTS; Index++) {

        Slot = &g_Ransom.Procs[Index];

        if (Slot->Active == FALSE || Slot->Pid != Pid) {
            continue;
        }

        if (Slot->CreateTime.QuadPart != CreateTime) {
            RtlZeroMemory(Slot, sizeof(*Slot));
            return NULL;
        }

        return Slot;
    }

    return NULL;
}

/*++
@IRQL: <= DISPATCH_LEVEL（调用方持锁）
@brief 取进程槽：复用同 PID 同创建时间的现有槽，否则用空闲槽 / 过期槽，
        最后淘汰最久未活动的槽。

@note  只由文件操作回调路径调用 —— 那里的 ProcessId 必然等于当前进程，
       因此创建时间直接取 PsGetCurrentProcess()，无需按 PID 反查
       （反查需要引用计数管理，不能在自旋锁内做）。
--*/
static
PDRG_RANSOM_PROC
DragonRansomAcquireSlotLocked(
    _In_ HANDLE Pid,
    _In_ LONGLONG CreateTime
    )
{
    ULONG Index;
    PDRG_RANSOM_PROC Slot;
    PDRG_RANSOM_PROC Oldest;
    LARGE_INTEGER Now;
    LARGE_INTEGER Expire;

    Oldest = NULL;
    Now = DragonNow();
    Expire.QuadPart = Now.QuadPart - DRG_RANSOM_SLOT_EXPIRE_100NS;

    for (Index = 0; Index < DRG_RANSOM_PROC_SLOTS; Index++) {

        Slot = &g_Ransom.Procs[Index];

        if (Slot->Active == TRUE &&
            Slot->Pid == Pid &&
            Slot->CreateTime.QuadPart == CreateTime) {
            return Slot;
        }

        if (Slot->Active == FALSE || Slot->LastActivity.QuadPart < Expire.QuadPart) {

            RtlZeroMemory(Slot, sizeof(*Slot));
            Slot->Active = TRUE;
            Slot->Pid = Pid;
            Slot->CreateTime.QuadPart = CreateTime;
            Slot->LastActivity = Now;
            return Slot;
        }

        if (Oldest == NULL || Slot->LastActivity.QuadPart < Oldest->LastActivity.QuadPart) {
            Oldest = Slot;
        }
    }

    if (Oldest != NULL) {
        RtlZeroMemory(Oldest, sizeof(*Oldest));
        Oldest->Active = TRUE;
        Oldest->Pid = Pid;
        Oldest->CreateTime.QuadPart = CreateTime;
        Oldest->LastActivity = Now;
        return Oldest;
    }

    return NULL;
}

/*=============================================================================
  多样性统计（锁内）
=============================================================================*/

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 向多样性槽登记一个哈希值，返回是否为新值。
--*/
static
BOOLEAN
DragonRansomRegisterDiversity(
    _Inout_updates_(DRG_RANSOM_DIVERSITY_SLOTS) PULONG Slots,
    _Inout_ PULONG Count,
    _In_ ULONG Hash
    )
{
    ULONG Index;

    if (Hash == 0) {
        Hash = 1;
    }

    for (Index = 0; Index < *Count; Index++) {
        if (Slots[Index] == Hash) {
            return FALSE;
        }
    }

    if (*Count >= DRG_RANSOM_DIVERSITY_SLOTS) {
        return FALSE;
    }

    Slots[*Count] = Hash;
    (*Count)++;

    return TRUE;
}

/*=============================================================================
  评分
=============================================================================*/

/*++
@IRQL: <= DISPATCH_LEVEL（调用方持锁）
@brief 依据操作时间戳环重新计算进程评分。

        每一项信号都只在 60 秒窗口内计数：窗口滑过之后旧的破坏性操作不再
        贡献分数，避免「一次误操作把进程永久标脏」。
--*/
static
VOID
DragonRansomScoreLocked(
    _Inout_ PDRG_RANSOM_PROC Slot
    )
{
    ULONG Index;
    ULONG WriteCount;
    ULONG DeleteCount;
    ULONG RenameCount;
    ULONG ExtChangeCount;
    ULONG EntropyCount;
    ULONG TotalOps;
    ULONG Score;
    ULONG Flags;
    LARGE_INTEGER Now;
    LONGLONG WindowStart;

    Now = DragonNow();
    WindowStart = Now.QuadPart - DRG_RANSOM_WINDOW_100NS;

    WriteCount = 0;
    DeleteCount = 0;
    RenameCount = 0;
    ExtChangeCount = 0;
    EntropyCount = 0;
    TotalOps = 0;

    for (Index = 0; Index < DRG_RANSOM_OP_RING; Index++) {

        PDRG_RANSOM_OP Op;

        Op = &Slot->Ops[Index];

        if (Op->Time.QuadPart == 0 || Op->Time.QuadPart < WindowStart) {
            continue;
        }

        TotalOps++;

        switch (Op->Kind) {

            case DRG_RANSOM_OP_WRITE:
                WriteCount++;
                if ((Op->Flags & DRG_RANSOM_SIG_ENTROPY) != 0) {
                    EntropyCount++;
                }
                break;

            case DRG_RANSOM_OP_DELETE:
                DeleteCount++;
                break;

            case DRG_RANSOM_OP_RENAME:
                RenameCount++;
                break;

            case DRG_RANSOM_OP_EXT_CHANGE:
                ExtChangeCount++;
                break;

            default:
                break;
        }
    }

    Score = 0;
    Flags = 0;

    if (WriteCount > DRG_TRIGGER_MASS_MODIFY) {
        Score += DRG_SCORE_MASS_MODIFY_BASE + ((WriteCount - DRG_TRIGGER_MASS_MODIFY) * 2u);
        Flags |= DRG_RANSOM_SIG_MASS_MODIFY;
    }

    if (DeleteCount > DRG_TRIGGER_MASS_DELETE) {
        Score += DRG_SCORE_MASS_DELETE_BASE + ((DeleteCount - DRG_TRIGGER_MASS_DELETE) * 2u);
        Flags |= DRG_RANSOM_SIG_MASS_DELETE;
    }

    if (RenameCount > DRG_TRIGGER_MASS_RENAME) {
        Score += DRG_SCORE_MASS_RENAME_BASE + ((RenameCount - DRG_TRIGGER_MASS_RENAME) * 3u);
        Flags |= DRG_RANSOM_SIG_MASS_RENAME;
    }

    if (ExtChangeCount > 0) {
        Score += DRG_SCORE_EXT_CHANGE_PER * ExtChangeCount;
        Flags |= DRG_RANSOM_SIG_EXT_CHANGE;
    }

    if (EntropyCount > 0) {
        ULONG EntropyScore;

        EntropyScore = EntropyCount * DRG_SCORE_ENTROPY_PER;
        if (EntropyScore > DRG_SCORE_ENTROPY_MAX) {
            EntropyScore = DRG_SCORE_ENTROPY_MAX;
        }

        Score += EntropyScore;
        Flags |= DRG_RANSOM_SIG_ENTROPY;
    }

    if (Slot->ExtSlotCount > DRG_TRIGGER_TYPE_DIVERSITY) {
        Score += DRG_SCORE_TYPE_DIVERSITY;
        Flags |= DRG_RANSOM_SIG_TYPE_DIVERSITY;
    }

    if (Slot->DirSlotCount > DRG_TRIGGER_DIR_DIVERSITY) {
        Score += DRG_SCORE_DIR_DIVERSITY;
        Flags |= DRG_RANSOM_SIG_DIR_DIVERSITY;
    }

    if (TotalOps > DRG_TRIGGER_RAPID_WRITES) {
        Score += DRG_SCORE_RAPID_WRITE_BASE;
        Flags |= DRG_RANSOM_SIG_RAPID_WRITES;
    }

    if (Score > DRG_RANSOM_SCORE_CAP) {
        Score = DRG_RANSOM_SCORE_CAP;
    }

    Slot->Score = Score;
    Slot->Flags = Flags;
}

/*=============================================================================
  备份
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 确保备份目录存在（已存在时直接返回成功）。
--*/
static
NTSTATUS
DragonRansomEnsureDirectory(
    VOID
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Handle;

    Handle = NULL;

    InitializeObjectAttributes(
        &Attributes,
        &g_Ransom.BackupDir,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &Handle,
                 FILE_LIST_DIRECTORY | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                 FILE_OPEN_IF,
                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);

    if (Handle != NULL) {
        ZwClose(Handle);
        Handle = NULL;
    }

    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 备份文件是否已存在且可读。存在即认为该文件在本轮已备份过。
--*/
static
BOOLEAN
DragonRansomBackupExists(
    _In_ PCUNICODE_STRING BackupPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Handle;

    Handle = NULL;

    InitializeObjectAttributes(
        &Attributes,
        (PUNICODE_STRING)BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &Handle,
                 FILE_READ_DATA | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                 FILE_OPEN,
                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);

    if (NT_SUCCESS(Status) && Handle != NULL) {
        ZwClose(Handle);
        return TRUE;
    }

    return FALSE;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 把原文件复制到备份路径，并在备份文件头部写入自描述信息。

@note  头部里的 OriginalPath 是「恢复不需要内存状态」的关键：
       即使驱动后来重启、记录表丢失，也能从备份文件本身找回原路径。
--*/
static
BOOLEAN
DragonRansomCopyToBackup(
    _In_ PCUNICODE_STRING Source,
    _In_ PCUNICODE_STRING BackupPath,
    _In_ PCUNICODE_STRING OriginalPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE SourceHandle;
    HANDLE BackupHandle;
    FILE_STANDARD_INFORMATION Standard;
    DRG_BACKUP_HEADER Header;
    PUCHAR Chunk;
    ULONGLONG Remaining;
    ULONG Requested;
    ULONG PathChars;
    BOOLEAN Result;

    SourceHandle = NULL;
    BackupHandle = NULL;
    Chunk = NULL;
    Result = FALSE;

    /* --- 1. 打开源文件（共享读写删，避免干扰正在使用该文件的程序） --- */

    InitializeObjectAttributes(
        &Attributes,
        (PUNICODE_STRING)Source,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &SourceHandle,
                 FILE_READ_DATA | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                 FILE_OPEN,
                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);

    if (!NT_SUCCESS(Status) || SourceHandle == NULL) {
        goto Exit;
    }

    /* --- 2. 取文件大小，超过上限直接放弃 --- */

    RtlZeroMemory(&Standard, sizeof(Standard));

    Status = ZwQueryInformationFile(
                 SourceHandle,
                 &IoStatus,
                 &Standard,
                 sizeof(Standard),
                 FileStandardInformation);

    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    if (Standard.EndOfFile.QuadPart <= 0 ||
        Standard.EndOfFile.QuadPart > (LONGLONG)g_Ransom.BackupMaxBytes) {
        goto Exit;
    }

    if (Standard.Directory == TRUE) {
        goto Exit;
    }

    /* --- 3. 创建备份文件并写入头部 --- */

    InitializeObjectAttributes(
        &Attributes,
        (PUNICODE_STRING)BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &BackupHandle,
                 FILE_WRITE_DATA | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ,
                 FILE_OVERWRITE_IF,
                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);

    if (!NT_SUCCESS(Status) || BackupHandle == NULL) {
        goto Exit;
    }

    RtlZeroMemory(&Header, sizeof(Header));

    Header.Magic = DRG_BACKUP_MAGIC;
    Header.Version = DRG_BACKUP_VERSION;
    Header.OriginalSize = (ULONGLONG)Standard.EndOfFile.QuadPart;
    Header.BackupTime = (ULONGLONG)DragonNow().QuadPart;

    PathChars = (ULONG)(OriginalPath->Length / sizeof(WCHAR));
    if (PathChars >= DRG_BACKUP_PATH_CHARS) {
        PathChars = DRG_BACKUP_PATH_CHARS - 1;
    }

    if (PathChars > 0) {
        RtlCopyMemory(Header.OriginalPath, OriginalPath->Buffer, PathChars * sizeof(WCHAR));
    }
    Header.OriginalPath[PathChars] = L'\0';
    Header.PathChars = PathChars;

    Status = ZwWriteFile(
                 BackupHandle,
                 NULL,
                 NULL,
                 NULL,
                 &IoStatus,
                 &Header,
                 sizeof(Header),
                 NULL,
                 NULL);

    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    /* --- 4. 分块复制正文 --- */

    Chunk = (PUCHAR)DragonAllocate(DRG_RANSOM_CHUNK_BYTES);
    if (Chunk == NULL) {
        goto Exit;
    }

    Remaining = Header.OriginalSize;

    while (Remaining > 0) {

        Requested = (Remaining > DRG_RANSOM_CHUNK_BYTES)
                        ? DRG_RANSOM_CHUNK_BYTES
                        : (ULONG)Remaining;

        Status = ZwReadFile(
                     SourceHandle,
                     NULL,
                     NULL,
                     NULL,
                     &IoStatus,
                     Chunk,
                     Requested,
                     NULL,
                     NULL);

        if (!NT_SUCCESS(Status) || IoStatus.Information == 0) {
            goto Exit;
        }

        Status = ZwWriteFile(
                     BackupHandle,
                     NULL,
                     NULL,
                     NULL,
                     &IoStatus,
                     Chunk,
                     (ULONG)IoStatus.Information,
                     NULL,
                     NULL);

        if (!NT_SUCCESS(Status)) {
            goto Exit;
        }

        Remaining -= IoStatus.Information;
    }

    Result = TRUE;

Exit:
    if (Chunk != NULL) {
        DragonFree(Chunk);
    }

    if (BackupHandle != NULL) {
        ZwClose(BackupHandle);
    }

    if (SourceHandle != NULL) {
        ZwClose(SourceHandle);
    }

    return Result;
}

/*=============================================================================
  对外接口：文档判定 / 备份 / 评分
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 该路径是否需要纳入防勒索保护。

        排除三类：备份目录自身（否则备份文件会被反复备份）、数据库文件、
        不在扩展名表内的其它文件。
--*/
BOOLEAN
DragonRansomIsDocument(
    _In_ PCUNICODE_STRING FileName
    )
{
    if (g_Ransom.Ready == FALSE || FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    /* 备份目录自身及其子路径不参与保护，避免自我循环 */
    if (g_Ransom.BackupDir.Length > 0 &&
        g_Ransom.BackupDir.Length <= FileName->Length) {

        UNICODE_STRING Prefix;

        Prefix.Buffer = FileName->Buffer;
        Prefix.Length = g_Ransom.BackupDir.Length;
        Prefix.MaximumLength = g_Ransom.BackupDir.Length;

        if (RtlEqualUnicodeString(&Prefix, &g_Ransom.BackupDir, TRUE) == TRUE) {
            return FALSE;
        }
    }

    if (DragonRansomLookupExtension(FileName, g_RansomExcludedExtensions,
                                    DRG_RANSOM_EXCLUDED_COUNT) != (ULONG)-1) {
        return FALSE;
    }

    return (DragonRansomLookupExtension(FileName, g_RansomDocExtensions,
                                        DRG_RANSOM_DOC_EXT_COUNT) != (ULONG)-1);
}

/*++
@IRQL: <= APC_LEVEL
@brief 该文件类型是否属于「本来就压缩/高熵」的容器。

        这类文件写入后的字节分布天然接近均匀，做熵判定只会制造误报。
--*/
static
BOOLEAN
DragonRansomIsPreCompressed(
    _In_ PCUNICODE_STRING FileName
    )
{
    return (DragonRansomLookupExtension(FileName, g_RansomCompressedExtensions,
                                        DRG_RANSOM_COMPRESSED_COUNT) != (ULONG)-1);
}

/*++
@IRQL: <= APC_LEVEL
@brief 该进程是否正被勒索阻断。
--*/
BOOLEAN
DragonRansomIsBlocked(
    _In_ HANDLE ProcessId
    )
{
    KIRQL OldIrql;
    PDRG_RANSOM_PROC Slot;
    BOOLEAN Blocked;
    LARGE_INTEGER Now;

    if (g_Ransom.Ready == FALSE || ProcessId == NULL) {
        return FALSE;
    }

    Blocked = FALSE;

    KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

    Slot = DragonRansomFindSlotLocked(
               ProcessId,
               PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess()));

    if (Slot != NULL && Slot->Blocked == TRUE) {

        Now = DragonNow();

        /* 阻断超过窗口且期间没有任何新操作 -> 自动解封，避免留下永久性拦截 */
        if (Now.QuadPart - Slot->BlockTime.QuadPart > DRG_RANSOM_BLOCK_TIMEOUT_100NS &&
            Now.QuadPart - Slot->LastActivity.QuadPart > DRG_RANSOM_BLOCK_TIMEOUT_100NS) {

            Slot->Blocked = FALSE;
            Slot->Score = 0;
            Slot->Flags = 0;
        }
        else {
            Blocked = TRUE;
        }
    }

    KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);

    return Blocked;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 写打开时创建备份。

        只在 PASSIVE_LEVEL 执行，且仅对「尚未备份过」的文件做一次，
        避免同一文件被反复复制导致 I/O 放大。
--*/
BOOLEAN
DragonRansomBackup(
    _In_ PCUNICODE_STRING FileName
    )
{
    WCHAR NameBuffer[32];
    UNICODE_STRING BackupPath;
    ULONGLONG Hash;
    BOOLEAN Created;

    if (g_Ransom.Ready == FALSE || g_Ransom.BackupDirReady == FALSE) {
        return FALSE;
    }

    if (DragonRansomIsDocument(FileName) == FALSE) {
        return FALSE;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    Hash = DragonRansomHashPath(FileName);

    /* 备份文件名 = 原路径哈希，可由原路径反算，无需索引 */
    {
        NTSTATUS FormatStatus;

        FormatStatus = RtlStringCbPrintfW(
                           NameBuffer,
                           sizeof(NameBuffer),
                           L"%016I64x.bak",
                           Hash);

        if (!NT_SUCCESS(FormatStatus)) {
            return FALSE;
        }
    }

    BackupPath.Buffer = (PWCHAR)DragonAllocate(DRG_BACKUP_PATH_CHARS * sizeof(WCHAR));
    if (BackupPath.Buffer == NULL) {
        return FALSE;
    }

    BackupPath.Length = 0;
    BackupPath.MaximumLength = DRG_BACKUP_PATH_CHARS * sizeof(WCHAR);

    if (!NT_SUCCESS(RtlStringCbCopyUnicodeString(
                        BackupPath.Buffer,
                        BackupPath.MaximumLength,
                        &g_Ransom.BackupDir)) ||
        !NT_SUCCESS(RtlStringCbCatW(BackupPath.Buffer, BackupPath.MaximumLength, NameBuffer))) {

        DragonFree(BackupPath.Buffer);
        return FALSE;
    }

    BackupPath.Length = (USHORT)(DragonWideLength(BackupPath.Buffer) * sizeof(WCHAR));

    Created = FALSE;

    if (DragonRansomBackupExists(&BackupPath) == FALSE) {

        Created = DragonRansomCopyToBackup(FileName, &BackupPath, FileName);

        if (Created == TRUE) {
            KIRQL OldIrql;

            InterlockedIncrement64(&g_Ransom.BackupsCreated);
            DragonMetricsBump(DrgMetricRansomBackups, 1);

            KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

            g_Ransom.BackedUpRing[g_Ransom.BackedUpHead] = Hash;
            g_Ransom.BackedUpHead = (g_Ransom.BackedUpHead + 1) % DRG_RANSOM_BACKEDUP_RING;
            if (g_Ransom.BackedUpCount < DRG_RANSOM_BACKEDUP_RING) {
                g_Ransom.BackedUpCount++;
            }

            /*
             * 受影响文件记录环。
             *
             * 恢复的权威依据是备份文件本身（原始路径写在它的头部里），这里的
             * 记录只服务两件事：状态查询显示条数、以及「恢复全部」时知道要处理
             * 哪些路径。所以允许被覆盖丢弃 —— 丢的只是展示完整性，不影响能否恢复。
             */
            {
                PDRG_RANSOM_RECORD Record;
                ULONG PathChars;

                Record = &g_Ransom.Records[g_Ransom.RecordHead];
                g_Ransom.RecordHead = (g_Ransom.RecordHead + 1) % DRG_RANSOM_RECORD_MAX;

                if (g_Ransom.RecordCount < DRG_RANSOM_RECORD_MAX) {
                    g_Ransom.RecordCount++;
                }

                RtlZeroMemory(Record, sizeof(*Record));
                Record->Time = DragonNow();
                Record->Pid = PsGetCurrentProcessId();
                Record->Operation = DRG_RANSOM_OP_WRITE;

                PathChars = (ULONG)(FileName->Length / sizeof(WCHAR));
                if (PathChars >= DRG_BACKUP_PATH_CHARS) {
                    PathChars = DRG_BACKUP_PATH_CHARS - 1;
                }

                RtlCopyMemory(Record->Path, FileName->Buffer, PathChars * sizeof(WCHAR));
                Record->Path[PathChars] = L'\0';
            }

            KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);
        }
    }
    else {
        Created = TRUE;
    }

    DragonFree(BackupPath.Buffer);

    return Created;
}

/*++
@IRQL: <= APC_LEVEL
@brief 记录一次文件操作并重新评分。

@return 0 表示放行；非 0 为事件码，表示本次操作应被拒绝。
--*/
ULONG
DragonRansomEvaluate(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FileName,
    _In_opt_ PCUNICODE_STRING NewName,
    _In_ ULONG Operation,
    _In_opt_ PVOID WriteBuffer,
    _In_ ULONG WriteLength
    )
{
    KIRQL OldIrql;
    PDRG_RANSOM_PROC Slot;
    PDRG_RANSOM_OP Op;
    ULONG Kind;
    ULONG Flags;
    ULONG Hash;
    ULONG Result;
    LONGLONG CreateTime;

    Result = 0;

    if (g_Ransom.Ready == FALSE || ProcessId == NULL || FileName == NULL) {
        return 0;
    }

    if (DragonRansomIsDocument(FileName) == FALSE) {
        return 0;
    }

    if (DragonRansomIsSystemProcess() == TRUE) {
        return 0;
    }

    Kind = DRG_RANSOM_OP_WRITE;
    Flags = 0;

    if ((Operation & DRG_OP_DELETE) != 0) {
        Kind = DRG_RANSOM_OP_DELETE;
    }
    else if ((Operation & DRG_OP_RENAME) != 0) {
        Kind = DRG_RANSOM_OP_RENAME;
    }

    /*
     * 扩展名变更：原本是文档类文件，改名后扩展名已不在文档表内
     * （.doc -> .doc.locked / .jpg -> .jpg.crypt 这类命名）。这是单个操作
     * 里最强的勒索信号 —— 正常重命名很少会把文件改成系统不认识的类型。
     */
    if (Kind == DRG_RANSOM_OP_RENAME && NewName != NULL && NewName->Length > 0 &&
        DragonRansomLookupExtension(NewName, g_RansomDocExtensions,
                                    DRG_RANSOM_DOC_EXT_COUNT) == (ULONG)-1) {
        Kind = DRG_RANSOM_OP_EXT_CHANGE;
    }

    /* 高熵采样：只对写操作、且跳过「本来就压缩/高熵」的类型 */
    if (Kind == DRG_RANSOM_OP_WRITE &&
        WriteBuffer != NULL &&
        WriteLength >= DRG_RANSOM_ENTROPY_MIN &&
        DragonRansomIsPreCompressed(FileName) == FALSE) {

        ULONG SampleLength;
        ULONG Randomness;

        SampleLength = WriteLength;
        if (SampleLength > DRG_RANSOM_ENTROPY_MAX) {
            SampleLength = DRG_RANSOM_ENTROPY_MAX;
        }

        Randomness = DragonRansomRandomness((PUCHAR)WriteBuffer, SampleLength);

        if (Randomness >= DRG_RANSOM_ENTROPY_THRESHOLD) {
            Flags |= DRG_RANSOM_SIG_ENTROPY;
        }
    }

    CreateTime = PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());

    KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

    Slot = DragonRansomAcquireSlotLocked(ProcessId, CreateTime);
    if (Slot == NULL) {
        KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);
        return 0;
    }

    /* 已被阻断的进程：直接拒绝，不再累计 */
    if (Slot->Blocked == TRUE) {
        Slot->LastActivity = DragonNow();
        Result = DRG_CODE_RANSOM_DETECT;
        KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);
        return Result;
    }

    Op = &Slot->Ops[Slot->OpHead];
    Slot->OpHead = (Slot->OpHead + 1) % DRG_RANSOM_OP_RING;

    Op->Time = DragonNow();
    Op->Kind = Kind;
    Op->Flags = Flags;

    Slot->LastActivity = Op->Time;

    if (Kind == DRG_RANSOM_OP_WRITE) {
        Slot->WriteTotal++;
    }

    /* 类型与目录多样性：只用哈希登记，不保存路径，内存占用可控 */
    Hash = DragonRansomHashDirectory(FileName);
    (VOID)DragonRansomRegisterDiversity(Slot->DirSlots, &Slot->DirSlotCount, Hash);

    {
        WCHAR Extension[32];

        Extension[0] = L'\0';

        if (DragonRansomExtractExtension(FileName, Extension, RTL_NUMBER_OF(Extension)) == TRUE) {

            ULONGLONG ExtensionHash;
            ULONG Index;

            ExtensionHash = DRG_FNV_BASIS;
            for (Index = 0; Extension[Index] != L'\0'; Index++) {

                WCHAR Character;

                Character = Extension[Index];
                if (Character >= L'A' && Character <= L'Z') {
                    Character = (WCHAR)(Character + (L'a' - L'A'));
                }

                ExtensionHash ^= (ULONGLONG)Character;
                ExtensionHash *= DRG_FNV_PRIME;
            }

            (VOID)DragonRansomRegisterDiversity(
                      Slot->ExtSlots,
                      &Slot->ExtSlotCount,
                      (ULONG)(ExtensionHash ^ (ExtensionHash >> 32)));
        }
    }

    DragonRansomScoreLocked(Slot);

    if (Slot->Score >= DRG_RANSOM_SCORE_THRESHOLD) {

        Slot->Blocked = TRUE;
        Slot->BlockTime = Op->Time;
        Result = DRG_CODE_RANSOM_DETECT;

        InterlockedIncrement64(&g_Ransom.BlockEvents);
        DragonMetricsBump(DrgMetricRansomBlocks, 1);
    }

    KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);

    return Result;
}

/*=============================================================================
  恢复
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 从备份还原单个文件。

@return TRUE 表示恢复成功。
--*/
static
BOOLEAN
DragonRansomRestoreOne(
    _In_ PCUNICODE_STRING OriginalPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE BackupHandle;
    HANDLE TargetHandle;
    UNICODE_STRING BackupPath;
    DRG_BACKUP_HEADER Header;
    PUCHAR Chunk;
    ULONGLONG Remaining;
    ULONG Requested;
    BOOLEAN Result;
    WCHAR NormBuf[DRG_BACKUP_PATH_CHARS];

    Result = FALSE;
    UNICODE_STRING NormPath;
    PCUNICODE_STRING UsePath;

    BackupHandle = NULL;
    TargetHandle = NULL;
    Chunk = NULL;
    Result = FALSE;

    BackupPath.Buffer = NULL;

    if (g_Ransom.BackupDirReady == FALSE) {
        return FALSE;
    }

    /* --- 0. 路径规范化：把 DOS/Win32 输入对齐到备份用的 NT 设备路径 --- */

    NormPath.Buffer = NormBuf;
    NormPath.Length = 0;
    NormPath.MaximumLength = sizeof(NormBuf);

    if (!NT_SUCCESS(DragonRansomCanonPath(OriginalPath, &NormPath)) ||
        NormPath.Length == 0) {
        /* 规范化失败：退化为原始输入，保持原行为 */
        RtlCopyUnicodeString(&NormPath, (PUNICODE_STRING)OriginalPath);
    }
    UsePath = &NormPath;

    /* --- 1. 由原路径反算备份文件 --- */

    BackupPath.Buffer = (PWCHAR)DragonAllocate(DRG_BACKUP_PATH_CHARS * sizeof(WCHAR));
    if (BackupPath.Buffer == NULL) {
        return FALSE;
    }

    BackupPath.Length = 0;
    BackupPath.MaximumLength = DRG_BACKUP_PATH_CHARS * sizeof(WCHAR);

    if (!NT_SUCCESS(RtlStringCbCopyUnicodeString(
                        BackupPath.Buffer,
                        BackupPath.MaximumLength,
                        &g_Ransom.BackupDir))) {
        goto Exit;
    }
    /* RtlStringCbCopyUnicodeString 只写缓冲区、不更新 Length；
       必须先按已写入的目录长度修正 Length，否则下面的 Printf 偏移为 0，
       会把目录覆盖成哈希文件名，导致备份路径落到「无目录的文件名」上
       （ZwCreateFile 报 STATUS_OBJECT_PATH_NOT_FOUND）。这是 C3/C4 恢复失败的真因。 */
    BackupPath.Length = (USHORT)(DragonWideLength(BackupPath.Buffer) * sizeof(WCHAR));

    if (!NT_SUCCESS(RtlStringCbPrintfW(
                        BackupPath.Buffer + (BackupPath.Length / sizeof(WCHAR)),
                        BackupPath.MaximumLength - BackupPath.Length,
                        L"%016I64x.bak",
                        DragonRansomHashPath(UsePath)))) {
        goto Exit;
    }

    BackupPath.Length = (USHORT)(DragonWideLength(BackupPath.Buffer) * sizeof(WCHAR));

    /* --- 2. 打开备份并校验头部 --- */

    InitializeObjectAttributes(
        &Attributes,
        &BackupPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &BackupHandle,
                 FILE_READ_DATA | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ,
                 FILE_OPEN,
                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);

    if (!NT_SUCCESS(Status) || BackupHandle == NULL) {
        goto Exit;
    }

    RtlZeroMemory(&Header, sizeof(Header));

    Status = ZwReadFile(
                 BackupHandle,
                 NULL,
                 NULL,
                 NULL,
                 &IoStatus,
                 &Header,
                 sizeof(Header),
                 NULL,
                 NULL);

    if (!NT_SUCCESS(Status) || IoStatus.Information != sizeof(Header)) {
        goto Exit;
    }

    if (Header.Magic != DRG_BACKUP_MAGIC || Header.Version != DRG_BACKUP_VERSION) {
        goto Exit;
    }

    /* 备份头部里的原路径必须与请求一致，防止哈希碰撞导致张冠李戴 */
    if (Header.PathChars == 0 || Header.PathChars > DRG_BACKUP_PATH_CHARS) {
        goto Exit;
    }

    {
        UNICODE_STRING HeaderPath;

        HeaderPath.Buffer = Header.OriginalPath;
        HeaderPath.Length = (USHORT)(Header.PathChars * sizeof(WCHAR));
        HeaderPath.MaximumLength = HeaderPath.Length;

        if (RtlEqualUnicodeString(&HeaderPath, UsePath, TRUE) == FALSE) {
            goto Exit;
        }
    }

    /* --- 3. 覆盖写回原文件 --- */

    InitializeObjectAttributes(
        &Attributes,
        (PUNICODE_STRING)UsePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(
                 &TargetHandle,
                 FILE_WRITE_DATA | SYNCHRONIZE,
                 &Attributes,
                 &IoStatus,
                 NULL,
                 FILE_ATTRIBUTE_NORMAL,
                 FILE_SHARE_READ,
                 FILE_OVERWRITE_IF,
                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                 NULL,
                 0);

    if (!NT_SUCCESS(Status) || TargetHandle == NULL) {
        goto Exit;
    }

    Chunk = (PUCHAR)DragonAllocate(DRG_RANSOM_CHUNK_BYTES);
    if (Chunk == NULL) {
        goto Exit;
    }

    Remaining = Header.OriginalSize;

    while (Remaining > 0) {

        Requested = (Remaining > DRG_RANSOM_CHUNK_BYTES)
                        ? DRG_RANSOM_CHUNK_BYTES
                        : (ULONG)Remaining;

        Status = ZwReadFile(
                     BackupHandle,
                     NULL,
                     NULL,
                     NULL,
                     &IoStatus,
                     Chunk,
                     Requested,
                     NULL,
                     NULL);

        if (!NT_SUCCESS(Status) || IoStatus.Information == 0) {
            goto Exit;
        }

        Status = ZwWriteFile(
                     TargetHandle,
                     NULL,
                     NULL,
                     NULL,
                     &IoStatus,
                     Chunk,
                     (ULONG)IoStatus.Information,
                     NULL,
                     NULL);

        if (!NT_SUCCESS(Status)) {
            goto Exit;
        }

        Remaining -= IoStatus.Information;
    }

    Result = TRUE;

Exit:
    if (Chunk != NULL) {
        DragonFree(Chunk);
    }

    if (TargetHandle != NULL) {
        ZwClose(TargetHandle);
    }

    if (BackupHandle != NULL) {
        ZwClose(BackupHandle);
    }

    if (BackupPath.Buffer != NULL) {
        DragonFree(BackupPath.Buffer);
    }

    return Result;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 执行恢复命令。

        Path 为空     -> 处理全部受影响记录（回滚模式）
        Path 非空     -> 只处理该路径对应的备份

        Mode 为 DRG_RESTORE_MODE_RELEASE 时只解除阻断、不触碰文件。

@note  恢复会读写文件（ZwCreateFile / ZwWriteFile，两者都要求 PASSIVE_LEVEL），
        而唯一入口是通信端口的消息回调。该回调的 IRQL 由 Filter Manager 保证为
        PASSIVE_LEVEL（PFLT_MESSAGE_NOTIFY 的官方文档在 Requirements 里明确标注
        IRQL = PASSIVE_LEVEL），所以这里不再加运行时守卫 —— 那只会变成死代码。
--*/
NTSTATUS
DragonRansomRestore(
    _In_opt_ PUNICODE_STRING Path,
    _In_ ULONG Mode,
    _Out_ PDRG_RESTORE_REPLY Reply
    )
{
    ULONG Index;
    ULONG Released;

    if (Reply == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Reply->Requested = 0;
    Reply->Restored = 0;
    Reply->Failed = 0;
    Reply->Released = 0;

    if (g_Ransom.Ready == FALSE) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* --- 1. 收集本次要处理的路径 --- */

    if (Path != NULL && Path->Length > 0) {

        Reply->Requested = 1;

        if (Mode == DRG_RESTORE_MODE_ROLLBACK) {

            if (DragonRansomRestoreOne(Path) == TRUE) {
                Reply->Restored++;
                InterlockedIncrement64(&g_Ransom.RestoredFiles);
                DragonMetricsBump(DrgMetricRansomRestores, 1);
            }
            else {
                Reply->Failed++;
            }
        }
    }
    else {

        /*
         * 全部记录：把受影响的路径先复制到本地数组，再在锁外逐个恢复 ——
         * 恢复涉及文件 I/O，绝不能在持有自旋锁时进行。
         */
        ULONG Count;
        PWCHAR Bucket;
        ULONG IndexInner;

        Count = g_Ransom.RecordCount;
        if (Count == 0) {
            Reply->Requested = 0;
        }
        else {

            Bucket = (PWCHAR)DragonAllocate(Count * DRG_BACKUP_PATH_CHARS * sizeof(WCHAR));
            if (Bucket == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlZeroMemory(Bucket, Count * DRG_BACKUP_PATH_CHARS * sizeof(WCHAR));

            {
                KIRQL OldIrql;

                KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

                Count = g_Ransom.RecordCount;

                for (Index = 0; Index < Count; Index++) {
                    RtlCopyMemory(
                        Bucket + (Index * DRG_BACKUP_PATH_CHARS),
                        g_Ransom.Records[Index].Path,
                        DRG_BACKUP_PATH_CHARS * sizeof(WCHAR));
                }

                KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);
            }

            Reply->Requested = Count;

            if (Mode == DRG_RESTORE_MODE_ROLLBACK) {

                for (IndexInner = 0; IndexInner < Count; IndexInner++) {

                    UNICODE_STRING Item;

                    RtlInitUnicodeString(&Item, Bucket + (IndexInner * DRG_BACKUP_PATH_CHARS));

                    if (Item.Length == 0) {
                        continue;
                    }

                    if (DragonRansomRestoreOne(&Item) == TRUE) {
                        Reply->Restored++;
                        InterlockedIncrement64(&g_Ransom.RestoredFiles);
                        DragonMetricsBump(DrgMetricRansomRestores, 1);
                    }
                    else {
                        Reply->Failed++;
                    }
                }
            }

            DragonFree(Bucket);
        }
    }

    /* --- 2. 解除所有阻断（回滚与仅解封两种模式都要做） --- */

    Released = 0;

    {
        KIRQL OldIrql;

        KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

        for (Index = 0; Index < DRG_RANSOM_PROC_SLOTS; Index++) {

            PDRG_RANSOM_PROC Slot;

            Slot = &g_Ransom.Procs[Index];

            if (Slot->Active == TRUE && Slot->Blocked == TRUE) {
                Slot->Blocked = FALSE;
                Slot->Score = 0;
                Slot->Flags = 0;
                Slot->Reported = FALSE;
                Released++;
            }
        }

        KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);
    }

    Reply->Released = Released;

    return STATUS_SUCCESS;
}

/*=============================================================================
  查询与清理
=============================================================================*/

/*++
@IRQL: <= APC_LEVEL
@brief 填充勒索防护状态快照。
--*/
VOID
DragonRansomQueryStatus(
    _Out_ PDRG_RANSOM_STATUS Status
    )
{
    ULONG Index;
    KIRQL OldIrql;

    if (Status == NULL) {
        return;
    }

    RtlZeroMemory(Status, sizeof(*Status));

    KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

    for (Index = 0; Index < DRG_RANSOM_PROC_SLOTS; Index++) {

        PDRG_RANSOM_PROC Slot;

        Slot = &g_Ransom.Procs[Index];

        if (Slot->Active == FALSE) {
            continue;
        }

        Status->TrackedProcesses++;

        if (Slot->Blocked == TRUE) {
            Status->BlockedProcesses++;
            Status->Blocking = 1;
        }

        if (Slot->Score > Status->MaxScore) {
            Status->MaxScore = Slot->Score;
            Status->DetectionFlags = Slot->Flags;
            Status->BlockedPid = (ULONG)(ULONG_PTR)Slot->Pid;
        }
    }

    Status->Records = g_Ransom.RecordCount;

    KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);

    Status->BackupsCreated = (ULONG)InterlockedCompareExchange64(&g_Ransom.BackupsCreated, 0, 0);
    Status->RestoredFiles = (ULONG)InterlockedCompareExchange64(&g_Ransom.RestoredFiles, 0, 0);
}

/*++
@IRQL: <= APC_LEVEL
@brief 进程退出时释放跟踪槽。

        调用方是进程退出通知；此处只做 O(n) 标记，真正的内存回收留在后续
        槽位复用时进行（静态数组，不存在释放问题）。
--*/
VOID
DragonRansomForgetProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG Index;
    KIRQL OldIrql;

    if (g_Ransom.Ready == FALSE || ProcessId == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

    for (Index = 0; Index < DRG_RANSOM_PROC_SLOTS; Index++) {
        if (g_Ransom.Procs[Index].Active == TRUE &&
            g_Ransom.Procs[Index].Pid == ProcessId) {

            RtlZeroMemory(&g_Ransom.Procs[Index], sizeof(g_Ransom.Procs[Index]));
            break;
        }
    }

    KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 初始化：初始化锁，解析备份目录与备份上限，创建备份目录。

        配置来源（服务键 \Parameters 下，均可缺省）：
          RansomBackupDir      REG_SZ   备份目录（NT 或 Win32 路径）
          RansomBackupMaxBytes REG_DWORD 单文件备份上限
        缺省时备份目录取「驱动镜像同级目录 \RansomBackup\」。
--*/
NTSTATUS
DragonRansomInitialize(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING SubKeyName;
    UNICODE_STRING ValueName;
    HANDLE ServiceKey;
    HANDLE ParametersKey;
    UCHAR Buffer[1024];
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG ResultLength;
    ULONG Length;
    BOOLEAN Found;

    KeInitializeSpinLock(&g_Ransom.Lock);

    g_Ransom.Ready = FALSE;
    g_Ransom.BackupDirReady = FALSE;
    g_Ransom.BackupMaxBytes = DRG_RANSOM_DEFAULT_BACKUP_MAX;
    g_Ransom.BackupDir.Buffer = g_Ransom.BackupDirBuffer;
    g_Ransom.BackupDir.Length = 0;
    g_Ransom.BackupDir.MaximumLength = sizeof(g_Ransom.BackupDirBuffer);
    RtlZeroMemory(g_Ransom.BackupDirBuffer, sizeof(g_Ransom.BackupDirBuffer));

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ServiceKey = NULL;
    ParametersKey = NULL;
    Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;

    InitializeObjectAttributes(
        &Attributes,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwOpenKey(&ServiceKey, KEY_READ, &Attributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /*
     * 参数优先从 <服务键>\Parameters 读取（INF 与部署脚本写入的位置），
     * 读不到再回退到服务键根（手工部署可能写在那里）—— 与 ClientImagePath
     * 的读取策略一致，杜绝「脚本写了但驱动读不到」的静默失效。
     */
    RtlInitUnicodeString(&SubKeyName, L"Parameters");

    InitializeObjectAttributes(
        &Attributes,
        &SubKeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        ServiceKey,
        NULL);

    Status = ZwOpenKey(&ParametersKey, KEY_READ, &Attributes);
    if (!NT_SUCCESS(Status)) {
        ParametersKey = NULL;
    }

    /* --- 单文件备份上限 --- */

    RtlInitUnicodeString(&ValueName, DRG_RANSOM_VALUE_BACKUP_MAX);

    Found = FALSE;

    if (ParametersKey != NULL) {
        ResultLength = sizeof(Buffer);
        Status = ZwQueryValueKey(
                     ParametersKey, &ValueName, KeyValuePartialInformation,
                     Info, ResultLength, &ResultLength);
        if (NT_SUCCESS(Status)) {
            Found = TRUE;
        }
    }

    if (Found == FALSE) {
        ResultLength = sizeof(Buffer);
        Status = ZwQueryValueKey(
                     ServiceKey, &ValueName, KeyValuePartialInformation,
                     Info, ResultLength, &ResultLength);
        if (NT_SUCCESS(Status)) {
            Found = TRUE;
        }
    }

    if (Found == TRUE &&
        Info->Type == REG_DWORD &&
        Info->DataLength >= sizeof(ULONG)) {

        ULONG Value;

        RtlCopyMemory(&Value, Info->Data, sizeof(ULONG));

        if (Value >= 65536u) {
            g_Ransom.BackupMaxBytes = Value;
        }
    }

    /* --- 备份目录 --- */

    RtlInitUnicodeString(&ValueName, DRG_RANSOM_VALUE_BACKUP_DIR);

    Found = FALSE;

    if (ParametersKey != NULL) {
        ResultLength = sizeof(Buffer);
        Status = ZwQueryValueKey(
                     ParametersKey, &ValueName, KeyValuePartialInformation,
                     Info, ResultLength, &ResultLength);
        if (NT_SUCCESS(Status)) {
            Found = TRUE;
        }
    }

    if (Found == FALSE) {
        ResultLength = sizeof(Buffer);
        Status = ZwQueryValueKey(
                     ServiceKey, &ValueName, KeyValuePartialInformation,
                     Info, ResultLength, &ResultLength);
        if (NT_SUCCESS(Status)) {
            Found = TRUE;
        }
    }

    if (Found == TRUE &&
        (Info->Type == REG_SZ || Info->Type == REG_EXPAND_SZ) &&
        Info->DataLength >= sizeof(WCHAR)) {

        Length = Info->DataLength / sizeof(WCHAR);

        if (Length > 0 && ((PCWSTR)Info->Data)[Length - 1] == L'\0') {
            Length--;
        }

        if (Length > 0 && Length < DRG_BACKUP_PATH_CHARS - 1) {

            RtlCopyMemory(g_Ransom.BackupDirBuffer, Info->Data, Length * sizeof(WCHAR));
            g_Ransom.BackupDirBuffer[Length] = L'\0';
            g_Ransom.BackupDir.Length = (USHORT)(Length * sizeof(WCHAR));
        }
    }

    /* --- 备份目录未配置：取驱动镜像所在目录下的 RansomBackup\ --- */

    if (g_Ransom.BackupDir.Length == 0) {

        RtlInitUnicodeString(&ValueName, L"ImagePath");

        ResultLength = sizeof(Buffer);

        Status = ZwQueryValueKey(
                     ServiceKey, &ValueName, KeyValuePartialInformation,
                     Info, ResultLength, &ResultLength);

        if (NT_SUCCESS(Status) &&
            (Info->Type == REG_SZ || Info->Type == REG_EXPAND_SZ) &&
            Info->DataLength >= sizeof(WCHAR)) {

            ULONG Chars;
            ULONG Index;
            ULONG LastSeparator;

            Chars = Info->DataLength / sizeof(WCHAR);

            if (Chars > 0 && ((PCWSTR)Info->Data)[Chars - 1] == L'\0') {
                Chars--;
            }

            LastSeparator = (ULONG)-1;

            for (Index = 0; Index < Chars && Index < DRG_BACKUP_PATH_CHARS - 1; Index++) {
                if (((PCWSTR)Info->Data)[Index] == L'\\') {
                    LastSeparator = Index;
                }
            }

            if (LastSeparator != (ULONG)-1 && LastSeparator > 0) {

                ULONG DirChars;
                ULONG SuffixChars;

                /*
                 * ImagePath 形如 \??\C:\...\drivers\Dragon-Drivers.sys，
                 * LastSeparator 指向最后一个反斜杠，它之前的部分即镜像所在目录。
                 *
                 * 必须把默认子目录名一并拼上：若只截取目录，备份文件会直接落在
                 * 系统驱动目录（System32\drivers\）里 —— 既污染系统目录，也让
                 * 「备份区」与驱动本体混在一处，不利于后续把备份区单独纳入自保护
                 * 范围。此处与本函数开头的注释、以及交付说明保持一致，
                 * 默认位置为 <镜像所在目录>\RansomBackup\。
                 */
                DirChars = LastSeparator;
                SuffixChars = (ULONG)(RTL_NUMBER_OF(DRG_RANSOM_BACKUP_SUBDIR) - 1);

                if (DirChars + 1 + SuffixChars < DRG_BACKUP_PATH_CHARS) {

                    RtlCopyMemory(
                        g_Ransom.BackupDirBuffer,
                        Info->Data,
                        DirChars * sizeof(WCHAR));

                    g_Ransom.BackupDirBuffer[DirChars] = L'\\';

                    RtlCopyMemory(
                        g_Ransom.BackupDirBuffer + DirChars + 1,
                        DRG_RANSOM_BACKUP_SUBDIR,
                        SuffixChars * sizeof(WCHAR));

                    g_Ransom.BackupDirBuffer[DirChars + 1 + SuffixChars] = L'\0';
                    g_Ransom.BackupDir.Length =
                        (USHORT)((DirChars + 1 + SuffixChars) * sizeof(WCHAR));
                }
            }
        }
    }

    if (ParametersKey != NULL) {
        ZwClose(ParametersKey);
        ParametersKey = NULL;
    }

    ZwClose(ServiceKey);
    ServiceKey = NULL;

    /* --- 规范化：补 NT 对象前缀与结尾反斜杠 --- */

    if (g_Ransom.BackupDir.Length > 0) {

        PWCHAR Text;
        ULONG Chars;
        WCHAR Final[DRG_BACKUP_PATH_CHARS];
        ULONG FinalChars;

        Text = g_Ransom.BackupDirBuffer;
        Chars = g_Ransom.BackupDir.Length / sizeof(WCHAR);
        FinalChars = 0;

        RtlZeroMemory(Final, sizeof(Final));

        if (Chars >= 4 && RtlEqualMemory(Text, L"\\??\\", 4 * sizeof(WCHAR)) == TRUE) {

            /* 已经是 NT 对象路径，原样使用 */
            RtlCopyMemory(Final, Text, Chars * sizeof(WCHAR));
            FinalChars = Chars;
        }
        else if (Chars >= 11 &&
                 RtlEqualMemory(Text, L"\\SystemRoot", 11 * sizeof(WCHAR)) == TRUE) {

            /* \SystemRoot 前缀内核对对象管理器可直接解析，保留 */
            RtlCopyMemory(Final, Text, Chars * sizeof(WCHAR));
            FinalChars = Chars;
        }
        else if (Chars >= 2 && Text[1] == L':') {

            /* 形如 C:\... 的 Win32 路径：补 \??\ 前缀 */
            Final[0] = L'\\';
            Final[1] = L'?';
            Final[2] = L'?';
            Final[3] = L'\\';

            RtlCopyMemory(Final + 4, Text, Chars * sizeof(WCHAR));
            FinalChars = Chars + 4;
        }
        else {

            /*
             * 形态不认识（相对路径等）：放弃备份目录，只保留评分能力。
             * 与其对着一个解析不了的路径反复失败，不如明确降级 ——
             * 状态查询里的 BackupsCreated 会停在 0，一眼能看出没生效。
             */
            g_Ransom.BackupDir.Length = 0;
            FinalChars = 0;
        }

        if (FinalChars > 0) {

            if (Final[FinalChars - 1] != L'\\') {
                Final[FinalChars] = L'\\';
                FinalChars++;
            }

            Final[FinalChars] = L'\0';

            RtlZeroMemory(g_Ransom.BackupDirBuffer, sizeof(g_Ransom.BackupDirBuffer));
            RtlCopyMemory(g_Ransom.BackupDirBuffer, Final, (FinalChars + 1) * sizeof(WCHAR));

            g_Ransom.BackupDir.Length = (USHORT)(FinalChars * sizeof(WCHAR));
        }
    }


    g_Ransom.Ready = TRUE;

    if (g_Ransom.BackupDir.Length > 0) {

        Status = DragonRansomEnsureDirectory();

        if (NT_SUCCESS(Status)) {
            g_Ransom.BackupDirReady = TRUE;

            /*
             * 把备份区登记为自保护的豁免目录（只放行内核自身发起的写入）。
             *
             * 备份区默认就在驱动镜像所在目录里，而那个目录很可能被安装期写入的
             * GuardPaths 覆盖 —— 自保护只按路径判定、不看发起者，不登记就会把
             * 我们自己的备份写入一并挡掉（现场表现：评分正常、备份数恒为 0）。
             */
            DragonSelfProtectAddExemptDir(&g_Ransom.BackupDir);

            /*
             * 成功路径也打一条：备份目录的实际解析结果（含是否来自注册表配置）
             * 是排障时第一个要看的东西 —— 只报失败会让人无法确认「默认值算出来
             * 到底对不对」。
             */
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "Dragon-Drivers: ransom backup directory = %wZ\n",
                &g_Ransom.BackupDir);
        }
        else {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "Dragon-Drivers: ransom backup directory unavailable (0x%08X), "
                "scoring stays active but no file will be backed up\n",
                Status);
        }
    }

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 拆卸：清空所有状态。
--*/
VOID
DragonRansomTeardown(
    VOID
    )
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_Ransom.Lock, &OldIrql);

    RtlZeroMemory(g_Ransom.Procs, sizeof(g_Ransom.Procs));
    RtlZeroMemory(g_Ransom.Records, sizeof(g_Ransom.Records));
    RtlZeroMemory(g_Ransom.BackedUpRing, sizeof(g_Ransom.BackedUpRing));

    g_Ransom.RecordHead = 0;
    g_Ransom.RecordCount = 0;
    g_Ransom.BackedUpHead = 0;
    g_Ransom.BackedUpCount = 0;

    KeReleaseSpinLock(&g_Ransom.Lock, OldIrql);

    g_Ransom.Ready = FALSE;
    g_Ransom.BackupDirReady = FALSE;
}
