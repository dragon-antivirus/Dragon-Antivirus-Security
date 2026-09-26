/*++
===============================================================================
 Dragon-Drivers / DragonSupport.c

 通用工具层：池分配、IRQL 判定、时间换算、路径复制、通配符匹配。

 本文件不持有任何全局可变状态，可被任意 IRQL 的调用方安全使用
 （具体上限见每个函数头部的 IRQL 标注）。
===============================================================================
--*/

#include "DragonCommon.h"

#define DRG_INDEX_NONE   ((ULONG)0xFFFFFFFFu)

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 分配不可分页（NX）内核内存。返回的内存已被 ExAllocatePool2 清零。
--*/
PVOID
DragonAllocate(
    _In_ SIZE_T Size
    )
{
    if (Size == 0) {
        return NULL;
    }

    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, DRG_POOL_TAG);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 释放由 DragonAllocate 分配的内存；NULL 安全。
--*/
VOID
DragonFree(
    _In_opt_ PVOID Pointer
    )
{
    if (Pointer == NULL) {
        return;
    }

    ExFreePoolWithTag(Pointer, DRG_POOL_TAG);
}

/*++
@IRQL: 任意
@brief 当前是否处于 PASSIVE_LEVEL。
--*/
BOOLEAN
DragonAtPassiveLevel(
    VOID
    )
{
    return (KeGetCurrentIrql() == PASSIVE_LEVEL) ? TRUE : FALSE;
}

/*++
@IRQL: 任意
@brief 读取当前系统时间（自 1601-01-01 起的 100ns 数）。
--*/
LARGE_INTEGER
DragonNow(
    VOID
    )
{
    LARGE_INTEGER Now;

    Now.QuadPart = 0;
    KeQuerySystemTime(&Now);
    return Now;
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 毫秒 -> 负相对 100ns 值，供 KeWaitForSingleObject / KeDelayExecutionThread 使用。
--*/
LONGLONG
DragonMillisecondsToRelative(
    _In_ ULONG Milliseconds
    )
{
    if (Milliseconds == 0) {
        return 0;
    }

    return -((LONGLONG)Milliseconds * 10000LL);
}

/*++
@IRQL: <= DISPATCH_LEVEL
@brief 把 Source 指向的宽字符串截断复制到 Destination，并保证 NUL 结尾。

@param  DestinationChars  Destination 的容量（以 WCHAR 计，含结尾 NUL）
@param  SourceBytes       Source 中有效字节数（可以为 0，此时按 NUL 结尾串处理）
@return 实际写入的有效字节数（不含结尾 NUL）
--*/
USHORT
DragonCopyPath(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCWSTR Source,
    _In_ USHORT SourceBytes
    )
{
    ULONG MaxChars;
    ULONG CopyChars;
    ULONG Index;

    if (Destination == NULL || DestinationChars == 0) {
        return 0;
    }

    Destination[0] = L'\0';

    if (Source == NULL) {
        return 0;
    }

    /* 预留 1 个 WCHAR 给结尾 NUL */
    MaxChars = DestinationChars - 1;
    if (MaxChars == 0) {
        return 0;
    }

    CopyChars = 0;
    if (SourceBytes > 0) {
        CopyChars = SourceBytes / sizeof(WCHAR);
    }

    if (CopyChars > MaxChars) {
        CopyChars = MaxChars;
    }

    for (Index = 0; Index < CopyChars; Index++) {
        if (Source[Index] == L'\0') {
            break;
        }
        Destination[Index] = Source[Index];
    }

    Destination[Index] = L'\0';
    return (USHORT)(Index * sizeof(WCHAR));
}

/*++
@IRQL: <= APC_LEVEL
@brief 段匹配：等长比较，'?' 匹配任意单字符，其余大小写不敏感。

@note  Pattern 段不会被 NUL 截断，比较长度完全由 PatternChars 决定。
--*/
static
BOOLEAN
DragonSegmentMatchAt(
    _In_reads_(SegmentChars) PCWSTR Segment,
    _In_ ULONG SegmentChars,
    _In_reads_(TextChars) PCWSTR Text,
    _In_ ULONG TextChars
    )
{
    ULONG Index;

    if (SegmentChars != TextChars) {
        return FALSE;
    }

    for (Index = 0; Index < SegmentChars; Index++) {
        if (Segment[Index] == L'?') {
            continue;
        }

        if (RtlDowncaseUnicodeChar(Segment[Index]) != RtlDowncaseUnicodeChar(Text[Index])) {
            return FALSE;
        }
    }

    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 自 Text[FromIndex] 起向后查找首个能容纳 Segment 的位置。

@return 命中起始下标；未命中返回 DRG_INDEX_NONE。
--*/
static
ULONG
DragonFindSegment(
    _In_reads_(SegmentChars) PCWSTR Segment,
    _In_ ULONG SegmentChars,
    _In_reads_(TextChars) PCWSTR Text,
    _In_ ULONG TextChars,
    _In_ ULONG FromIndex
    )
{
    ULONG Index;
    ULONG LastStart;

    if (SegmentChars > TextChars) {
        return DRG_INDEX_NONE;
    }

    LastStart = TextChars - SegmentChars;

    for (Index = FromIndex; Index <= LastStart; Index++) {
        if (DragonSegmentMatchAt(Segment, SegmentChars, Text + Index, SegmentChars)) {
            return Index;
        }
    }

    return DRG_INDEX_NONE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 通配符匹配，大小写不敏感。

       算法：把模式按 '*' 切分为若干「段」，段内支持 '?'。
         · 模式不以 '*' 开头时，首段必须锚定在文本起点；
         · 以 '*' 结尾时，最后一段可为空，剩余文本全部被吞掉；
         · 否则最后一段必须锚定在文本末尾；
         · 中间段采用「最早出现位置」贪心策略——因为末段被锚定在末尾，
           最早放置只会为后续段留出最大空间，因此该贪心是完备的。

@param  TextBytes  Text 的有效字节数（Text 未必有 NUL 结尾）
--*/
BOOLEAN
DragonWildcardMatch(
    _In_opt_ PCWSTR Pattern,
    _In_opt_ PCWSTR Text,
    _In_ USHORT TextBytes
    )
{
    ULONG TextChars;
    ULONG PatternPos;
    ULONG TextPos;
    ULONG SegmentStart;
    ULONG SegmentChars;
    BOOLEAN AnchoredStart;
    BOOLEAN FirstSegment;
    ULONG Found;

    if (Pattern == NULL || Text == NULL) {
        return FALSE;
    }

    TextChars = (ULONG)(TextBytes / sizeof(WCHAR));
    PatternPos = 0;
    TextPos = 0;
    AnchoredStart = (Pattern[0] == L'*') ? FALSE : TRUE;
    FirstSegment = TRUE;

    for (;;) {
        SegmentStart = PatternPos;
        while (Pattern[PatternPos] != L'\0' && Pattern[PatternPos] != L'*') {
            PatternPos++;
        }

        SegmentChars = PatternPos - SegmentStart;

        if (Pattern[PatternPos] == L'*') {
            PatternPos++;
        }
        else {
            /* 模式在本段结束，说明这是最后一段 */
            if (FirstSegment == TRUE && AnchoredStart == TRUE) {
                /* 模式整体不含 '*'：长度必须完全一致 */
                if (TextChars != SegmentChars) {
                    return FALSE;
                }
                return DragonSegmentMatchAt(Pattern + SegmentStart, SegmentChars, Text, TextChars);
            }

            if (SegmentChars == 0) {
                /* 模式以 '*' 收尾，剩余文本可任意 */
                return TRUE;
            }

            if (TextChars < SegmentChars) {
                return FALSE;
            }

            return DragonSegmentMatchAt(
                       Pattern + SegmentStart,
                       SegmentChars,
                       Text + (TextChars - SegmentChars),
                       SegmentChars);
        }

        /* 本段后面还有 '*'，属于中间段 */
        if (SegmentChars > 0) {
            if (FirstSegment == TRUE && AnchoredStart == TRUE) {
                if (TextChars < SegmentChars) {
                    return FALSE;
                }
                if (DragonSegmentMatchAt(Pattern + SegmentStart, SegmentChars, Text, SegmentChars) == FALSE) {
                    return FALSE;
                }
                TextPos = SegmentChars;
            }
            else {
                Found = DragonFindSegment(Pattern + SegmentStart, SegmentChars, Text, TextChars, TextPos);
                if (Found == DRG_INDEX_NONE) {
                    return FALSE;
                }
                TextPos = Found + SegmentChars;
            }
        }

        FirstSegment = FALSE;
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 模式串特异性评分：非通配字符数量 + 1。用于 Include/Exclude 优先裁决。
--*/
ULONG
DragonPatternSpecificity(
    _In_opt_ PCUNICODE_STRING Pattern
    )
{
    ULONG Score;
    ULONG Chars;
    ULONG Index;

    if (Pattern == NULL || Pattern->Buffer == NULL) {
        return 0;
    }

    Chars = (ULONG)(Pattern->Length / sizeof(WCHAR));
    Score = 1;

    for (Index = 0; Index < Chars; Index++) {
        if (Pattern->Buffer[Index] != L'*' && Pattern->Buffer[Index] != L'?') {
            Score++;
        }
    }

    return Score;
}

/*++
@IRQL: <= APC_LEVEL
@brief ASCII 大小写不敏感等值比较（仅处理 'A'-'Z'）。
--*/
BOOLEAN
DragonAnsiEqualNoCase(
    _In_opt_ PCSTR Left,
    _In_opt_ PCSTR Right
    )
{
    CHAR L;
    CHAR R;

    if (Left == NULL || Right == NULL) {
        return FALSE;
    }

    for (;;) {
        L = *Left;
        R = *Right;

        if (L >= 'A' && L <= 'Z') {
            L = (CHAR)(L - 'A' + 'a');
        }
        if (R >= 'A' && R <= 'Z') {
            R = (CHAR)(R - 'A' + 'a');
        }

        if (L != R) {
            return FALSE;
        }

        if (L == '\0') {
            return TRUE;
        }

        Left++;
        Right++;
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 宽字符串长度（不含结尾 NUL）。
--*/
ULONG
DragonWideLength(
    _In_opt_ PCWSTR Text
    )
{
    ULONG Length;

    if (Text == NULL) {
        return 0;
    }

    Length = 0;
    while (Text[Length] != L'\0') {
        Length++;
    }

    return Length;
}

/*++
@IRQL: <= APC_LEVEL
@brief 判断 Text 是否以 Prefix（NUL 结尾）开头，大小写不敏感。
--*/
BOOLEAN
DragonWideStartsWithNoCase(
    _In_opt_ PCWSTR Text,
    _In_opt_ PCWSTR Prefix
    )
{
    ULONG Index;

    if (Text == NULL || Prefix == NULL) {
        return FALSE;
    }

    Index = 0;
    while (Prefix[Index] != L'\0') {
        if (Text[Index] == L'\0') {
            return FALSE;
        }
        if (RtlDowncaseUnicodeChar(Text[Index]) != RtlDowncaseUnicodeChar(Prefix[Index])) {
            return FALSE;
        }
        Index++;
    }

    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 判断 Text 是否以 Suffix（NUL 结尾）结尾，大小写不敏感。
--*/
BOOLEAN
DragonHasSuffix(
    _In_opt_ PCUNICODE_STRING Text,
    _In_opt_ PCWSTR Suffix
    )
{
    ULONG TextChars;
    ULONG SuffixChars;
    ULONG Offset;
    ULONG Index;

    if (Text == NULL || Text->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }

    TextChars = (ULONG)(Text->Length / sizeof(WCHAR));
    SuffixChars = 0;
    while (Suffix[SuffixChars] != L'\0') {
        SuffixChars++;
    }

    if (TextChars < SuffixChars) {
        return FALSE;
    }

    Offset = TextChars - SuffixChars;
    for (Index = 0; Index < SuffixChars; Index++) {
        if (RtlDowncaseUnicodeChar(Text->Buffer[Offset + Index]) !=
            RtlDowncaseUnicodeChar(Suffix[Index])) {
            return FALSE;
        }
    }

    return TRUE;
}
