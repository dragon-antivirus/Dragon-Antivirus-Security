/*++
===============================================================================
 Dragon-Drivers / DragonJson.c

 极简 JSON 扫描器。

 只实现规则文件所需的子集：
   · 对象成员遍历（由调用方驱动键名匹配）
   · 无符号整数（十进制 / 0x 十六进制）
   · true / false
   · 字符串（保留转义原样，由 DragonJsonUnescape 二次处理）
   · 任意值跳过（含嵌套数组/对象）

 设计约束：
   · 全程指针游标 + 边界检查，绝不越界读取；
   · 不做任何内存分配，缓冲区由调用方提供；
   · 不实现递归，避免内核栈放大。
===============================================================================
--*/

#include "DragonCommon.h"

#define DRG_JSON_QUOTE  '"'
#define DRG_JSON_COLON  ':'

/*++
@IRQL: <= APC_LEVEL
@brief 初始化游标。
--*/
VOID
DragonJsonInit(
    _Out_ PDRG_JSON_CURSOR Cursor,
    _In_reads_bytes_(Length) PCSTR Buffer,
    _In_ ULONG Length
    )
{
    if (Cursor == NULL) {
        return;
    }

    Cursor->Begin = Buffer;
    Cursor->Current = Buffer;
    Cursor->End = (Buffer != NULL) ? (Buffer + Length) : NULL;
}

/*++
@IRQL: <= APC_LEVEL
@brief 取当前字符；越界返回 0。
--*/
CHAR
DragonJsonPeek(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    if (Cursor == NULL || Cursor->Current == NULL || Cursor->End == NULL) {
        return 0;
    }

    if (Cursor->Current >= Cursor->End) {
        return 0;
    }

    return *Cursor->Current;
}

/*++
@IRQL: <= APC_LEVEL
@brief 跳过空白字符。
--*/
VOID
DragonJsonSkipSpace(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    CHAR Ch;

    if (Cursor == NULL || Cursor->Current == NULL || Cursor->End == NULL) {
        return;
    }

    while (Cursor->Current < Cursor->End) {
        Ch = *Cursor->Current;
        if (Ch == ' ' || Ch == '\t' || Ch == '\r' || Ch == '\n') {
            Cursor->Current++;
        }
        else {
            break;
        }
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 读取无符号整数，支持 0x / 0X 前缀走十六进制；非法字符即停止。
--*/
ULONGLONG
DragonJsonReadUInt64(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    ULONGLONG Value;
    ULONG Base;
    CHAR Ch;
    ULONG Digit;

    Value = 0;
    Base = 10;

    DragonJsonSkipSpace(Cursor);

    if (Cursor == NULL || Cursor->Current == NULL || Cursor->End == NULL) {
        return 0;
    }

    if ((Cursor->Current + 1) < Cursor->End &&
        Cursor->Current[0] == '0' &&
        (Cursor->Current[1] == 'x' || Cursor->Current[1] == 'X')) {
        Base = 16;
        Cursor->Current += 2;
    }

    while (Cursor->Current < Cursor->End) {
        Ch = *Cursor->Current;
        Digit = 0xFFFFFFFFu;

        if (Ch >= '0' && Ch <= '9') {
            Digit = (ULONG)(Ch - '0');
        }
        else if (Base == 16 && Ch >= 'a' && Ch <= 'f') {
            Digit = (ULONG)(Ch - 'a') + 10u;
        }
        else if (Base == 16 && Ch >= 'A' && Ch <= 'F') {
            Digit = (ULONG)(Ch - 'A') + 10u;
        }
        else {
            break;
        }

        if (Digit >= Base) {
            break;
        }

        Value = (Value * Base) + Digit;
        Cursor->Current++;
    }

    return Value;
}

/*++
@IRQL: <= APC_LEVEL
@brief 读取 ULONG，溢出饱和到 MAXULONG。
--*/
ULONG
DragonJsonReadUInt32(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    ULONGLONG Value;

    Value = DragonJsonReadUInt64(Cursor);
    if (Value > (ULONGLONG)MAXULONG) {
        return MAXULONG;
    }

    return (ULONG)Value;
}

/*++
@IRQL: <= APC_LEVEL
@brief 读取 true / false；成功返回 TRUE 并回填 Value。
--*/
BOOLEAN
DragonJsonReadBoolean(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_ PBOOLEAN Value
    )
{
    if (Cursor == NULL || Value == NULL) {
        return FALSE;
    }

    DragonJsonSkipSpace(Cursor);

    if (Cursor->Current == NULL || Cursor->End == NULL) {
        return FALSE;
    }

    if ((Cursor->Current + 4) <= Cursor->End &&
        RtlCompareMemory(Cursor->Current, "true", 4) == 4) {
        *Value = TRUE;
        Cursor->Current += 4;
        return TRUE;
    }

    if ((Cursor->Current + 5) <= Cursor->End &&
        RtlCompareMemory(Cursor->Current, "false", 5) == 5) {
        *Value = FALSE;
        Cursor->Current += 5;
        return TRUE;
    }

    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 读取带引号字符串的原始内容（保留反斜杠转义，不负责反转义）。

@param  BufferChars  Buffer 容量（含结尾 NUL）；空间不足时仍会消费完整字符串
                     并返回 FALSE，以保持游标一致性。
--*/
BOOLEAN
DragonJsonReadRawString(
    _In_ PDRG_JSON_CURSOR Cursor,
    _Out_writes_(BufferChars) PCHAR Buffer,
    _In_ ULONG BufferChars
    )
{
    ULONG Written;
    CHAR Ch;
    BOOLEAN Escaped;

    if (Cursor == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = '\0';

    DragonJsonSkipSpace(Cursor);

    if (Cursor->Current == NULL || Cursor->End == NULL) {
        return FALSE;
    }

    if (DragonJsonPeek(Cursor) != DRG_JSON_QUOTE) {
        return FALSE;
    }

    Cursor->Current++;

    Written = 0;
    Escaped = FALSE;
    while (Cursor->Current < Cursor->End) {
        Ch = *Cursor->Current;

        if (Ch == DRG_JSON_QUOTE && Escaped == FALSE) {
            break;
        }

        if ((Written + 1) < BufferChars) {
            Buffer[Written] = Ch;
            Written++;
        }

        if (Ch == '\\' && Escaped == FALSE) {
            Escaped = TRUE;
        }
        else {
            Escaped = FALSE;
        }

        Cursor->Current++;
    }

    Buffer[Written] = '\0';

    if (Cursor->Current >= Cursor->End || *Cursor->Current != DRG_JSON_QUOTE) {
        return FALSE;
    }

    Cursor->Current++;
    return TRUE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 跳过任意一个 JSON 值（字符串 / 数组 / 对象 / 原子值）。
--*/
VOID
DragonJsonSkipValue(
    _In_ PDRG_JSON_CURSOR Cursor
    )
{
    CHAR Open;
    CHAR Close;
    CHAR Ch;
    LONG Depth;
    BOOLEAN InString;
    BOOLEAN Escaped;
    CHAR Tmp[4];

    if (Cursor == NULL || Cursor->Current == NULL || Cursor->End == NULL) {
        return;
    }

    DragonJsonSkipSpace(Cursor);

    if (Cursor->Current >= Cursor->End) {
        return;
    }

    Ch = *Cursor->Current;

    if (Ch == DRG_JSON_QUOTE) {
        /* 只为消费游标，缓冲刻意设得很小 */
        (VOID)DragonJsonReadRawString(Cursor, Tmp, RTL_NUMBER_OF(Tmp));
        return;
    }

    if (Ch == '[' || Ch == '{') {
        Open = Ch;
        Close = (Ch == '[') ? ']' : '}';
        Depth = 0;
        InString = FALSE;
        Escaped = FALSE;

        while (Cursor->Current < Cursor->End) {
            Ch = *Cursor->Current;

            if (InString == TRUE) {
                if (Ch == DRG_JSON_QUOTE && Escaped == FALSE) {
                    InString = FALSE;
                }
                if (Ch == '\\' && Escaped == FALSE) {
                    Escaped = TRUE;
                }
                else {
                    Escaped = FALSE;
                }
                Cursor->Current++;
                continue;
            }

            if (Ch == DRG_JSON_QUOTE) {
                InString = TRUE;
            }
            else if (Ch == Open) {
                Depth++;
            }
            else if (Ch == Close) {
                Depth--;
                Cursor->Current++;
                if (Depth == 0) {
                    return;
                }
                continue;
            }

            Cursor->Current++;
        }

        return;
    }

    /* 原子值：推进到分隔符 */
    while (Cursor->Current < Cursor->End) {
        Ch = *Cursor->Current;
        if (Ch == ',' || Ch == '}' || Ch == ']') {
            break;
        }
        Cursor->Current++;
    }
}

/*++
@IRQL: <= APC_LEVEL
@brief 在当前游标之后查找 "Key" 且其后紧跟冒号；命中后游标停在冒号之后。

@note  这是「扁平查找」，不做层级感知，仅用于定位顶层数组名。
--*/
BOOLEAN
DragonJsonSeekKey(
    _In_ PDRG_JSON_CURSOR Cursor,
    _In_ PCSTR Key
    )
{
    SIZE_T KeyChars;
    PCSTR Probe;

    if (Cursor == NULL || Cursor->Current == NULL || Cursor->End == NULL || Key == NULL) {
        return FALSE;
    }

    KeyChars = 0;
    while (Key[KeyChars] != '\0') {
        KeyChars++;
    }

    if (KeyChars == 0) {
        return FALSE;
    }

    Probe = Cursor->Current;
    while ((Probe + KeyChars) <= Cursor->End) {
        if (RtlCompareMemory(Probe, Key, KeyChars) == KeyChars) {
            Cursor->Current = Probe + KeyChars;
            DragonJsonSkipSpace(Cursor);
            if (DragonJsonPeek(Cursor) == DRG_JSON_COLON) {
                Cursor->Current++;
                DragonJsonSkipSpace(Cursor);
                return TRUE;
            }
            /* 命中但不是键：继续向后找 */
            Probe = Probe + KeyChars;
            Cursor->Current = Probe;
            continue;
        }
        Probe++;
    }

    Cursor->Current = Cursor->End;
    return FALSE;
}

/*++
@IRQL: <= APC_LEVEL
@brief 就地处理 JSON 转义（\\ \" \/ \n \r \t 以及 \"\uXXXX\" 之外的普通转义）。

@param  Chars  Buffer 中有效字符数
@return 处理后的有效字节数
--*/
ULONG
DragonJsonUnescape(
    _Inout_updates_(Chars) PWCHAR Buffer,
    _In_ ULONG Chars
    )
{
    ULONG ReadIndex;
    ULONG WriteIndex;
    WCHAR Next;

    if (Buffer == NULL || Chars == 0) {
        return 0;
    }

    ReadIndex = 0;
    WriteIndex = 0;

    while (ReadIndex < Chars) {
        if (Buffer[ReadIndex] == L'\\' && (ReadIndex + 1) < Chars) {
            Next = Buffer[ReadIndex + 1];

            if (Next == L'\\' || Next == L'"' || Next == L'/') {
                Buffer[WriteIndex] = Next;
                WriteIndex++;
                ReadIndex += 2;
                continue;
            }

            if (Next == L'n') {
                Buffer[WriteIndex] = L'\n';
                WriteIndex++;
                ReadIndex += 2;
                continue;
            }

            if (Next == L'r') {
                Buffer[WriteIndex] = L'\r';
                WriteIndex++;
                ReadIndex += 2;
                continue;
            }

            if (Next == L't') {
                Buffer[WriteIndex] = L'\t';
                WriteIndex++;
                ReadIndex += 2;
                continue;
            }

            /* 未知转义：保留反斜杠，交由后续逻辑原样处理 */
            Buffer[WriteIndex] = Buffer[ReadIndex];
            WriteIndex++;
            ReadIndex++;
            continue;
        }

        Buffer[WriteIndex] = Buffer[ReadIndex];
        WriteIndex++;
        ReadIndex++;
    }

    Buffer[WriteIndex] = L'\0';
    return WriteIndex * sizeof(WCHAR);
}
