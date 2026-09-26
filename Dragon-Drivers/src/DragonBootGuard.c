/*++
===============================================================================
 Dragon-Drivers / DragonBootGuard.c

 启动引导区 / 裸磁盘防护。

 拦截点：minifilter 的 IRP_MJ_DEVICE_CONTROL 前回调。
 关注的控制码（均属「整盘改写 / 绕过文件系统直写」风险面）：
   IOCTL_DISK_SET_DRIVE_LAYOUT_EX   —— 重写磁盘分区表
   IOCTL_SCSI_PASS_THROUGH_DIRECT   —— 直接下发 SCSI 命令
   IOCTL_DISK_FORMAT_TRACKS         —— 格式化磁道
   IOCTL_DISK_FORMAT_TRACKS_EX      —— 格式化磁道（扩展）

 命中后上报固定标识 Disk_Wiper_Attempt，并按规则的 Action 语义处置（上报 / 终止）。
===============================================================================
--*/

#include "DragonCommon.h"
#include <ntdddisk.h>
#include <ntddscsi.h>

/* 部分 WDK 版本未导出格式化磁道控制码，按官方 ntdddisk.h 定义补全 */
#ifndef IOCTL_DISK_FORMAT_TRACKS
#define IOCTL_DISK_FORMAT_TRACKS \
    CTL_CODE(IOCTL_DISK_BASE, 0x0006, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_DISK_FORMAT_TRACKS_EX
#define IOCTL_DISK_FORMAT_TRACKS_EX \
    CTL_CODE(IOCTL_DISK_BASE, 0x000b, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

/*++
@IRQL: <= APC_LEVEL
@brief 判断控制码是否属于受关注的磁盘改写类操作。
--*/
static
BOOLEAN
DragonIsGuardedDiskControl(
    _In_ ULONG IoControlCode
    )
{
    if (IoControlCode == IOCTL_DISK_SET_DRIVE_LAYOUT_EX) {
        return TRUE;
    }

    if (IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
        return TRUE;
    }

    if (IoControlCode == IOCTL_DISK_FORMAT_TRACKS) {
        return TRUE;
    }

    if (IoControlCode == IOCTL_DISK_FORMAT_TRACKS_EX) {
        return TRUE;
    }

    return FALSE;
}

/*++
@IRQL: PASSIVE_LEVEL  (Filter Manager 前回调，实际上限 APC_LEVEL)
@brief IRP_MJ_DEVICE_CONTROL 前回调：拦截磁盘擦写类控制码。
--*/
FLT_PREOP_CALLBACK_STATUS
DragonBootPreDeviceControl(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    ULONG IoControlCode;
    HANDLE ProcessId;
    ULONG RuleCode;
    ULONG Action;

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

    IoControlCode = Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;

    if (DragonIsGuardedDiskControl(IoControlCode) == FALSE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ProcessId = PsGetCurrentProcessId();
    RuleCode = 0;
    Action = DRG_ACTION_REPORT;

    DragonMetricsBump(DrgMetricDeviceIoctl, 1);

    if (DragonEvaluateDevice(ProcessId, &RuleCode, &Action) == TRUE) {

        DragonQueueViolation(
            RuleCode,
            Action,
            ProcessId,
            DRG_MSG_DISK_WIPER,
            (USHORT)(DragonWideLength(DRG_MSG_DISK_WIPER) * sizeof(WCHAR)));

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
