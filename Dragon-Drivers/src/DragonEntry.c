/*++
===============================================================================
 Dragon-Drivers / DragonEntry.c

 驱动入口与生命周期。

 装载顺序（每一步失败都会走统一清理，不留半初始化状态）：
   1. 初始化全局结构与同步原语；
   2. WdfDriverCreate             —— KMDF 非 PnP 驱动（不提供 EvtDriverDeviceAdd）；
   3. 创建控制设备对象            —— 非 PnP KMDF 驱动的官方要求，
                                     同时作为工作项对象的父对象；
   4. 创建 WDFWAITLOCK            —— 连接状态簿记（仅 PASSIVE_LEVEL 使用）；
   5. 初始化规则引擎 + 载入规则 + 登记客户端镜像路径；
   6. FltRegisterFilter + 创建通信端口 + 启动过滤；
   7. 注册配置管理器 / 进程 / 对象 / 线程 / 镜像回调。

 卸载顺序与装载严格逆序，且遵循官方对 FilterUnloadCallback 的要求
 （关闭服务端口 -> FltUnregisterFilter -> 全局清理 -> 返回状态）。

 说明：FilterUnloadCallback 是唯一的实际拆卸入口。KMDF 的 EvtDriverUnload
 由框架在驱动对象销毁前调用，此处只做状态收尾——因为 KMDF 与 Filter Manager
 都会在 DRIVER_OBJECT 上设置卸载例程，把真实拆卸集中在 FilterUnloadCallback
 可以避免两者竞态（社区共识做法）。
===============================================================================
--*/

#include "DragonCommon.h"

/*-----------------------------------------------------------------------------
  全局数据
-----------------------------------------------------------------------------*/
DRG_DRIVER_DATA g_Dragon;

/*
 * 控制设备对象的默认安全描述符：仅系统与管理员完全访问。
 * 采用与官方 SDDL_DEVOBJ_SYS_ALL_ADM_ALL 完全一致的 SDDL 内容，
 * 但以本地 const 结构自持，避免额外依赖 wdmsec.lib 中的导出符号。
 */
static const WCHAR g_DragonSddlText[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
static const UNICODE_STRING g_DragonControlDeviceSddl = {
    sizeof(g_DragonSddlText) - sizeof(WCHAR),
    sizeof(g_DragonSddlText),
    (PWCH)g_DragonSddlText
};

/*-----------------------------------------------------------------------------
  前向声明：注册结构需要在函数定义之前引用这些回调
-----------------------------------------------------------------------------*/
static NTSTATUS DragonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static NTSTATUS DragonInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

static VOID DragonInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

static VOID DragonInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

static NTSTATUS DragonFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

/*-----------------------------------------------------------------------------
  Minifilter 回调注册表
-----------------------------------------------------------------------------*/
static const FLT_OPERATION_REGISTRATION g_DragonCallbacks[] = {
    { IRP_MJ_CREATE,              0, DragonFilePreCreate,           NULL, NULL },
    { IRP_MJ_WRITE,               0, DragonFilePreWrite,            NULL, NULL },
    { IRP_MJ_SET_INFORMATION,     0, DragonFilePreSetInformation,   NULL, NULL },
    { IRP_MJ_SET_SECURITY,        0, DragonFilePreSetSecurity,      NULL, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, DragonFilePreFileSystemControl,NULL, NULL },
    { IRP_MJ_DEVICE_CONTROL,      0, DragonBootPreDeviceControl,    NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

/*-----------------------------------------------------------------------------
  过滤器注册结构
-----------------------------------------------------------------------------*/
static const FLT_REGISTRATION g_DragonFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                              /* Flags */
    NULL,                           /* ContextRegistration */
    g_DragonCallbacks,              /* OperationRegistration */
    DragonFilterUnload,             /* FilterUnloadCallback */
    DragonInstanceSetup,            /* InstanceSetupCallback */
    DragonInstanceQueryTeardown,    /* InstanceQueryTeardownCallback */
    DragonInstanceTeardownStart,    /* InstanceTeardownStartCallback */
    DragonInstanceTeardownComplete, /* InstanceTeardownCompleteCallback */
    NULL,                           /* GenerateFileNameCallback */
    NULL,                           /* NormalizeNameComponentCallback */
    NULL,                           /* NormalizeContextCleanupCallback */
    NULL,                           /* TransactionNotificationCallback */
    NULL,                           /* NormalizeNameComponentExCallback */
    NULL                            /* SectionNotificationCallback */
};

/*=============================================================================
  Instance 回调
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 卷实例建立：对所有卷一视同仁地挂载。
--*/
static
NTSTATUS
DragonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 手工解绑请求一律允许。
--*/
static
NTSTATUS
DragonInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 实例开始拆除。
--*/
static
VOID
DragonInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 实例拆除完成。
--*/
static
VOID
DragonInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

/*=============================================================================
  控制设备对象
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 创建 KMDF 控制设备对象。

        非 PnP KMDF 驱动官方要求创建「仅代表控制设备的框架设备对象」；
        本驱动不对外命名该设备、不注册任何 I/O 队列——它只承担两个职责：
          · 满足 KMDF 对非 PnP 驱动的结构要求；
          · 作为 WDFWORKITEM 的父对象（工作项的父必须是设备对象或其祖先）。

        安全描述符取「系统 + 管理员」上限，纵深防御。
--*/
static
NTSTATUS
DragonControlDeviceCreate(
    VOID
    )
{
    NTSTATUS Status;
    PWDFDEVICE_INIT DeviceInit;
    WDFDEVICE Device;

    DeviceInit = WdfControlDeviceInitAllocate(g_Dragon.WdfDriver, &g_DragonControlDeviceSddl);
    if (DeviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &Device);
    if (!NT_SUCCESS(Status)) {
        /*
         * WdfDeviceCreate 失败时由框架回收 WDFDEVICE_INIT，
         * 这里不再调用 WdfDeviceInitFree，避免重复释放。
         */
        return Status;
    }

    g_Dragon.ControlDevice = Device;
    return STATUS_SUCCESS;
}

/*=============================================================================
  生命周期
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 判断是否需要真正执行卸载（含状态机推进与等待收敛）。

@return STATUS_SUCCESS 表示调用方可以继续拆卸；其他值应直接返回给 Filter Manager。
--*/
NTSTATUS
DragonBeginTeardown(
    _In_ BOOLEAN Mandatory
    )
{
    LONG State;
    LARGE_INTEGER Timeout;
    PLARGE_INTEGER TimeoutPointer;
    NTSTATUS WaitStatus;

    for (;;) {

        State = DragonStateGet();

        if (State == (LONG)DrgStateStopped) {
            return STATUS_SUCCESS;
        }

        if (State == (LONG)DrgStateStopping) {

            TimeoutPointer = NULL;
            if (Mandatory == FALSE) {
                Timeout.QuadPart = -(LONGLONG)(2LL * 10 * 1000 * 1000); /* 2 秒 */
                TimeoutPointer = &Timeout;
            }

            WaitStatus = KeWaitForSingleObject(
                             &g_Dragon.ShutdownEvent,
                             Executive,
                             KernelMode,
                             FALSE,
                             TimeoutPointer);

            if (Mandatory == FALSE && WaitStatus == STATUS_TIMEOUT) {
                return STATUS_DEVICE_BUSY;
            }

            if (!NT_SUCCESS(WaitStatus)) {
                return WaitStatus;
            }

            continue;
        }

        if (State != (LONG)DrgStateRunning && State != (LONG)DrgStateRetry) {
            return STATUS_DEVICE_NOT_READY;
        }

        if (Mandatory == FALSE &&
            InterlockedCompareExchange(&g_Dragon.UnloadAuthorized, 0, 1) != 1) {
            /* 未获用户态授权：按官方推荐状态码拒绝卸载 */
            return STATUS_FLT_DO_NOT_DETACH;
        }

        if (Mandatory == TRUE) {
            InterlockedExchange(&g_Dragon.UnloadAuthorized, 0);
        }

        if (InterlockedCompareExchange(&g_Dragon.DriverState, (LONG)DrgStateStopping, State) != State) {
            if (Mandatory == FALSE) {
                return STATUS_DEVICE_BUSY;
            }
            continue;
        }

        KeClearEvent(&g_Dragon.ShutdownEvent);
        return STATUS_SUCCESS;
    }
}

/*++
@IRQL: PASSIVE_LEVEL
@brief 全面拆卸：注销所有内核回调、关闭通信端口、反注册过滤器、释放规则与框架对象。

        必须遵守「先注销回调，再释放被回调引用的数据」的顺序，
        否则会出现「回调仍在执行而数据已释放」的 Use-After-Free。
--*/
NTSTATUS
DragonFullCleanup(
    _In_ BOOLEAN MandatoryUnload
    )
{
    UNREFERENCED_PARAMETER(MandatoryUnload);

    /* 1. 注销所有会发起作业的内核回调 */
    DragonObjectGuardStop();
    DragonRegistryGuardStop();
    DragonProcessGuardStop();

    /* 2. 关闭通信端口（停止接受连接、关闭客户端端口、等待回调收敛） */
    DragonCommsClose();

    /* 3. 反注册过滤器（框架会等待在途回调结束） */
    if (g_Dragon.FilterHandle != NULL) {
        FltUnregisterFilter(g_Dragon.FilterHandle);
        g_Dragon.FilterHandle = NULL;
    }

    /* 4. 停止排空工作项并丢弃残余作业 */
    DragonResponseTeardown();

    /* 5. 释放规则数据库、勒索防护状态与自保护路径表 */
    DragonRansomTeardown();
    DragonRulesTeardown();
    DragonSelfProtectTeardown();

    /* 6. 销毁控制设备对象（其子对象 —— 等待锁 —— 由框架级联回收） */
    if (g_Dragon.ControlDevice != NULL) {
        WdfObjectDelete(g_Dragon.ControlDevice);
        g_Dragon.ControlDevice = NULL;
    }

    g_Dragon.ConnectionLock = NULL;
    g_Dragon.Initialized = FALSE;

    return STATUS_SUCCESS;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief FilterUnloadCallback：唯一实际拆卸入口。
--*/
static
NTSTATUS
DragonFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    BOOLEAN Mandatory;
    NTSTATUS Status;

    Mandatory = (FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY)) ? TRUE : FALSE;

    Status = DragonBeginTeardown(Mandatory);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (DragonStateGet() == (LONG)DrgStateStopped) {
        return STATUS_SUCCESS;
    }

    Status = DragonFullCleanup(Mandatory);

    DragonStateSet(NT_SUCCESS(Status) ? (LONG)DrgStateStopped : (LONG)DrgStateRetry);
    KeSetEvent(&g_Dragon.ShutdownEvent, IO_NO_INCREMENT, FALSE);

    return Status;
}

/*++
@IRQL: PASSIVE_LEVEL
@brief KMDF 驱动卸载回调。

        实际拆卸已在 FilterUnloadCallback 中完成；这里只做状态收尾与诊断输出，
        因为框架会在本回调返回后销毁驱动对象及其全部子对象。
--*/
static
VOID
DragonEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    DragonStateSet((LONG)DrgStateStopped);
    KeSetEvent(&g_Dragon.ShutdownEvent, IO_NO_INCREMENT, FALSE);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "Dragon-Drivers: unloaded, reported=%I64d dropped=%I64d\n",
        (LONGLONG)InterlockedCompareExchange64(&g_Dragon.EventsReported, 0, 0),
        (LONGLONG)InterlockedCompareExchange64(&g_Dragon.EventsDropped, 0, 0));
}

/*=============================================================================
  驱动入口
=============================================================================*/

/*++
@IRQL: PASSIVE_LEVEL
@brief 驱动入口。
--*/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    WDF_DRIVER_CONFIG DriverConfig;
    WDF_OBJECT_ATTRIBUTES LockAttributes;

    RtlZeroMemory(&g_Dragon, sizeof(g_Dragon));

    g_Dragon.DriverObject = DriverObject;
    g_Dragon.ClientImagePath.Buffer = g_Dragon.ClientImageBuffer;
    g_Dragon.ClientImagePath.Length = 0;
    g_Dragon.ClientImagePath.MaximumLength = (USHORT)sizeof(g_Dragon.ClientImageBuffer);

    KeInitializeSpinLock(&g_Dragon.JobLock);
    InitializeListHead(&g_Dragon.JobQueue);
    ExInitializeRundownProtection(&g_Dragon.PortRundown);
    KeInitializeEvent(&g_Dragon.ShutdownEvent, NotificationEvent, FALSE);

    InterlockedExchange(&g_Dragon.DriverState, (LONG)DrgStateStarting);
    InterlockedExchange(&g_Dragon.PortAccepting, 0);
    InterlockedExchange(&g_Dragon.ClientPid, 0);
    InterlockedExchange(&g_Dragon.UnloadAuthorized, 0);
    InterlockedExchange(&g_Dragon.Shutdown, 0);
    InterlockedExchange64(&g_Dragon.EventsReported, 0);
    InterlockedExchange64(&g_Dragon.EventsDropped, 0);

    /* --- 1. 建立 KMDF 驱动对象（非 PnP，不提供 EvtDriverDeviceAdd） --- */
    WDF_DRIVER_CONFIG_INIT(&DriverConfig, WDF_NO_EVENT_CALLBACK);
    DriverConfig.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    DriverConfig.EvtDriverUnload = DragonEvtDriverUnload;
    DriverConfig.DriverPoolTag = DRG_POOL_TAG;

    Status = WdfDriverCreate(
                 DriverObject,
                 RegistryPath,
                 WDF_NO_OBJECT_ATTRIBUTES,
                 &DriverConfig,
                 &g_Dragon.WdfDriver);
    if (!NT_SUCCESS(Status)) {
        g_Dragon.WdfDriver = NULL;
        goto Failure;
    }

    /* --- 2. 控制设备对象（非 PnP 驱动要求 + 工作项父对象） --- */
    Status = DragonControlDeviceCreate();
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    /* --- 3. 连接状态自旋锁（父对象为控制设备，保证随其回收） ---
     *  使用 WDFSPINLOCK 而非 WDFWAITLOCK：Filter Manager 的连接/断开回调
     *  并没有 PASSIVE_LEVEL 的官方保证，而 WdfWaitLockAcquire 只允许 PASSIVE，
     *  一旦在合法的高 IRQL 上误用会直接触发 KMDF 断言（蓝屏）。
     *  临界区内只做指针/PID 交换，满足自旋锁的使用约束。
     */
    WDF_OBJECT_ATTRIBUTES_INIT(&LockAttributes);
    LockAttributes.ParentObject = g_Dragon.ControlDevice;

    Status = WdfSpinLockCreate(&LockAttributes, &g_Dragon.ConnectionLock);
    if (!NT_SUCCESS(Status)) {
        g_Dragon.ConnectionLock = NULL;
        goto Failure;
    }

    /* --- 4. 规则引擎 --- */
    Status = DragonRulesInitialize();
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    /*
     * 规则文件与客户端身份的处理策略（与参考实现的两点差异，均已在交付说明标注）：
     *
     *  a) 规则文件缺失 —— 采用「非致命」：记录诊断后继续加载。
     *     理由：规则既可由驱动在启动时从镜像目录读取，也可由用户态客户端
     *     通过通信端口下发；若强制要求磁盘规则文件存在，会让驱动在未部署
     *     规则包的机器上完全无法启动，反而降低可维护性。
     *
     *  b) 客户端镜像路径未配置 —— 同样「非致命」：驱动照常启动并继续在
     *     内核侧执行规则，但通信端口会拒绝一切连接（DragonIsAuthorizedClient
     *     在 ClientImagePath 为空时直接返回 FALSE）。这样既不会让驱动因为
     *     部署顺序问题启动失败，也不会出现「未配置即开放端口」的安全缺口。
     */
    Status = DragonRulesLoadFromDisk(RegistryPath);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: rule file not loaded (0x%08X), running with in-memory rules only\n",
            Status);
    }

    Status = DragonClientIdentityLoad(RegistryPath);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: ClientImagePath unavailable (0x%08X), communication port will reject all clients\n",
            Status);
    }

    /*
     * 内置自保护：受保护路径从服务键 ImagePath 推导。
     *
     * 失败同样采用「非致命」策略 —— 拿不到自身路径等于自保护失效，但驱动
     * 仍然可以正常做规则防护；若在这里硬失败，反而会让整机失去防护。
     * 该降级会以 WARNING 级别打印，便于在 DebugView 中及时发现。
     */
    Status = DragonSelfProtectInitialize(RegistryPath);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: self-protection disabled, cannot resolve own image path (0x%08X)\n",
            Status);
    }

    /*
     * 诊断统计与勒索防护。
     *
     * 两者都必须在「注册任何内核回调」之前就绪：
     *   · 统计模块要先于第一个回调，否则驱动启动瞬间的计数会丢失；
     *   · 勒索模块要先建好备份目录，否则启动瞬间的写操作会全部跳过备份
     *     （目录不存在时备份直接失败但评分照常，不会拖垮驱动）。
     * 失败一律非致命 —— 少一层能力，也好过驱动整个起不来。
     */
    DragonMetricsInitialize();

    Status = DragonRansomInitialize(RegistryPath);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "Dragon-Drivers: ransom protection disabled (0x%08X)\n",
            Status);
    }

    /* --- 5. 作业队列 / 排空工作项（必须先于任何回调注册） --- */
    Status = DragonResponseInitialize(g_Dragon.WdfDriver);
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    /* --- 6. 注册过滤器并创建通信端口 --- */
    Status = FltRegisterFilter(DriverObject, &g_DragonFilterRegistration, &g_Dragon.FilterHandle);
    if (!NT_SUCCESS(Status)) {
        g_Dragon.FilterHandle = NULL;
        goto Failure;
    }

    Status = DragonCommsCreate(DriverObject);
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    /* --- 7. 注册内核回调 --- */
    Status = DragonRegistryGuardStart(DriverObject);
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    Status = DragonProcessGuardStart();
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    Status = DragonObjectGuardStart();
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    /* --- 8. 启动过滤 --- */
    Status = FltStartFiltering(g_Dragon.FilterHandle);
    if (!NT_SUCCESS(Status)) {
        goto Failure;
    }

    g_Dragon.Initialized = TRUE;
    DragonStateSet((LONG)DrgStateRunning);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "Dragon-Drivers: loaded, filter=%p port=%p\n",
        g_Dragon.FilterHandle,
        g_Dragon.ServerPort);

    return STATUS_SUCCESS;

Failure:
    (VOID)DragonFullCleanup(TRUE);

    DragonStateSet((LONG)DrgStateStopped);
    KeSetEvent(&g_Dragon.ShutdownEvent, IO_NO_INCREMENT, FALSE);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "Dragon-Drivers: DriverEntry failed 0x%08X\n",
        Status);

    return Status;
}
