#include <ntddk.h>


// 自定义设备扩展结构
typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	// 设备名称
	UNICODE_STRING ustrSymLinkName;	// 符号连接名
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;



typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,                // 0 Y N
	SystemProcessorInformation,            // 1 Y N
	SystemPerformanceInformation,        // 2 Y N
	SystemTimeOfDayInformation,            // 3 Y N
	SystemNotImplemented1,                // 4 Y N
	SystemProcessesAndThreadsInformation, // 5 Y N
	SystemCallCounts,                    // 6 Y N
	SystemConfigurationInformation,        // 7 Y N
	SystemProcessorTimes,                // 8 Y N
	SystemGlobalFlag,                    // 9 Y Y
	SystemNotImplemented2,                // 10 Y N
	SystemModuleInformation,            // 11 Y N
	SystemLockInformation,                // 12 Y N
	SystemNotImplemented3,                // 13 Y N
	SystemNotImplemented4,                // 14 Y N
	SystemNotImplemented5,                // 15 Y N
	SystemHandleInformation,            // 16 Y N
	SystemObjectInformation,            // 17 Y N
	SystemPagefileInformation,            // 18 Y N
	SystemInstructionEmulationCounts,    // 19 Y N
	SystemInvalidInfoClass1,            // 20
	SystemCacheInformation,                // 21 Y Y
	SystemPoolTagInformation,            // 22 Y N
	SystemProcessorStatistics,            // 23 Y N
	SystemDpcInformation,                // 24 Y Y
	SystemNotImplemented6,                // 25 Y N
	SystemLoadImage,                    // 26 N Y
	SystemUnloadImage,                    // 27 N Y
	SystemTimeAdjustment,                // 28 Y Y
	SystemNotImplemented7,                // 29 Y N
	SystemNotImplemented8,                // 30 Y N
	SystemNotImplemented9,                // 31 Y N
	SystemCrashDumpInformation,            // 32 Y N
	SystemExceptionInformation,            // 33 Y N
	SystemCrashDumpStateInformation,    // 34 Y Y/N
	SystemKernelDebuggerInformation,    // 35 Y N
	SystemContextSwitchInformation,        // 36 Y N
	SystemRegistryQuotaInformation,        // 37 Y Y
	SystemLoadAndCallImage,                // 38 N Y
	SystemPrioritySeparation,            // 39 N Y
	SystemNotImplemented10,                // 40 Y N
	SystemNotImplemented11,                // 41 Y N
	SystemInvalidInfoClass2,            // 42
	SystemInvalidInfoClass3,            // 43
	SystemTimeZoneInformation,            // 44 Y N
	SystemLookasideInformation,            // 45 Y N
	SystemSetTimeSlipEvent,                // 46 N Y
	SystemCreateSession,                // 47 N Y
	SystemDeleteSession,                // 48 N Y
	SystemInvalidInfoClass4,            // 49
	SystemRangeStartInformation,        // 50 Y N
	SystemVerifierInformation,            // 51 Y Y
	SystemAddVerifier,                    // 52 N Y
	SystemSessionProcessesInformation    // 53 Y N
} SYSTEM_INFORMATION_CLASS;


//////////////////////////////////////////////////////////////////////////
// Hook ZwQuerySystemInformation
extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);
typedef NTSTATUS (* NTQUERYSYSTEMINFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);
//////////////////////////////////////////////////////////////////////////
// Hook ZwSetValueKey
extern "C" NTSYSAPI NTSTATUS NTAPI ZwSetValueKey (
	IN HANDLE  KeyHandle,
	IN PUNICODE_STRING  ValueName, //要新建或者修改的键名
	IN ULONG  TitleIndex  OPTIONAL, //一般设为0
	IN ULONG  Type,  //键值类型，上表中的一个
	IN PVOID  Data, //数据
	IN ULONG  DataSize //记录键值数据大小
	);
typedef NTSTATUS (*NTSETVALUEKEY)(
	IN HANDLE  KeyHandle,
	IN PUNICODE_STRING  ValueName, //要新建或者修改的键名
	IN ULONG  TitleIndex  OPTIONAL, //一般设为0
	IN ULONG  Type,  //键值类型，上表中的一个
	IN PVOID  Data, //数据
	IN ULONG  DataSize //记录键值数据大小
	);
//////////////////////////////////////////////////////////////////////////
// Hook ZwCreateKey
extern "C" NTSYSAPI NTSTATUS NTAPI ZwCreateKey(
	OUT PHANDLE  KeyHandle,
	IN ACCESS_MASK  DesiredAccess, //访问权限，一般为KEY_ALL_ACCLESS
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN ULONG  TitleIndex, //一般为NULL
	IN PUNICODE_STRING  Class  OPTIONAL, //一般为NULL
	IN ULONG  CreateOptions, //一般为REG_OPTION_NON_VOLATILE
	OUT PULONG  Disposition  OPTIONAL //返回是打开成功还是创建成功
	);
typedef NTSTATUS (*NTCREATEKEY)(	
	OUT PHANDLE  KeyHandle,
	IN ACCESS_MASK  DesiredAccess, //访问权限，一般为KEY_ALL_ACCLESS
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN ULONG  TitleIndex, //一般为NULL
	IN PUNICODE_STRING  Class  OPTIONAL, //一般为NULL
	IN ULONG  CreateOptions, //一般为REG_OPTION_NON_VOLATILE
	OUT PULONG  Disposition  OPTIONAL //返回是打开成功还是创建成功
	);
//////////////////////////////////////////////////////////////////////////
// Hook ZwOpenKey
extern "C" NTSYSAPI NTSTATUS NTAPI ZwOpenKey(
	OUT PHANDLE  KeyHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes
	);
typedef NTSTATUS (*NTOPENKEY) (
	OUT PHANDLE  KeyHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes
	);
//////////////////////////////////////////////////////////////////////////
// Hook ZwDeleteKey
extern "C" NTSYSAPI NTSTATUS NTAPI ZwDeleteKey(
	IN HANDLE  KeyHandle
	);
typedef NTSTATUS (*NTDELETEKEY) (
	IN HANDLE  KeyHandle
	);
//////////////////////////////////////////////////////////////////////////
// Hook ZwDeleteKeyValue
extern "C" NTSYSAPI NTSTATUS NTAPI ZwDeleteValueKey(
	IN  HANDLE KeyHandle,
	IN  PUNICODE_STRING ValueName
	);
typedef NTSTATUS (*NTDELETEVALUEKEY) (
	IN  HANDLE KeyHandle,
	IN  PUNICODE_STRING ValueName
	);
//////////////////////////////////////////////////////////////////////////

typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG  NumberOfService;
	ULONG  ParamTableBase;
}KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE ntoskrnl;
	KSYSTEM_SERVICE_TABLE win32k;
	KSYSTEM_SERVICE_TABLE notUsed1;
	KSYSTEM_SERVICE_TABLE notUsed2;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

extern "C" PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
NTSTATUS DeviceIoControlDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp);



#define MAX_SYSTEM_SERVICE_NUMBER 1024
ULONG oldSysServiceAddr[MAX_SYSTEM_SERVICE_NUMBER];

#define SYSCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))

#define SYSCALL_FUNCTION(ServiceFunction) \
	KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYSCALL_INDEX(ServiceFunction)]

VOID BackupSysServiceTable();
NTSTATUS InstallSysServiceHook(ULONG oldService, ULONG newService);
NTSTATUS UnInstallSysServiceHook(ULONG oldService);
VOID DisableWriteProtect(ULONG oldAddr);
VOID EnableWriteProtect(PULONG pOldAttr);
NTSTATUS HookReadfn(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
//////////////////////////////////////////////////////////////////////////
typedef struct _OBJECT_TYPE_INFORMATION { 
	UNICODE_STRING Name; 
	ULONG ObjectCount; 
	ULONG HandleCount; 
	ULONG Reserved1[4]; 
	ULONG PeakObjectCount; 
	ULONG PeakHandleCount; 
	ULONG Reserved2[4]; 
	ULONG InvalidAttributes; 
	GENERIC_MAPPING GenericMapping; 
	ULONG ValidAccess; 
	UCHAR Unknown; 
	BOOLEAN MaintainHandleDatabase; 
	POOL_TYPE PoolType; 
	ULONG PagedPoolUsage; 
	ULONG NonPagedPoolUsage; 
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION; 

typedef struct _OBJECT_ALL_TYPES_INFORMATION { 
	ULONG NumberOfTypes; 
	OBJECT_TYPE_INFORMATION TypeInformation; 
} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG                   Attributes;
	ACCESS_MASK             DesiredAccess;
	ULONG                   HandleCount;
	ULONG                   ReferenceCount;
	ULONG                   PagedPoolUsage;
	ULONG                   NonPagedPoolUsage;
	ULONG                   Reserved[3];
	ULONG                   NameInformationLength;
	ULONG                   TypeInformationLength;
	ULONG                   SecurityDescriptorLength;
	LARGE_INTEGER           CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION {
	ULONG                   NumberOfObjectsTypes;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

typedef struct _OBJECT_DATA_INFORMATION {
	BOOLEAN                 InheritHandle;
	BOOLEAN                 ProtectFromClose;
} OBJECT_DATA_INFORMATION, *POBJECT_DATA_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

extern "C" NTSTATUS ZwQueryObject( 
	IN HANDLE ObjectHandle, 
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass, 
	OUT PVOID ObjectInformation, 
	IN ULONG ObjectInformationLength, 
	OUT PULONG ReturnLength OPTIONAL 
	); 
//////////////////////////////////////////////////////////////////////////
NTSTATUS HookNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);
NTSTATUS HookZwSetValueKey(
	IN HANDLE			KeyHandle,
	IN PUNICODE_STRING  ValueName, //要新建或者修改的键名
	IN ULONG			TitleIndex  OPTIONAL, //一般设为0
	IN ULONG			Type,  //键值类型，上表中的一个
	IN PVOID			Data, //数据
	IN ULONG			DataSize //记录键值数据大小
	);
NTSTATUS HookZwCreateKey(
	OUT PHANDLE  KeyHandle,
	IN ACCESS_MASK  DesiredAccess, //访问权限，一般为KEY_ALL_ACCLESS
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN ULONG  TitleIndex, //一般为NULL
	IN PUNICODE_STRING  Class  OPTIONAL, //一般为NULL
	IN ULONG  CreateOptions, //一般为REG_OPTION_NON_VOLATILE
	OUT PULONG  Disposition  OPTIONAL //返回是打开成功还是创建成功
	);
NTSTATUS HookZwOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);
NTSTATUS HookZwDeleteKey(
	IN HANDLE  KeyHandle
	);
NTSTATUS HookZwDeleteValueKey(
	IN  HANDLE KeyHandle,
	IN  PUNICODE_STRING ValueName
	);
//////////////////////////////////////////////////////////////////////////、、、

// typedef struct _REGDATA
// {
// 	char ImageFilePath[256];
// 	char Key[256];
// 	char SubKey[256];
// }REGDATA, *PREGDATA;


typedef NTSTATUS (*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);
QUERY_INFO_PROCESS ZwQueryInformationProcess;

#define IOCTL_SETVALUEKEY \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SETEVENT \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GETINFO \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 设置等待用户判断的事件
#define IOCTL_SETWAITEVENT \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 传递用户的判断结果
#define IOCTL_PASSUSERRES \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)


KMUTEX g_setValueKeyMutex;
// 这个事件用于阻塞hook函数调用old函数
PRKEVENT gpEventObject;
POBJECT_HANDLE_INFORMATION objHandleInfo;

// 这个事件用于阻塞用户选择的时候
PRKEVENT gpWaitForUserRequestEvent;
POBJECT_HANDLE_INFORMATION pobjWaitHandleInfo;

// 这个互斥体用于在多个线程之间进行同步
// 因为会有多个进程同时访问注册表
KMUTEX kmutexStockProcess;

char RegData[1024];
char userRes = 0;