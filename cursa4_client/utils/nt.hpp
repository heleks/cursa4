#ifndef nt_hpp
#define nt_hpp

namespace nt {
	constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
	constexpr auto STATUS_IMAGE_ALREADY_LOADED = 0xC000010E;

	constexpr auto SystemModuleInformation = 11;

	typedef NTSTATUS( *NtLoadDriver )( PUNICODE_STRING );
	typedef NTSTATUS( *NtUnloadDriver )( PUNICODE_STRING );
	typedef NTSTATUS( *RtlAdjustPrivilege )( ULONG, BOOLEAN, BOOLEAN, PBOOLEAN );

	typedef enum class _POOL_TYPE {
		NonPagedPool
	} POOL_TYPE;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[ 256 ];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
}

#endif