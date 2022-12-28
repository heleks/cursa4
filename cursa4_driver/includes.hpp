#ifndef includes_hpp
#define includes_hpp

#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>
#include <stdint.h>

constexpr auto SystemModuleInformation = 11;
extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation( ULONG, PVOID, ULONG, PULONG );
extern "C" NTSYSAPI LPSTR NTAPI PsGetProcessImageFileName( PEPROCESS );
extern "C" NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName( PVOID, PCCH );

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

#include "debug/log.hpp"
#include "utils/kernel_offsets.hpp"
#include "utils/utils.hpp"

#endif