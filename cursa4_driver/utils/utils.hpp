#ifndef utils_hpp
#define utils_hpp

namespace utils {
	uint64_t get_system_module_base( const char* module_name ) {
		ULONG bytes { 0 };

		NTSTATUS status { ZwQuerySystemInformation( SystemModuleInformation , 0 , bytes , &bytes ) };

		if ( !bytes )
			return 0;

		RTL_PROCESS_MODULES* modules { static_cast< RTL_PROCESS_MODULES* >( ExAllocatePool( NonPagedPool , bytes ) ) };

		status = ZwQuerySystemInformation( SystemModuleInformation , modules , bytes , &bytes );

		if ( !NT_SUCCESS( status ) )
			return 0;

		uint64_t module_base{ };

		for ( ULONG i { 0 }; i < modules->NumberOfModules; ++i ) {
			RTL_PROCESS_MODULE_INFORMATION module { modules->Modules[ i ] };

			if ( strstr( reinterpret_cast< char* >( module.FullPathName ) , module_name ) != 0 ) {
				module_base = reinterpret_cast< uint64_t >( modules->Modules[ i ].ImageBase );
				break;
			}
		}

		if ( modules )
			ExFreePoolWithTag( modules , 0 );

		return module_base;
	}

	void* get_system_module_export( const char* module_name, const char* routine_name ) {
		uint64_t lp_module{ get_system_module_base( module_name ) };

		if ( !lp_module )
			return nullptr;

		return RtlFindExportedRoutineByName( reinterpret_cast< void* >( lp_module ), routine_name );
	}

	HANDLE get_process_handle( const char* process_name ) {
		static uint64_t system_process{ *reinterpret_cast< uint64_t* >( &PsInitialSystemProcess ) };

		if ( !system_process )
			return 0;

		uint64_t current_process{ system_process };

		do {
			if ( strstr( reinterpret_cast< char* >( current_process + kernel_offsets::image_file_name_offset ), process_name ) )
				if ( *reinterpret_cast< uint32_t* >( current_process + kernel_offsets::active_threads_offset ) )
					return *reinterpret_cast< HANDLE* >( current_process + kernel_offsets::unique_process_id_offset );

			LIST_ENTRY* list{ reinterpret_cast< LIST_ENTRY* >( current_process + kernel_offsets::active_process_links_offset ) };
			current_process = reinterpret_cast< uint64_t >( list->Flink ) - kernel_offsets::active_process_links_offset;
		} while ( current_process != system_process );

		return 0;
	}
}
 
#endif