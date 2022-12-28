#include "../includes.hpp"

NTSTATUS driver_entry_point( uint64_t, uint64_t ) {
	if ( !kernel_offsets::initialize( ) )
		return STATUS_FAILED_DRIVER_ENTRY;

	HANDLE win_logon_handle{ utils::get_process_handle( "csrss.exe" ) };

	if ( !win_logon_handle ) {
		debug_log( "winlogon process not found" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	debug_log( "process handle: %p", win_logon_handle );

	PEPROCESS pe_process;
	NTSTATUS status{ PsLookupProcessByProcessId( win_logon_handle, &pe_process ) };

	if ( !NT_SUCCESS( status ) ) {
		debug_log( "failed to get winlogon peprocess" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	KeAttachProcess( pe_process );

	uint64_t gpsi{ reinterpret_cast< uint64_t >( utils::get_system_module_export( "win32kbase.sys" , "gpsi" ) ) };
	if ( !gpsi ) {
		debug_log( "gpsi not found" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*reinterpret_cast< uint32_t* >( gpsi + 0x874 ) = 0;

	debug_log( "spoofed successfuly" );

	KeDetachProcess( );

	return STATUS_SUCCESS;
}
