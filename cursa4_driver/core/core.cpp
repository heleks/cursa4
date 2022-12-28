#include "../includes.hpp"

NTSTATUS driver_entry_point( uint64_t, uint64_t ) {
	if ( !kernel_offsets::initialize( ) )
		return STATUS_FAILED_DRIVER_ENTRY;

	HANDLE winlogon_handle{ utils::get_process_handle( "winlogon.exe" ) }; //get winlogon handle

	if ( !winlogon_handle ) {
		debug_log( "winlogon process not found" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	debug_log( "process handle: %p", winlogon_handle );

	PEPROCESS pe_process;
	NTSTATUS status{ PsLookupProcessByProcessId( winlogon_handle, &pe_process ) }; // get peproccess of winlogon

	if ( !NT_SUCCESS( status ) ) {
		debug_log( "failed to get winlogon peprocess" ); 
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	KeAttachProcess( pe_process ); // attach to winlogon

	uint64_t gpsi{ reinterpret_cast< uint64_t >( utils::get_system_module_export( "win32kbase.sys" , "gpsi" ) ) }; // get gpsi address
	if ( !gpsi ) {
		debug_log( "gpsi not found" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*reinterpret_cast< uint32_t* >( gpsi + 0x874 ) = 0; // spoof boolean

	debug_log( "spoofed successfuly" );

	KeDetachProcess( ); // detach from winlogon

	return STATUS_SUCCESS;
}
