#ifndef service_hpp
#define service_hpp

namespace service {
	std::string driver_name = "iqvw64e.sys";

	bool register_service( const std::string driver_path ) {
		DWORD service_type_kernel{ 1 };
		std::string service_path{ "SYSTEM\\CurrentControlSet\\Services\\" + driver_name };
		const std::string path{ "\\??\\" + driver_path };

		HKEY service;
		LSTATUS status{ RegCreateKeyA( HKEY_LOCAL_MACHINE, service_path.c_str( ), &service ) };
		if ( status != ERROR_SUCCESS ) {
			logger::log( logger::log_type_t::error, "failed to create service key" );
			return false;
		}

		status = RegSetKeyValueA( service, NULL, "ImagePath", REG_EXPAND_SZ, path.c_str( ), static_cast< DWORD >( path.size( ) * sizeof uint8_t  ) );
		if ( status != ERROR_SUCCESS ) {
			RegCloseKey( service );
			logger::log( logger::log_type_t::error, "failed to create 'ImagePath' registry value" );
			return false;
		}

		status = RegSetKeyValueA( service, NULL, "Type", REG_DWORD, &service_type_kernel, sizeof DWORD );
		if ( status != ERROR_SUCCESS ) {
			RegCloseKey( service );
			logger::log( logger::log_type_t::error, "failed to create 'Type' registry value" );
			return false;
		}

		RegCloseKey( service );
	}

	bool start_service( ) {
		HMODULE ntdll{ GetModuleHandleA( "ntdll.dll" ) };
		if ( ntdll == NULL )
			return false;

		nt::RtlAdjustPrivilege RtlAdjustPrivilege{ reinterpret_cast< nt::RtlAdjustPrivilege >( GetProcAddress( ntdll, "RtlAdjustPrivilege" ) ) };
		nt::NtLoadDriver NtLoadDriver{ reinterpret_cast< nt::NtLoadDriver >( GetProcAddress( ntdll, "NtLoadDriver" ) ) };

		ULONG se_load_driver_privilege{ 10UL };
		BOOLEAN was_enabled;
		NTSTATUS status{ RtlAdjustPrivilege( se_load_driver_privilege, TRUE, FALSE, &was_enabled ) }; // создаем программе привилегию для загрузки драйвера
		if ( !NT_SUCCESS( status ) ) {
			logger::log( logger::log_type_t::error, "failed to adjust privilege" );
			return false;
		}

		std::string driver_registry_path{ "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name };
		ANSI_STRING ansi_string;
		UNICODE_STRING service_string;
		RtlInitAnsiString( &ansi_string, driver_registry_path.c_str( ) );
		RtlAnsiStringToUnicodeString( &service_string, &ansi_string, TRUE );

		status = NtLoadDriver( &service_string );

		RtlFreeUnicodeString( &service_string );

		logger::log( logger::log_type_t::info, std::format( "driver load status: {:#08x}", static_cast< unsigned >( status ) ) );

		if ( status == nt::STATUS_IMAGE_ALREADY_LOADED )
			return true;

		return NT_SUCCESS( status );
	}

	bool shutdown( ) {
		HMODULE ntdll{ GetModuleHandleA( "ntdll.dll" ) };
		if ( ntdll == NULL )
			return false;

		std::string driver_registry_path{ "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name };
		ANSI_STRING ansi_string;
		UNICODE_STRING service_string;
		RtlInitAnsiString( &ansi_string, driver_registry_path.c_str( ) );
		RtlAnsiStringToUnicodeString( &service_string, &ansi_string, TRUE );

		HKEY driver_service;
		std::string service_path{ "SYSTEM\\CurrentControlSet\\Services\\" + driver_name };
		LSTATUS status{ RegOpenKeyA( HKEY_LOCAL_MACHINE, service_path.c_str( ), &driver_service ) };
		if ( status != ERROR_SUCCESS ) {
			if ( status == ERROR_FILE_NOT_FOUND ) {
				RtlFreeUnicodeString( &service_string );
				return true;
			}

			RtlFreeUnicodeString( &service_string );

			return false;
		}
		RegCloseKey( driver_service );

		nt::NtUnloadDriver NtUnloadDriver{ reinterpret_cast< nt::NtUnloadDriver >( GetProcAddress( ntdll, "NtUnloadDriver" ) ) };
		NTSTATUS unload_status{ NtUnloadDriver( &service_string ) };
		RtlFreeUnicodeString( &service_string );

		logger::log( logger::log_type_t::info, std::format( "driver unload status: {:#08x}", static_cast< unsigned >( unload_status ) ) );

		if ( unload_status != 0x0 ) {
			logger::log( logger::log_type_t::error, "failed to unload driver" );
			status = RegDeleteKeyA( HKEY_LOCAL_MACHINE, service_path.c_str( ) );
			return false;
		}

		status = RegDeleteKeyA( HKEY_LOCAL_MACHINE, service_path.c_str( ) );
		if ( status != ERROR_SUCCESS )
			return false;
		
		return true;
	}
}

#endif