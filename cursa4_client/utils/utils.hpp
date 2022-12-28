#ifndef utils_hpp
#define utils_hpp

namespace utils {
	std::string get_temp_path( ) {
		char temp_directory[ MAX_PATH + 1 ]{ };
		if ( !GetTempPathA( sizeof temp_directory, temp_directory ) )
			return "";
	
		if ( temp_directory[ strlen( temp_directory ) - 1 ] == L'\\' )
			temp_directory[ strlen( temp_directory ) - 1 ] = 0;

		return temp_directory;
	}

	bool create_file_from_memory( const std::string file_path, const char* binary_file, const size_t size ) {
		std::ofstream file( file_path.c_str( ), std::ios_base::out | std::ios_base::binary );
		if ( !file.write( binary_file, size ) ) {
			file.close( );
			return false;
		}

		file.close( );
		return true;
	}

	bool read_file_from_memory( const std::string file_path, std::vector< uint8_t >* out_buffer ) {
		std::ifstream file_ifstream( file_path, std::ios::binary );

		if ( !file_ifstream )
			return false;

		out_buffer->assign( ( std::istreambuf_iterator< char >( file_ifstream ) ), std::istreambuf_iterator< char >( ) );
		file_ifstream.close( );

		return true;
	}

	uint64_t get_kernel_module_address( const std::string module_name ) {
		void* buffer{ nullptr };
		DWORD buffer_size{ 0 };

		NTSTATUS status{ NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( nt::SystemModuleInformation ), buffer, buffer_size, &buffer_size ) };

		while ( status == nt::STATUS_INFO_LENGTH_MISMATCH ) {
			if ( buffer != nullptr )
				VirtualFree( buffer, 0, MEM_RELEASE );

			buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
			status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( nt::SystemModuleInformation ), buffer, buffer_size, &buffer_size );
		}

		if ( !NT_SUCCESS( status ) ) {
			if ( buffer != nullptr )
				VirtualFree( buffer, 0, MEM_RELEASE );

			return 0;
		}

		nt::RTL_PROCESS_MODULES* modules{ static_cast< nt::RTL_PROCESS_MODULES* >( buffer ) };
		if ( !modules )
			return 0;

		for ( uint32_t i{ 0 }; i < modules->NumberOfModules; ++i ) {
			std::string current_module_name{ std::string( reinterpret_cast< char* >( modules->Modules[ i ].FullPathName ) + modules->Modules[ i ].OffsetToFileName ) };

			if ( !_stricmp( current_module_name.c_str( ), module_name.c_str( ) ) ) {
				uint64_t result{ reinterpret_cast< uint64_t >( modules->Modules[ i ].ImageBase ) };

				VirtualFree( buffer, 0, MEM_RELEASE );
				return result;
			}
		}

		VirtualFree( buffer, 0, MEM_RELEASE );
		return 0;
	}
}

#endif