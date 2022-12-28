#ifndef mapper_hpp
#define mapper_hpp

namespace mapper {

	void relocate_image_by_delta( portable_executable::vec_relocs relocations, const uint64_t delta ) {
		for ( const auto& current_reloc : relocations ) {
			for ( auto i{ 0 }; i < current_reloc.count; ++i ) {
				uint16_t type = current_reloc.item[ i ] >> 12;
				uint16_t offset = current_reloc.item[ i ] & 0xFFF;

				if ( type == IMAGE_REL_BASED_DIR64 )
					*reinterpret_cast< uint64_t* >( current_reloc.address + offset ) += delta;
			}
		}
	}

	bool resolve_imports( HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports ) { // todo
		for ( const auto& current_import : imports ) {
			ULONG64 module{ utils::get_kernel_module_address( current_import.module_name ) };
			if ( !module ) {
				logger::log( logger::log_type_t::error, std::format( "dependency {} wasn't found", current_import.module_name ) );
	
				return false;
			}

			for ( auto& current_function_data : current_import.function_datas ) {
				uint64_t function_address{ intel_driver::get_kernel_module_export( iqvw64e_device_handle, module, current_function_data.name ) };

				if ( !function_address ) {
					//resolve with ntoskrnl
					if ( module != intel_driver::ntoskrnl_address ) {
						function_address = intel_driver::get_kernel_module_export( iqvw64e_device_handle, intel_driver::ntoskrnl_address, current_function_data.name );
						if ( !function_address ) {
							logger::log( logger::log_type_t::error, std::format( "failed to resolve {} {}", current_function_data.name, current_import.module_name ) );

							return false;
						}
					}
				}

				*current_function_data.address = function_address;
			}
		}

		return true;
	}

	uint64_t map_driver( HANDLE iqvw64e_device_handle, BYTE* data ) {
		PIMAGE_NT_HEADERS64 nt_headers{ portable_executable::get_nt_headers( data ) };

		if ( !nt_headers ) {
			logger::log( logger::log_type_t::error, "invalid format of PE image" );
			return 0;
		}

		if ( nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
			logger::log( logger::log_type_t::error, "image is not 64 bit" );
			return 0;
		}

		uint32_t image_size{ nt_headers->OptionalHeader.SizeOfImage };
		void* local_image_base{ VirtualAlloc( nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) };
		if ( !local_image_base )
			return 0;

		DWORD total_virtual_header_size{ ( IMAGE_FIRST_SECTION( nt_headers ) )->VirtualAddress };
		uint64_t kernel_image_base{ intel_driver::allocate_pool( iqvw64e_device_handle, nt::POOL_TYPE::NonPagedPool, image_size ) };
		do {
			if ( !kernel_image_base ) {
				logger::log( logger::log_type_t::error, "failed to allocate kernel memory" );
				break;
			}

			logger::log( logger::log_type_t::info, std::format( "image base has been allocated at {:#x}", kernel_image_base ) );

			// copy image headers

			memcpy( local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders );

			// copy image sections

			PIMAGE_SECTION_HEADER current_image_section{ IMAGE_FIRST_SECTION( nt_headers ) };

			for ( auto i{ 0 }; i < nt_headers->FileHeader.NumberOfSections; ++i ) {
				if ( ( current_image_section[ i ].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA ) > 0 )
					continue;

				void* local_section{ reinterpret_cast< void* >( reinterpret_cast< uint64_t >( local_image_base ) + current_image_section[ i ].VirtualAddress ) };
				memcpy( local_section, reinterpret_cast< void* >( reinterpret_cast< uint64_t >( data ) + current_image_section[ i ].PointerToRawData ), current_image_section[ i ].SizeOfRawData );
			}

			uint64_t real_base{ kernel_image_base };

			// resolve relocs and imports

			relocate_image_by_delta( portable_executable::get_relocations( local_image_base ), kernel_image_base - nt_headers->OptionalHeader.ImageBase );

			if ( !resolve_imports( iqvw64e_device_handle, portable_executable::get_imports( local_image_base ) ) ) {
				logger::log( logger::log_type_t::error, "failed to resolve imports" );
				kernel_image_base = real_base;
				break;
			}

			// write fixed image to kernel

			if ( !intel_driver::write_memory( iqvw64e_device_handle, real_base, ( PVOID )( ( uintptr_t )local_image_base ), image_size ) ) {
				logger::log( logger::log_type_t::error, "failed to write local image to kernel memory" );
				kernel_image_base = real_base;
				break;
			}

			// call driver entry point

			uint64_t address_of_entry_point{ kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint };

			logger::log( logger::log_type_t::info, std::format( "calling driver entry {:#x}", address_of_entry_point ) );

			NTSTATUS status;
			if ( !intel_driver::call_kernel_function( iqvw64e_device_handle, &status, address_of_entry_point, 0, 0 ) ) {
				logger::log( logger::log_type_t::error, "failed to call driver entry" );
				kernel_image_base = real_base;
				break;
			}

			logger::log( logger::log_type_t::info, std::format( "driver entry status {:#08x}", static_cast< unsigned >( status ) ) );

			VirtualFree( local_image_base, 0, MEM_RELEASE );
			return real_base;

		} while ( false );


		VirtualFree( local_image_base, 0, MEM_RELEASE );
		intel_driver::free_pool( iqvw64e_device_handle, kernel_image_base );

		return 0;
	}
}

#endif