#ifndef portable_executable_hpp
#define portable_executable_hpp

namespace portable_executable {

	struct relocations_info {
		uint64_t address;
		uint16_t* item;
		uint32_t count;
	};

	struct import_function_info {
		std::string name;
		uint64_t* address;
	};

	struct import_info {
		std::string module_name;
		std::vector<import_function_info> function_datas;
	};

	using vec_sections = std::vector< IMAGE_SECTION_HEADER >;
	using vec_relocs = std::vector< relocations_info >;
	using vec_imports = std::vector< import_info >;

	IMAGE_NT_HEADERS64* get_nt_headers( void* image_base ) {
		IMAGE_DOS_HEADER* dos_header{ reinterpret_cast< IMAGE_DOS_HEADER* >( image_base ) };

		if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
			return nullptr;

		IMAGE_NT_HEADERS64* nt_headers{ reinterpret_cast< IMAGE_NT_HEADERS64* >( reinterpret_cast< uint64_t >( image_base ) + dos_header->e_lfanew ) };

		if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
			return nullptr;

		return nt_headers;
	}

	vec_relocs get_relocations( void* image_base ) {
		IMAGE_NT_HEADERS64* nt_headers{ get_nt_headers( image_base ) };
		if ( !nt_headers )
			return {};

		DWORD reloc_va{ nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress };
		if ( !reloc_va )
			return {};

		IMAGE_BASE_RELOCATION* current_base_relocation{ reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( image_base ) + reloc_va ) };
		IMAGE_BASE_RELOCATION* reloc_end{ reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( current_base_relocation ) + nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size ) };

		vec_relocs relocations;
		while ( current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock ) {
			relocations_info reloc_info;

			reloc_info.address = reinterpret_cast< uint64_t >( image_base ) + current_base_relocation->VirtualAddress;
			reloc_info.item = reinterpret_cast< uint16_t* >( reinterpret_cast< uint64_t >( current_base_relocation ) + sizeof IMAGE_BASE_RELOCATION );
			reloc_info.count = ( current_base_relocation->SizeOfBlock - sizeof IMAGE_BASE_RELOCATION ) / sizeof uint16_t;

			relocations.push_back( reloc_info );

			current_base_relocation = reinterpret_cast< PIMAGE_BASE_RELOCATION >( reinterpret_cast< uint64_t >( current_base_relocation ) + current_base_relocation->SizeOfBlock );
		}

		return relocations;
	}

	vec_imports get_imports( void* image_base ) {
		IMAGE_NT_HEADERS64* nt_headers{ get_nt_headers( image_base ) };
		if ( !nt_headers )
			return {};

		DWORD import_va{ nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress };
		if ( !import_va )
			return {};

		vec_imports imports;
		IMAGE_IMPORT_DESCRIPTOR* current_import_descriptor{ reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( reinterpret_cast< uint64_t >( image_base ) + import_va ) };
		while ( current_import_descriptor->FirstThunk ) {
			import_info import_info;
			import_info.module_name = std::string( reinterpret_cast< char* >( reinterpret_cast< uint64_t >( image_base ) + current_import_descriptor->Name ) );

			IMAGE_THUNK_DATA64* current_first_thunk{ reinterpret_cast< IMAGE_THUNK_DATA64* >( reinterpret_cast< uint64_t >( image_base ) + current_import_descriptor->FirstThunk ) };
			IMAGE_THUNK_DATA64* current_originalFirstThunk{ reinterpret_cast< IMAGE_THUNK_DATA64* >( reinterpret_cast< uint64_t >( image_base ) + current_import_descriptor->OriginalFirstThunk ) };

			while ( current_originalFirstThunk->u1.Function ) {
				import_function_info import_function_data;

				IMAGE_IMPORT_BY_NAME* thunk_data{ reinterpret_cast< IMAGE_IMPORT_BY_NAME* >( reinterpret_cast< uint64_t >( image_base ) + current_originalFirstThunk->u1.AddressOfData ) };

				import_function_data.name = thunk_data->Name;
				import_function_data.address = &current_first_thunk->u1.Function;

				import_info.function_datas.push_back( import_function_data );

				++current_originalFirstThunk;
				++current_first_thunk;
			}

			imports.push_back( import_info );
			++current_import_descriptor;
		}

		return imports;
	}

}

#endif
