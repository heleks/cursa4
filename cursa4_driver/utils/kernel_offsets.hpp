#ifndef kernel_offsets_hpp
#define kernel_offsets_hpp

namespace kernel_offsets {
	uint64_t unique_process_id_offset;
	uint64_t active_process_links_offset;
	uint64_t image_file_name_offset;
	uint64_t active_threads_offset;

	bool initialize( ) {
		unique_process_id_offset = *reinterpret_cast< uint32_t* >( reinterpret_cast< uint64_t >( PsGetProcessId ) + 0x3 );
		active_process_links_offset = unique_process_id_offset + 0x8;
		image_file_name_offset = *reinterpret_cast< uint32_t* >( reinterpret_cast< uint64_t >( PsGetProcessImageFileName ) + 0x3 );;
		active_threads_offset = image_file_name_offset + 0x48;

		debug_log( "thread unique_process_id_offset: %p" , unique_process_id_offset );
		debug_log( "thread active_process_links_offset: %p" , active_process_links_offset );
		debug_log( "thread image_file_name_offset: %p" , image_file_name_offset );
		debug_log( "thread active_threads_offset: %p" , active_threads_offset );

		return unique_process_id_offset && active_process_links_offset && image_file_name_offset && active_threads_offset;
	}

}

#endif