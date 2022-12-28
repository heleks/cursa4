#include "../includes.hpp"

int main( ) {
    HANDLE iqvw64e_handle = intel_driver::load( ); // load vulnerable driver
	std::vector< uint8_t > raw_image{ };
	if ( !utils::read_file_from_memory( "C:\\Users\\Administrator\\Desktop\\test.sys", &raw_image ) ) { // read driver to memory
		logger::log( logger::log_type_t::error, "failed to read file" );
		intel_driver::unload( iqvw64e_handle );
		return -1;
	}

	if ( !mapper::map_driver( iqvw64e_handle, raw_image.data( ) ) ) { // map driver
		logger::log( logger::log_type_t::error, "failed to map driver" );
		intel_driver::unload( iqvw64e_handle );
		return -1;
	}

	logger::log( logger::log_type_t::success, "driver mapped successfully" );

    intel_driver::unload( iqvw64e_handle ); // unload vulnerable driver
    
	std::cin.get( );
    return 0;
}