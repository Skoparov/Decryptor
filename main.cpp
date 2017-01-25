#include <iostream>
#include <thread>

#include "decrypt.hpp"

int main( int argc, char* argv[] )
{
    if( argc != 2 )
    {
        std::cerr << "Usage: " << argv[0] << " file_path" << std::endl;
        return 1;
    }

    std::string path{ argv[ 1 ] };

    try
    {
        unsigned int threads_num{ std::thread::hardware_concurrency() };
        std::string pass{ decrypt::decrypt_password( path, threads_num > 1? threads_num - 1 : 1 ) };
        std::cout<< "Password: " << pass << std::endl;
    }
    catch( const std::exception& e )
    {
        std::cerr << "Exception was thrown: " << e.what() << std::endl;
    }
}
