#include <iostream>

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
        std::string pass{ decrypt::decrypt_password( path, 8 ) };
        std::cout<< "Password: " << pass << std::endl;
    }
    catch( const std::exception& e )
    {
        std::cerr << "Exception was thrown: " << e.what() << std::endl;
    }
}
