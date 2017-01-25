cmake_minimum_required(VERSION 3.2)
add_definitions( "-std=c++11" )

set (PROJECT Decipher)
project( ${PROJECT} )

SET( CMAKE_BUILD_TYPE Debug )

file( GLOB_RECURSE SOURCES "*.hpp" "*.cpp" )

find_library( SSL_LIB libssl.a REQUIRED )
find_library( CRYPTO_LIB libcrypto.a REQUIRED )


add_executable (${PROJECT} ${SOURCES} )
target_link_libraries( ${PROJECT} ${SSL_LIB} ${CRYPTO_LIB} pthread )
