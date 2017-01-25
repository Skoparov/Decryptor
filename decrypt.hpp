#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include <string>

namespace decrypt
{

std::string decrypt_password( const std::string& file_path, size_t threads_num );


}// decrypt

#endif
