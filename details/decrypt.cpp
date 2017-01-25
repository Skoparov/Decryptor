#include <list>
#include <array>
#include <vector>
#include <fstream>
#include <string.h>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

#include "async.hpp"

#define BLOCK_SIZE 16
#define TRIPLE_DES_HEADER_SIZE 8
#define PASSWORD_LEN 3

namespace decrypt
{

namespace details
{

struct file_data
{
    std::array< unsigned char, SHA256_DIGEST_LENGTH > checksum;
    std::vector< char > data;
};

file_data read_file( const std::string& filename )
{
    file_data result;

    std::ifstream file{ filename, std::ios::binary };
    if( !file.is_open() )
    {
        throw std::runtime_error{ "Failed to open file: " + filename };
    }

    file.unsetf( std::ios::skipws );
    std::streampos file_size;

    file.seekg( 0, std::ios::end );
    file_size = file.tellg();
    file.seekg( 0, std::ios::beg );

    if( file_size < SHA256_DIGEST_LENGTH + TRIPLE_DES_HEADER_SIZE )
    {
        throw std::invalid_argument{ "Corrupted file" };
    }

    // Read data
    result.data.resize( file_size - SHA256_DIGEST_LENGTH );
    file.read( result.data.data(), result.data.size() );

    // Read checksum
    file.read( ( char* )( result.checksum.data() ), result.checksum.size() );

    return result;
}

// Tries to decrypt data with the given key
std::string check( std::string& password, const file_data& fa_data )
{   
    unsigned char passw_hash[ MD5_DIGEST_LENGTH ];
    MD5( ( const unsigned char* )password.data(), password.length(), passw_hash );

    DES_cblock cb1, cb2;
    for( int i{ 0 }; i < MD5_DIGEST_LENGTH / 2; ++i )
    {
        cb1[ i ] = passw_hash[ i ];
        cb2[ i ] = passw_hash[ i + MD5_DIGEST_LENGTH / 2 ];
    }

    DES_key_schedule ks1, ks2;

    DES_set_key(&cb1, &ks1);
    DES_set_key(&cb2, &ks2);

    DES_cblock buffer;
    memset( buffer, 0, sizeof( buffer ) );

    std::string text_end;
    text_end.resize( fa_data.data.size() );

    DES_ede3_cbc_encrypt( ( const unsigned char* )fa_data.data.data(),
                          ( unsigned char* )text_end.data(),
                          text_end.length(),
                          &ks1,
                          &ks2,
                          &ks1,
                          &buffer,
                          DES_DECRYPT);

    text_end.erase( text_end.begin(), text_end.begin() + TRIPLE_DES_HEADER_SIZE );

    std::array< unsigned char, SHA256_DIGEST_LENGTH > text_sha256;
    SHA256_CTX sha256;
    SHA256_Init( &sha256 );
    SHA256_Update( &sha256, text_end.c_str(), text_end.length() );
    SHA256_Final( text_sha256.data(), &sha256 );

    if( text_sha256 != fa_data.checksum )
    {
        password.clear();
    }

    return password;
}

// A general struct containing task information
struct Task
{
    std::packaged_task< std::string() > task;
    std::future< std::string > result;
};

// Check if password was found, remove finished tasks from the list
std::string check_for_password( std::list< Task >& tasks )
{
    std::string password;

    tasks.remove_if(
        [ &password ]( Task& t )
        {
            if( t.result.wait_for( std::chrono::seconds{ 0 } ) == std::future_status::ready )
            {
                std::string curr_pass{ t.result.get() }; // rethrow
                if( curr_pass.length() )
                {
                    password = curr_pass;
                }

                return true;
            }

            return false;
        });

    return password;
}

// Generates password sequences
class password_generator
{
public:
    password_generator()
    {
        //Generate lookup dictionary
        for( int i{ 0 }; i < m_number_of_letters; ++i  )
        {
          m_dict[i] = 97 + i; // lower case letter
          m_dict[i + m_number_of_letters ] = 65 + i; // upper case letter

          if( i < m_number_of_digits )
          {
              m_dict[ i + m_number_of_letters * 2 ] = 48 + i; // digit
          }
        }
    }

    std::string next()
    {
        std::string curr_pass;

        if( m_first_counter < m_dict.size() )
        {
            curr_pass = std::string{ m_dict[ m_first_counter ] } +
                                     m_dict[ m_second_counter ] +
                                     m_dict[ m_third_counter ];

            ++m_third_counter;

            if( m_third_counter == m_dict.size() )
            {
                m_third_counter = 0;
                ++m_second_counter;
            }

            if( m_second_counter == m_dict.size() )
            {
                m_second_counter = 0;
                ++m_first_counter;
            }
        }

        return curr_pass;
    }

    bool empty() const
    {
        return m_first_counter == m_dict.size();
    }

private:
    size_t m_first_counter{ 0 };
    size_t m_second_counter{ 0 };
    size_t m_third_counter{ 0 };

    static constexpr int m_number_of_letters{ 26 };
    static constexpr int m_number_of_digits{ 10 };
    std::array< char, m_number_of_letters * 2 + m_number_of_digits > m_dict;
};

}// details

std::string decrypt_password( const std::string& file_path, size_t threads_num )
{
    using namespace details;

    std::string password;

    file_data fa_data = read_file( file_path );

    concurrency::async async( threads_num );
    std::list< Task > tasks;

    password_generator gen;

    while( !gen.empty() )
    {               
        async.wait_for_vacant_thread();

        std::string new_pass{ gen.next() };

        password = check_for_password( tasks );
        if( password.length() )
        {
            break;
        }

        auto task_func = std::bind( &check, new_pass, std::ref( fa_data ) );
        tasks.emplace_back();

        Task& curr_task{ tasks.back() };
        curr_task.task = std::move( std::packaged_task< std::string() >{ task_func } );
        curr_task.result = std::move( async.run( curr_task.task ) );
    }

    // Wait for running tasks
    for( auto& task : tasks )
    {
        task.result.get();
    }  

    return password;
}

}// decrypt
