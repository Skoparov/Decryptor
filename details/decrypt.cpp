#include <list>
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

// Check if password has been found, remove finished tasks from the list
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
    password_generator( std::string& dict, size_t counters_num ) : m_dict( std::move( dict ) )
    {
        if( m_dict.empty() )
        {
            throw std::invalid_argument{ "Dictionary should not be empty" };
        }

        if( !counters_num )
        {
            throw std::invalid_argument{ "Number of counters should be positive" };
        }

        m_counters.resize( counters_num );
    }

    std::string next()
    {
        if( empty() )
        {
            throw std::out_of_range{ "Generator depleted" };
        }

        std::string curr_pass;

        for( size_t counter_num{ 0 }; counter_num < m_counters.size(); ++counter_num )
        {
            curr_pass += m_dict[ m_counters[ counter_num ] ];
        }

        size_t curr_counter{ m_counters.size() - 1 };

        while( true )
        {
            ++m_counters[ curr_counter ];

            if( curr_counter + 1 < m_counters.size() &&
                    m_counters[ curr_counter + 1 ] == m_dict.size() )
            {
                m_counters[ curr_counter + 1 ] = 0;
            }

            if( curr_counter == 0 )
            {
                break;
            }

            --curr_counter;
        }

        return curr_pass;
    }

    bool empty() const
    {
        return m_counters[ 0 ] == m_dict.size();
    }

private:
    std::string m_dict;
    std::vector< size_t > m_counters;
};

std::string generate_dict()
{
    static constexpr int number_of_letters{ 26 };
    static constexpr int number_of_digits{ 10 };

    std::string dict;
    dict.resize( number_of_letters * 2 + number_of_digits );

    //Generate lookup dictionary
    for( int i{ 0 }; i < number_of_letters; ++i  )
    {
        dict[ i ] = 97 + i; // lower case letter
        dict[ i + number_of_letters ] = 65 + i; // upper case letter

        if( i < number_of_digits )
        {
            dict[ i + number_of_letters * 2 ] = 48 + i; // digit
        }
    }

    return dict;
}

}// details

std::string decrypt_password( const std::string& file_path, size_t threads_num )
{
    using namespace details;

    std::string password;

    file_data fa_data = read_file( file_path );

    concurrency::async async( threads_num );
    std::list< Task > tasks;

    std::string dict{ generate_dict() };
    size_t number_of_counters{ 3 }; // Uppercase + lowercase + digits

    password_generator gen{ dict, number_of_counters };

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

        Task& curr_task = tasks.back();
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
