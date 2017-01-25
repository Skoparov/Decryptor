#include "async.hpp"

namespace decrypt
{

namespace details
{

namespace concurrency
{

async::async( size_t number_of_threads )
{
    for( size_t thread{ 0 }; thread < number_of_threads; ++thread )
    {
        add_thread();
    }
}

async::~async()
{
    m_running = false;

    for( auto& t : m_pool )
    {
        t.join();
    }
}

void async::wait_for_vacant_thread() const
{
    if( m_currently_working == m_pool.size() )
    {
        std::unique_lock< std::mutex > l{ m_sync_mutex };
        m_done.wait( l, [ this ](){ return m_currently_working < m_pool.size(); } );
    }
}

void async::add_thread()
{
    std::thread t
    {
        [ this ]()
        {
            while( m_running )
            {
                std::function< void() > task;

                {
                    std::unique_lock< std::mutex > l{ m_sync_mutex };

                    if( m_tasks.empty() )
                    {
                        m_cv.wait_for( l, std::chrono::duration< int, std::milli >( 5 ) );
                        continue;
                    }

                    task = std::move( m_tasks.front() );
                    m_tasks.pop_front();
                }

                task();
            }
        }
    };

    m_pool.push_back( std::move( t ) );
}

}// concurrency

}// details

}// decrypt

