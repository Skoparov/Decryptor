#ifndef ASYNC_HPP
#define ASYNC_HPP

#include <mutex>
#include <atomic>
#include <thread>
#include <vector>
#include <future>
#include <deque>
#include <condition_variable>

namespace decrypt
{

namespace details
{

namespace concurrency
{

// Thread pool class designed to concurrently run tasks
class async
{
public:
    explicit async( size_t number_of_threads = std::thread::hardware_concurrency() );
    ~async();

    template< typename PackTask >
    auto run( std::packaged_task< PackTask() >& task  ) -> std::future< PackTask >;

    void wait_for_vacant_thread() const;

private:
    void add_thread();

private:
    bool m_running{ true };
    std::atomic_size_t m_currently_working{ 0 };

    std::vector< std::thread > m_pool;
    std::deque< std::function< void() > > m_tasks;

    mutable std::mutex m_sync_mutex;
    mutable std::condition_variable m_cv;
    mutable std::condition_variable m_done;
};

///// implementation

template< typename PackTask >
auto async::run( std::packaged_task< PackTask() >& task  ) -> std::future< PackTask >
{
    std::unique_lock< std::mutex > l{ m_sync_mutex };

    auto result = task.get_future();
    m_tasks.push_back( [ &task, this ]
                       {
                            ++m_currently_working;
                            task();
                            --m_currently_working;
                            m_done.notify_one();
                       } );

    m_cv.notify_one();
    return result;
}

}// concurrency

}// details

}//decrypt

#endif
