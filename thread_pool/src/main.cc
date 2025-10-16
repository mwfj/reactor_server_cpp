#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "threadpool.h"
#include "threads.h"

namespace TESTCASE {

void PrintSection(const std::string& name) {
    std::cout << "\n==== " << name << " ====\n";
}

class TestTask : public ThreadTaskInterface {
public:
    explicit TestTask(std::function<int()> func)
        : func_(std::move(func)) {}

protected:
    int RunTask() override { return func_(); }

private:
    std::function<int()> func_;
};

class InspectableTask : public ThreadTaskInterface {
public:
    explicit InspectableTask(std::function<int(std::function<bool()>)> func)
        : func_(std::move(func)) {}

protected:
    int RunTask() override {
        auto checker = [this]() { return this->is_running(); };
        return func_(checker);
    }

private:
    std::function<int(std::function<bool()>)> func_;
};

void TestBasicExecution() {
    PrintSection("BasicExecution");

    ThreadPool pool;
    pool.Init();
    pool.SetMaxThreadWorkerNum(4, false);
    pool.Start();

    constexpr int task_count = 5;
    std::atomic<int> counter{0};
    std::vector<std::shared_ptr<ThreadTaskInterface>> tasks;
    tasks.reserve(task_count);

    for (int i = 0; i < task_count; ++i) {
        auto task = std::make_shared<TestTask>([&, i]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(15 + i * 5));
            std::cout << "Running basic task " << i << std::endl;
            return ++counter;
        });
        tasks.push_back(task);
        pool.AddTask(task);
    }

    std::vector<int> results;
    results.reserve(task_count);
    for (auto& task : tasks) {
        results.push_back(task->GetValue());
    }

    const int actual_sum = std::accumulate(results.begin(), results.end(), 0);
    const int expected_sum = task_count * (task_count + 1) / 2;
    if (actual_sum != expected_sum) {
        throw std::runtime_error("BasicExecution: unexpected task results");
    }

    if (pool.running_threads() != 0) {
        throw std::runtime_error("BasicExecution: pool should report 0 running threads");
    }

    pool.Stop();
    std::cout << "BasicExecution passed" << std::endl;
}

void TestExceptionPropagation() {
    PrintSection("ExceptionPropagation");

    ThreadPool pool;
    pool.Init();
    pool.SetMaxThreadWorkerNum(2, false);
    pool.Start();

    auto ok_task = std::make_shared<TestTask>([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        return 42;
    });

    auto bad_task = std::make_shared<TestTask>([]() -> int {
        throw std::runtime_error("intentional failure");
    });

    pool.AddTask(ok_task);
    pool.AddTask(bad_task);

    const int ok_result = ok_task->GetValue();
    if (ok_result != 42) {
        throw std::runtime_error("ExceptionPropagation: expected ok task to return 42");
    }

    bool caught_expected_exception = false;
    try {
        (void)bad_task->GetValue();
    } catch (const std::runtime_error& e) {
        if (std::string(e.what()).find("intentional failure") != std::string::npos) {
            caught_expected_exception = true;
        }
    }

    pool.Stop();

    if (!caught_expected_exception) {
        throw std::runtime_error("ExceptionPropagation: did not catch expected runtime_error");
    }

    std::cout << "ExceptionPropagation passed" << std::endl;
}

void TestStopCancelsPendingTasks() {
    PrintSection("StopCancelsPendingTasks");

    ThreadPool pool;
    pool.Init();
    pool.SetMaxThreadWorkerNum(1, false);
    pool.Start();

    auto long_task = std::make_shared<TestTask>([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        return 1;
    });

    auto pending_task1 = std::make_shared<TestTask>([]() { return 2; });
    auto pending_task2 = std::make_shared<TestTask>([]() { return 3; });

    pool.AddTask(long_task);
    pool.AddTask(pending_task1);
    pool.AddTask(pending_task2);

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    pool.Stop();

    const int long_result = long_task->GetValue();
    if (long_result != 1) {
        throw std::runtime_error("StopCancelsPendingTasks: long task returned unexpected value");
    }

    auto verify_cancelled = [](const std::shared_ptr<ThreadTaskInterface>& task) {
        try {
            (void)task->GetValue();
            throw std::runtime_error("Expected queued task to be cancelled");
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("ThreadPool Stopped") == std::string::npos) {
                throw;
            }
        }
    };

    verify_cancelled(pending_task1);
    verify_cancelled(pending_task2);

    std::cout << "StopCancelsPendingTasks passed" << std::endl;
}

void TestRestartability() {
    PrintSection("Restartability");

    ThreadPool pool;
    pool.Init();
    pool.SetMaxThreadWorkerNum(2, false);

    auto run_batch = [&](int batch_size, int expected_start) {
        pool.Start();

        std::atomic<int> counter{expected_start};
        std::vector<std::shared_ptr<ThreadTaskInterface>> tasks;
        tasks.reserve(batch_size);

        for (int i = 0; i < batch_size; ++i) {
            auto task = std::make_shared<TestTask>([&counter]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                return ++counter;
            });
            tasks.push_back(task);
            pool.AddTask(task);
        }

        std::vector<int> results;
        results.reserve(batch_size);
        for (auto& task : tasks) {
            results.push_back(task->GetValue());
        }

        pool.Stop();

        std::sort(results.begin(), results.end());
        for (int i = 0; i < batch_size; ++i) {
            if (results[i] != expected_start + i + 1) {
                throw std::runtime_error("Restartability: unexpected result sequence");
            }
        }

        if (pool.running_threads() != 0) {
            throw std::runtime_error("Restartability: running_threads should be zero after Stop");
        }
    };

    run_batch(6, 0);
    run_batch(4, 10);

    std::cout << "Restartability passed" << std::endl;
}

void TestStartValidation() {
    PrintSection("StartValidation");

    ThreadPool pool;
    pool.Init();

    if (pool.GetMaxThreadWorkerNum() <= 0) {
        throw std::runtime_error("StartValidation: Init did not assign a positive worker count");
    }

    pool.SetMaxThreadWorkerNum(0, false);

    bool caught_expected = false;
    try {
        pool.Start();
    } catch (const std::runtime_error& e) {
        if (std::string(e.what()).find("thread count <= 0") != std::string::npos) {
            caught_expected = true;
        }
    }

    if (!caught_expected) {
        throw std::runtime_error("StartValidation: expected Start() to reject zero workers");
    }

    pool.SetMaxThreadWorkerNum(1, false);
    pool.Start();
    pool.Stop();

    std::cout << "StartValidation passed" << std::endl;
}

void TestCooperativeCancellation() {
    PrintSection("CooperativeCancellation");

    ThreadPool pool;
    pool.Init();
    pool.SetMaxThreadWorkerNum(1, false);
    pool.Start();

    bool running_reported_at_start = false;
    bool running_reported_after_stop = true;

    auto task = std::make_shared<InspectableTask>(
        [&](std::function<bool()> is_pool_running) {
            running_reported_at_start = is_pool_running();
            while (is_pool_running()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            running_reported_after_stop = is_pool_running();
            return 0;
        });

    pool.AddTask(task);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    pool.Stop();

    const int result = task->GetValue();
    if (result != 0) {
        throw std::runtime_error("CooperativeCancellation: unexpected task result");
    }

    if (!running_reported_at_start) {
        throw std::runtime_error("CooperativeCancellation: is_running() should be true while pool is active");
    }

    if (running_reported_after_stop) {
        throw std::runtime_error("CooperativeCancellation: is_running() should report false after Stop()");
    }

    std::cout << "CooperativeCancellation passed" << std::endl;
}

void TestHighConcurrency() {
    PrintSection("HighConcurrency");

    ThreadPool pool;
    pool.Init();
    pool.Start();

    constexpr int task_count = 64;
    std::atomic<int> counter{0};
    std::vector<std::shared_ptr<ThreadTaskInterface>> tasks;
    tasks.reserve(task_count);

    for (int i = 0; i < task_count; ++i) {
        auto task = std::make_shared<TestTask>([&, i]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(5 + (i % 4)));
            return ++counter;
        });
        tasks.push_back(task);
        pool.AddTask(task);
    }

    std::vector<int> results;
    results.reserve(task_count);
    for (auto& task : tasks) {
        results.push_back(task->GetValue());
    }

    std::sort(results.begin(), results.end());
    for (int i = 0; i < task_count; ++i) {
        if (results[i] != i + 1) {
            throw std::runtime_error("HighConcurrency: missing or duplicate task result");
        }
    }

    if (pool.running_threads() != 0) {
        throw std::runtime_error("HighConcurrency: pool should report 0 running threads");
    }

    pool.Stop();
    std::cout << "HighConcurrency passed" << std::endl;
}

}  // namespace TESTCASE

int main() {
    try {
        TESTCASE::TestBasicExecution();
        TESTCASE::TestExceptionPropagation();
        TESTCASE::TestStopCancelsPendingTasks();
        TESTCASE::TestRestartability();
        TESTCASE::TestStartValidation();
        TESTCASE::TestCooperativeCancellation();
        TESTCASE::TestHighConcurrency();
    } catch (const std::exception& e) {
        std::cerr << "Test failure: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nAll tests passed." << std::endl;
    return 0;
}
