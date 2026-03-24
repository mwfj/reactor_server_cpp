#include "log/logger.h"

#include <vector>
#include <mutex>

namespace logging {

static std::shared_ptr<spdlog::logger> g_logger;
static std::mutex g_logger_mtx;

void Init(const std::string& name,
          spdlog::level::level_enum level,
          const std::string& log_file,
          size_t max_size,
          int max_files) {
    std::lock_guard<std::mutex> lock(g_logger_mtx);

    std::vector<spdlog::sink_ptr> sinks;

    // Console sink with color support
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(level);
    sinks.push_back(console_sink);

    // Optional rotating file sink
    if (!log_file.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, max_size, max_files);
        file_sink->set_level(level);
        sinks.push_back(file_sink);
    }

    // Create logger with all sinks
    g_logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
    g_logger->set_level(level);
    g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] %v");

    // Register as default logger
    spdlog::set_default_logger(g_logger);
}

std::shared_ptr<spdlog::logger> Get() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (g_logger) {
        return g_logger;
    }
    return spdlog::default_logger();
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(g_logger_mtx);
    if (g_logger) {
        g_logger->flush();
    }
    spdlog::shutdown();
    g_logger.reset();
}

} // namespace logging
