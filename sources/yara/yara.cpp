#include "yara/yara.hpp"
#include <yara/error.h>
#include "spdlog/spdlog.h"
#include <dirent.h>
#include <filesystem>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include <yara/rules.h>

namespace YaraAnalysis
{
    Yara::Yara(const char *folder_rules) : m_folder_rules(folder_rules), m_yara_compiler(nullptr), m_yara_rules(nullptr)
    {
        if (yr_initialize() != ERROR_SUCCESS)
        {
            spdlog::error("Yara : yr_initialize() ERROR_SUCCESS = 1");
            throw std::runtime_error("Yara : yr_initialize() ERROR_SUCCESS = 1");
        }

        int yr_compiler = yr_compiler_create(&m_yara_compiler);

        if (yr_compiler == ERROR_SUCCESS && yr_compiler != ERROR_INSUFFICIENT_MEMORY)
        {
            std::thread thread_set_all_signatures(&Yara::set_all_signatures_rules_folder, this, m_folder_rules);

            thread_set_all_signatures.join();

            get_all_signatures_rules();
        }
    }

    void Yara::get_all_signatures_rules()
    {
        int get_rules = yr_compiler_get_rules(m_yara_compiler, &m_yara_rules);
        if (get_rules != ERROR_SUCCESS || get_rules == ERROR_INSUFFICIENT_MEMORY)
        {
            spdlog::error("Yara: Error occurred while compiling rules");
            throw std::runtime_error("Yara : yr_compiler_get_rules() = " + get_rules);
        }
    }

    void Yara::set_all_signatures_rules_folder(const std::string &current_dir)
    {

        DIR *dir = opendir(current_dir.c_str());
        if (!dir)
        {
            spdlog::error("Yara : Failed to open folder '{}'  Please ensure that the folder exists and has the necessary permissions.", current_dir);
            throw std::runtime_error("Yara : Failed to open folder '" + current_dir + "'  Please ensure that the folder exists and has the necessary permissions.");
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            const std::filesystem::path entry_name = entry->d_name;
            const std::string full_path = std::string(current_dir) + "/" + entry_name.c_str();

            if (entry_name == "." || entry_name == "..")
            {
                continue;
            }

            if (entry_name.extension() == ".yar")
            {
                if (set_signature_rule(full_path.c_str(), entry_name.c_str()) != ERROR_SUCCESS)
                {
                    spdlog::error("Yara: Failed to compile rule {}", full_path);
                    throw std::runtime_error("Yara: Failed to compile rule " + std::string(full_path));
                }
            }
            else if (entry->d_type == DT_DIR)
            {
                set_all_signatures_rules_folder(full_path);
            }
        }

        closedir(dir);
    }

    const int Yara::set_signature_rule(const std::string &path, const std::string &yara_file_name) const
    {
        YR_FILE_DESCRIPTOR rules_fd = open(path.c_str(), O_RDONLY);

        int errors = yr_compiler_add_fd(m_yara_compiler, rules_fd, nullptr, yara_file_name.c_str());

        close(rules_fd);

        return errors;
    }

    const void Yara::scan_folder(const std::string &current_dir, int flags, YR_CALLBACK_FUNC call_back, const bool verbose) const
    {
        DIR *dir = opendir(current_dir.c_str());
        if (!dir)
        {
            spdlog::error("Yara : Failed to open folder '{}'  Please ensure that the folder exists and has the necessary permissions.", current_dir);
            throw std::runtime_error("Yara : Failed to open folder '" + current_dir + "'  Please ensure that the folder exists and has the necessary permissions.");
        }

        struct dirent *entry;
        std::vector<std::thread> threads;

        threads.reserve(ALLOC_MEMORY_RESERVE);

        while ((entry = readdir(dir)) != nullptr)
        {
            const std::filesystem::path entry_name = entry->d_name;
            const std::string full_path = std::string(current_dir) + "/" + entry_name.c_str();

            if (entry_name == "." || entry_name == "..")
            {
                continue;
            }

            if (entry->d_type == DT_DIR)
            {
                Yara::scan_folder(full_path, flags, call_back, verbose);
            }
            else
            {

            sleep:
                if (m_active_threads_count.load() >= TOTAL_THREADS)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_THREADS));
                    goto sleep;
                }

                threads.emplace_back(&Yara::scan_file, this, full_path, flags, call_back, verbose);
            }
        }

        for (auto &thread : threads)
        {
            thread.join();
        }

        closedir(dir);
    }

    const void Yara::scan_file(const std::string &path, int flags, YR_CALLBACK_FUNC call_back, const bool verbose) const
    {
        {
            std::lock_guard<std::mutex> lock(m_thread_count_mutex);
            m_active_threads_count++;
        }

        YR_FILE_DESCRIPTOR fd = open(path.c_str(), O_RDONLY);

        CALLBACK_ARGS *user_data = (struct _CALLBACK_ARGS *)malloc(sizeof(struct _CALLBACK_ARGS));
        user_data->file_path = path.c_str();
        user_data->current_count = 0;
        user_data->verbose = verbose;

        yr_rules_scan_fd(m_yara_rules, fd, SCAN_FLAGS_FAST_MODE, call_back, user_data, 0);

        free(user_data);
        close(fd);

        {
            std::lock_guard<std::mutex> lock(m_thread_count_mutex);
            m_active_threads_count--;
        }
    }

    YR_CALLBACK_FUNC Yara::scan_file_call_back_default(YR_SCAN_CONTEXT *context,
                                                       int message,
                                                       void *message_data,
                                                       void *user_data)
    {
        YR_RULE *rule = reinterpret_cast<YR_RULE *>(message_data);
        YR_STRING *string;
        YR_MATCH *match;
        std::string concat_string;

        switch (message)
        {
        case CALLBACK_MSG_SCAN_FINISHED:

            if (((CALLBACK_ARGS *)user_data)->verbose || ((CALLBACK_ARGS *)user_data)->current_count)
                spdlog::info("Yara : All rules were passed in this file '{}', the scan is over, rules matching {}", ((CALLBACK_ARGS *)user_data)->file_path, ((CALLBACK_ARGS *)user_data)->current_count);
            break;
        case CALLBACK_MSG_RULE_MATCHING:
            ((CALLBACK_ARGS *)user_data)->current_count++;
            yr_rule_strings_foreach(rule, string)
            {
                yr_string_matches_foreach(context, string, match)
                {
                    concat_string += fmt::format("[{}:0x{:x}]", string->identifier, match->offset);
                }
            }

            spdlog::warn("Yara : The rule '{}' were identified in this file '{}', Strings match {}", rule->identifier, ((CALLBACK_ARGS *)user_data)->file_path, concat_string);
            break;

        case CALLBACK_MSG_RULE_NOT_MATCHING:
            break;
        }

        return CALLBACK_CONTINUE;
    }

    Yara::~Yara()
    {
        if (yr_finalize() != ERROR_SUCCESS)
        {
            spdlog::error("Yara : yr_finalize() ERROR_SUCCESS = 1");
            std::runtime_error("Yara : Failed finalize yara");
        }

        if (m_yara_compiler != nullptr)
            yr_compiler_destroy(m_yara_compiler);

        if (yr_rules_destroy(m_yara_rules) != ERROR_SUCCESS)
        {
            spdlog::error("Yara : yr_rules_destroy() ERROR_SUCCESS = 1");
            std::runtime_error("Yara : Failed destroy rules");
        }
    }
}