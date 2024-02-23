#pragma once

#include <yara/libyara.h>
#include <yara/compiler.h>
#include <yara/filemap.h>
#include <yara/scan.h>
#include <string>
#include <atomic>
#include <mutex>
#include "yara/iyara.hpp"

namespace YaraAnalysis
{

/**
 * @brief default scan function
 *
 */
#define _DEFAULT_SCAN_FUNCTION reinterpret_cast<YR_CALLBACK_FUNC>(YaraAnalysis::Yara::scan_file_call_back_default)
#define ALLOC_MEMORY_RESERVE 2 * 1024 * 1024 // 2M
#define TOTAL_THREADS 40
#define SLEEP_THREADS 10

    class Yara : public IYara
    {
    public:
        typedef struct _CALLBACK_ARGS
        {
            const char *file_path;
            int current_count;
            bool verbose;

        } CALLBACK_ARGS;

        /**
         * @brief Load all YARA rules from the specified folder with .yar extensions.
         *
         * This function loads all YARA rules located in the specified folder that have the
         * .yar file extension.
         *
         * @param folder_rules The folder from which to load the YARA rules.
         */
        Yara(const char *folder_rules);

        ~Yara();

        const void scan_file(const std::string &path, int flags, YR_CALLBACK_FUNC call_back, const bool verbose = false) const override;

        const void scan_folder(const std::string &current_dir, int flags, YR_CALLBACK_FUNC call_back, const bool verbose = false) const override;

        static YR_CALLBACK_FUNC scan_file_call_back_default(YR_SCAN_CONTEXT *context,
                                                            int message,
                                                            void *message_data,
                                                            void *user_data);

    private:
        const char *m_folder_rules;
        YR_COMPILER *m_yara_compiler;
        YR_RULES *m_yara_rules;
        mutable std::atomic<int> m_active_threads_count{0};
        mutable std::mutex m_thread_count_mutex;

        /**
         * @brief Collects and compiles all signature rules and adds them to the member variable m_yara_rules.
         *
         * This function retrieves all compiled signature rules and stores them in the member variable m_yara_rules.
         */
        void get_all_signatures_rules();

        /**
         * @brief Recursively traverse folders, collecting and adding all YARA rules from the directory.
         *
         * This function recursively scans the specified directory and its subdirectories, collecting and adding
         * all YARA rules found within them.
         *
         * @param current_dir The current directory to start the recursive search from.
         */
        void set_all_signatures_rules_folder(const std::string &current_dir);

        /**
         * @brief Set a YARA rule signature.
         *
         * This function associates a YARA rule file with a specific file path, allowing
         * the application of the rule to that file.
         *
         * @param path The full path to the file to which the YARA rule will be applied.
         * @param yara_file_name The name of the YARA file containing the custom rule.
         * @return A constant integer value indicating the result of the operation.
         *         - 0: The YARA rule was successfully applied to the specified file.
         *         - Other value: Indicates an error or unexpected result.
         */
        const int set_signature_rule(const std::string &path, const std::string &yara_file_name) const;
    };
}