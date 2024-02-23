#pragma once

#include "pyscho/ipyscho.hpp"
#include "compiler/compiler_attribute.hpp"
#include <map>
#include <string>
#include "pyscho/ioctl.h"

namespace DriverPyscho
{
#define DRIVER_PATH "/dev/pyscho"

    class Pyscho : public IPyscho
    {
    public:
        Pyscho();
        ~Pyscho();

        /**
         * @brief connect driver pyscho
         *
         * @return __always_inline_ const void
         */
        __always_inline_ const void connect_driver() override;

    private:
        int m_fd_driver;
        struct inotify_event *m_identify;
        std::map<const std::string, const bool (Pyscho::*)()> m_callback_commands;
        struct __kernel_data *m_kernel_data;

        /**
         * @brief monitor signals sent by the driver
         *
         * @return __always_inline_ const void
         */
        __always_inline_ const void monitor_signals() override;

        /**
         * @brief Verify this driver is installed
         *
         * @return true
         * @return false
         */
        [[nodiscard]] __always_inline_ const bool is_driver_installed();

        static void sig_handler_events(int signo);

        /**
         * @brief open driver using wrapper system call open()  DRIVER_PATH
         *
         * @param flag flag pass for open()
         */
        __always_inline_ const void open_driver(int flag);

        __always_inline_ const void initialize_commands_map(void);

        __always_inline_ const void pr_infos_driver();

        __always_inline_ const bool command_exit(void);

        __always_inline_ const bool command_clear(void);

        __always_inline_ const bool command_help(void);

        __always_inline_ const bool command_version(void);

        __always_inline_ const bool execute_command(const std::string &cmd);

        __always_inline_ const int ioctl_set_cmd(const char *cmd);
    };
}