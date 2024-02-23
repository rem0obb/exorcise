#include "pyscho/pyscho.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <spdlog/spdlog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sys/ioctl.h>

namespace DriverPyscho
{
    Pyscho::Pyscho() : m_fd_driver(0), m_kernel_data((struct __kernel_data *)malloc(sizeof(struct __kernel_data)))
    {
        if (!Pyscho::is_driver_installed())
        {
            const std::string fmt = fmt::format("Pyscho : Driver '{}' not installed", DRIVER_PATH);
            spdlog::error(fmt);
            throw std::runtime_error(fmt);
        }

        spdlog::info("Pyscho : The driver '{}' is installed", DRIVER_PATH);
        Pyscho::initialize_commands_map();
    }

    __always_inline_ const void Pyscho::open_driver(int flag)
    {
        m_fd_driver = open(DRIVER_PATH, flag);

        if (m_fd_driver < 0)
        {
            int error_code = errno;
            const std::string fmt = fmt::format("Pyscho : Error opening driver '{}': {} (Error code: {})", DRIVER_PATH, strerror(error_code), error_code);
            spdlog::error(fmt);
            throw std::runtime_error(fmt);
        }
    }

    __always_inline_ const void Pyscho::connect_driver()
    {
        Pyscho::monitor_signals();
        Pyscho::open_driver(O_RDONLY);
        Pyscho::pr_infos_driver();

        std::string cmd;
        while (true)
        {
            fmt::print("(pyscho) ");
            std::getline(std::cin, cmd);
            if (cmd.empty())
            {
                continue;
            }
            if (!Pyscho::execute_command(cmd))
            {
                fmt::print("Command '{} 'not found\n", cmd);
            }
        }
    }

    void Pyscho::sig_handler_events(int signo)
    {
        switch (signo)
        {
        case SIGUSR1:
            spdlog::info("Pyscho : Driver received signal SIGUSR1 ( connected successfully )");
            break;

        default:
            break;
        }
    }

    __always_inline_ const void Pyscho::monitor_signals()
    {
        if (signal(SIGUSR1, sig_handler_events) == SIG_ERR)
        {
            int error_code = errno;
            const std::string fmt = fmt::format("Pyscho : Error monitor signals : {} (Error code: {})", strerror(error_code), error_code);
            spdlog::error(fmt);
            throw std::runtime_error(fmt);
        }
    }

    Pyscho::~Pyscho()
    {
        close(m_fd_driver);
        free(m_kernel_data);
        free(m_kernel_data->data);
    }

    __always_inline_ const bool Pyscho::is_driver_installed()
    {
        return (access(DRIVER_PATH, F_OK) == 0);
    }

    __always_inline_ const void Pyscho::initialize_commands_map(void)
    {
        m_callback_commands["clear"] = &Pyscho::command_clear;
        m_callback_commands["help"] = &Pyscho::command_help;
        m_callback_commands["exit"] = &Pyscho::command_exit;
        m_callback_commands["version"] = &Pyscho::command_version;
    }

    __always_inline_ const bool Pyscho::command_clear(void)
    {
        fmt::print("\033[2J\033[1;1H");
        return false;
    }

    __always_inline_ const bool Pyscho::command_exit(void)
    {
        exit(EXIT_SUCCESS);
        return false;
    }

    __always_inline_ const bool Pyscho::command_version(void)
    {
        return true;
    }

    __always_inline_ const bool Pyscho::execute_command(const std::string &cmd)
    {
        bool retval = false;
        if (m_callback_commands.find(cmd) != m_callback_commands.end())
        {
            retval = true;
            if ((this->*(m_callback_commands[cmd]))())
            {
                ioctl_set_cmd(cmd.c_str());
            }
        }

        return retval;
    }

    __always_inline_ const bool Pyscho::command_help()
    {
        fmt::print("\nAvailable Commands:\n"
                     "clear - Clears the terminal.\n"
                     "help - Displays the list of available commands and their descriptions.\n"
                     "exit - Exits the terminal.\n\n");
        return false;
    }

    __always_inline_ const void Pyscho::pr_infos_driver()
    {
        std::ifstream version_file("/proc/version");
        std::string kernel_version;
        if (version_file.is_open())
        {
            std::getline(version_file, kernel_version);
            version_file.close();
        }

        fmt::print("Pyscho v{} ({}) built-in shell\nEnter 'help' for a list of built-in commands.\n\n", VERSION, kernel_version);
    }

    __always_inline_ const int Pyscho::ioctl_set_cmd(const char *cmd)
    {
        int retval;

        m_kernel_data->size = strlen(cmd);
        m_kernel_data->data = malloc(m_kernel_data->size);

        m_kernel_data->data = (void *)cmd;

        retval = ioctl(m_fd_driver, IOCTL_SET_MSG, m_kernel_data);

        if (retval < 0)
        {
            const std::string fmt = fmt::format("Pyscho : Error in IOCTL_SET_MSG driver({}) = ", cmd);
            throw std::runtime_error(fmt);
        }

        return retval;
    }
}