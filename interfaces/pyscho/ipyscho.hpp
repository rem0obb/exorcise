#pragma once

#include <sys/inotify.h>

namespace DriverPyscho
{
    class IPyscho
    {
    public:
        IPyscho(){};
        virtual ~IPyscho(){};

        virtual const void connect_driver() = 0;
        virtual const void monitor_signals() = 0;
    };
}