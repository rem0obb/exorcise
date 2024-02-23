#pragma once

#include <linux/ioctl.h>

#define MAJOR_NUM 0x100
#define VERSION "1.0.0"

struct __kernel_data
{

    void *data;
    off_t size;

} __attribute__((packed));

#define IOCTL_SET_MSG _IOW(MAJOR_NUM, 0, struct __kernel_data)
