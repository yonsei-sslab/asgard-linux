/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_EXPOSE_HYPCALLS_IOCTL_H
#define __LINUX_EXPOSE_HYPCALLS_IOCTL_H

#include <linux/ioctl.h>

#define IOCTL_ATTACH_DEVICE _IO('w', 0x00)
#define IOCTL_DETACH_DEVICE _IO('w', 0x01)
#define IOCTL_GET_HYP_PERF_NUMS _IOR('w', 0x02, struct ioctl_hyp_perf_nums)

struct ioctl_hyp_perf_nums {
	__u64 hypcall_handle_start_time;
    __u64 hypcall_handle_end_time;
    __u64 reset_time;
};

#endif