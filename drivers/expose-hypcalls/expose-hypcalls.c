/**
 * Expose device_attach, device_detach ioctl to userspace.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/mem_encrypt.h>
#include <linux/arm-smccc.h>
#include "expose_hypcalls_ioctl.h"

struct expose_hypcalls {
	struct device *dev;
	struct cdev cdev;
	struct class *class;
	dev_t id;
};

static int expose_hypcalls_open(struct inode *inode, struct file *filp)
{
	pr_info("expose_hypcalls: device opened\n");
	return 0;
}

static long expose_hypcalls_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct arm_smccc_res smc_res;
	struct ioctl_hyp_perf_nums hyp_perf_nums;
	void __user *argp = (void __user *)arg;
	int ret = 0;

	switch(cmd) {
		case IOCTL_ATTACH_DEVICE:
			arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_ATTACH_DEVICE_FUNC_ID,
			     0, 0, 0, &smc_res);
			if (smc_res.a0 != SMCCC_RET_SUCCESS)
				ret = -EINVAL; 
			break;
		case IOCTL_DETACH_DEVICE:
			arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_DETACH_DEVICE_FUNC_ID,
			     0, 0, 0, &smc_res);
			if (smc_res.a0 != SMCCC_RET_SUCCESS)
				ret = -EINVAL;
			break;
		case IOCTL_GET_HYP_PERF_NUMS:
			arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_GET_HYP_PERF_NUMS_FUNC_ID,
			     0, 0, 0, &smc_res);
			if (smc_res.a0 != SMCCC_RET_SUCCESS) {
				ret = -EINVAL;
			} else {
				hyp_perf_nums.hypcall_handle_start_time = smc_res.a1;
				hyp_perf_nums.hypcall_handle_end_time = smc_res.a2;
				hyp_perf_nums.reset_time = smc_res.a3;

				if (copy_to_user(argp, &hyp_perf_nums, sizeof(hyp_perf_nums)))
					return -EFAULT;
			}
			break;
		default:
			ret = -EINVAL;
			break;
	}
	return ret;
}

static struct file_operations expose_hypcalls_chardev_ops = {
	.open = expose_hypcalls_open,
	.unlocked_ioctl = expose_hypcalls_ioctl,
};

static int __init expose_hypcalls_init(void)
{
	struct expose_hypcalls *expose_hypcalls;
	int ret = 0;

	expose_hypcalls = kzalloc(sizeof(*expose_hypcalls), GFP_KERNEL);
	if (!expose_hypcalls) {
		pr_err("expose_hypcalls: error: kzalloc\n");
		goto out_fail;
	}

	ret = alloc_chrdev_region(&expose_hypcalls->id, 0, 1, "expose-hypcalls");
	if (ret) {
		pr_err("expose_hypcalls: can't get major number\n");
		goto out_fail;
	}

	cdev_init(&expose_hypcalls->cdev, &expose_hypcalls_chardev_ops);
	ret = cdev_add(&expose_hypcalls->cdev, expose_hypcalls->id, 1);
	if (ret) {
		pr_err("expose_hypcalls: error: cdev_add\n");
		goto out_fail;
	}

	expose_hypcalls->class = class_create(THIS_MODULE, "expose-hypcalls");
	if (IS_ERR(expose_hypcalls->class)) {
		pr_err("expose_hypcalls: error: class_create\n");
		goto out_class;
	}

	expose_hypcalls->dev = device_create(
		expose_hypcalls->class,
		NULL,
		expose_hypcalls->id,
		NULL,
		"%s",
		"hypcall");
	if (IS_ERR(expose_hypcalls->dev)) {
		pr_err("expose_hypcalls: error: device_create\n");
		goto out_fail;
	}
	
	pr_info("expose_hypcalls: successfully initialized!\n");

	return 0;

out_class:
	class_unregister(expose_hypcalls->class);
out_fail:
	return ret;
}
module_init(expose_hypcalls_init);

static void __exit expose_hypcalls_exit(void)
{
	/* Not implemented. */
}
module_exit(expose_hypcalls_exit);

MODULE_DESCRIPTION("Expose device_attach, device_detach ioctl to userspace");