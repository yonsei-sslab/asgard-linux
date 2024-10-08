/**
 * I/O memory shared between host and guest.
 * Could be used to share inference input and output.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/mem_encrypt.h>

struct io_mem {
	struct device *dev;
	struct cdev cdev;
	struct class *class;
	dev_t id;
	phys_addr_t io_mem_phys_base;
};

static int io_mem_open(struct inode *inode, struct file *filp)
{
	struct io_mem *io_mem = container_of(inode->i_cdev, struct io_mem, cdev);

	filp->private_data = io_mem;

	return 0;
}

static int io_mem_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct io_mem *io_mem = filep->private_data;

	return remap_pfn_range(vma,
				vma->vm_start,
				io_mem->io_mem_phys_base >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
}

static struct file_operations io_mem_chardev_ops = {
	.open = io_mem_open,
	.mmap = io_mem_mmap,
};

static int __init io_mem_init(void)
{
	struct io_mem *io_mem;
	struct device_node *node;
	struct resource res;
	int ret = 0;

	/**
	 * Keep in mind that fdt.c might do its own thing to the reserved memory
	 * region in the future updates.
	 */

	node = of_find_node_by_name(NULL, "inference_io_reserved");
		if (!node) {
		pr_err("io_mem: memory-region entry not found!\n");
		goto out_fail;
	}

	ret = of_address_to_resource(node, 0, &res);
	if (ret) {
		pr_err("io_mem: failed to setup memory: ret = %d\n", ret);
		of_node_put(node);
		goto out_fail;
	}

	io_mem = kzalloc(sizeof(*io_mem), GFP_KERNEL);
	if (!io_mem) {
		pr_err("io_mem: error: kzalloc\n");
		goto out_fail;
	}

	io_mem->io_mem_phys_base = res.start;
	ret = alloc_chrdev_region(&io_mem->id, 0, 1, "io-mem");
	if (ret) {
		pr_err("io_mem: can't get major number\n");
		goto out_fail;
	}

	cdev_init(&io_mem->cdev, &io_mem_chardev_ops);
	ret = cdev_add(&io_mem->cdev, io_mem->id, 1);
	if (ret) {
		pr_err("io_mem: error: cdev_add\n");
		goto out_fail;
	}

	io_mem->class = class_create(THIS_MODULE, "io-mem");
	if (IS_ERR(io_mem->class)) {
		pr_err("io_mem: error: class_create\n");
		goto out_class;
	}

	io_mem->dev = device_create(
		io_mem->class,
		NULL,
		io_mem->id,
		NULL,
		"%s",
		"io-mem");
	if (IS_ERR(io_mem->dev)) {
		pr_err("io_mem: error: device_create\n");
		goto out_fail;
	}

	ret = set_memory_decrypted(
		(unsigned long) phys_to_virt(io_mem->io_mem_phys_base),
		resource_size(&res) >> PAGE_SHIFT);
	if (ret) {
		pr_err("io_mem: failed to share memory with the host: ret = %d\n", ret);
		goto out_fail;
	}
	
	pr_info("io_mem: successfully initialized!\n");

	return 0;

out_class:
	class_unregister(io_mem->class);
out_fail:
	return ret;
}
module_init(io_mem_init);

static void __exit io_mem_exit(void)
{
	/* Not implemented. */
}
module_exit(io_mem_exit);

MODULE_DESCRIPTION("I/O memory shared between host and guest");
