// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for Rockchip
 *
 * Module Authors:	Simon Xue <xxm@rock-chips.com>
 *			Daniel Kurtz <djkurtz@chromium.org>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <soc/rockchip/rockchip_iommu.h>

bool rockchip_iommu_is_enabled(struct device *dev)
{
	return true;
}
EXPORT_SYMBOL(rockchip_iommu_is_enabled);

static const struct of_device_id rk_iommu_dt_ids[] = {
	{
		.compatible = "rockchip,iommu-v2",
	},
	{ /* sentinel */ }
};

static int rk_iommu_probe(struct platform_device *pdev)
{
	return 0;
}

static void rk_iommu_shutdown(struct platform_device *pdev) {}

static struct platform_driver rk_iommu_driver = {
	.probe = rk_iommu_probe,
	.shutdown = rk_iommu_shutdown,
	.driver = {
		   .name = "rk_iommu",
		   .of_match_table = rk_iommu_dt_ids,
		   .suppress_bind_attrs = true,
	},
};

static int __init rk_iommu_init(void)
{
	return platform_driver_register(&rk_iommu_driver);
}
subsys_initcall(rk_iommu_init);

MODULE_DESCRIPTION("IOMMU API for Rockchip");
MODULE_AUTHOR("Simon Xue <xxm@rock-chips.com> and Daniel Kurtz <djkurtz@chromium.org>");
MODULE_ALIAS("platform:rockchip-iommu");
MODULE_LICENSE("GPL v2");
