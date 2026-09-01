// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "[stealth_net] " fmt

#include "stealth_net.h"
#include <linux/kobject.h>
#include <linux/sysfs.h>

atomic_t stealth_enabled = ATOMIC_INIT(1);
atomic_t stealth_ghost_mode = ATOMIC_INIT(0);
atomic64_t stealth_ghost_drops = ATOMIC64_INIT(0);
atomic64_t stealth_mitm_blocks = ATOMIC64_INIT(0);
static struct kobject *stealth_kobj;

static ssize_t enabled_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n",
	atomic_read(&stealth_enabled));
}

static ssize_t enabled_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	bool val;

	if (!stealth_admin_capable())
		return -EPERM;
	if (kstrtobool(buf, &val))
		return -EINVAL;
	atomic_set(&stealth_enabled, val ? 1 : 0);
	pr_info("Engine state: %s\n",
	val ? "ENABLED" : "DISABLED");
	return count;
}

static struct kobj_attribute enabled_attr =
	__ATTR_RW(enabled);

static ssize_t ghost_mode_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&stealth_ghost_mode));
}

static ssize_t ghost_mode_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned int mode;

	if (!stealth_admin_capable())
		return -EPERM;
	if (kstrtouint(buf, 0, &mode) || mode > 2)
		return -EINVAL;
	atomic_set(&stealth_ghost_mode, mode);
	pr_info("Ghost mode: %s\n",
		 mode == 0 ? "OFF" : mode == 1 ? "BALANCED" : "STRICT");
	return count;
}

static ssize_t ghost_stats_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "drops=%lld mitm_blocks=%lld\n",
		atomic64_read(&stealth_ghost_drops),
		atomic64_read(&stealth_mitm_blocks));
}

static struct kobj_attribute ghost_mode_attr = __ATTR_RW(ghost_mode);
static struct kobj_attribute ghost_stats_attr = __ATTR_RO(ghost_stats);

static struct attribute *stealth_attrs[] = {
	&enabled_attr.attr,
	&ghost_mode_attr.attr,
	&ghost_stats_attr.attr,
	NULL,
};

static const struct attribute_group stealth_attr_group = {
	.attrs = stealth_attrs,
};

int stealth_sysfs_init(void)
{
	int ret;

	stealth_kobj = kobject_create_and_add("stealth_net",
		kernel_kobj);
	if (!stealth_kobj)
		return -ENOMEM;
	ret = sysfs_create_group(stealth_kobj,
		&stealth_attr_group);
	if (ret) {
		kobject_put(stealth_kobj);
		stealth_kobj = NULL;
	}
	return ret;
}

void stealth_sysfs_cleanup(void)
{
	if (!stealth_kobj)
		return;

	sysfs_remove_group(stealth_kobj,
		&stealth_attr_group);
	kobject_put(stealth_kobj);
	stealth_kobj = NULL;
}
