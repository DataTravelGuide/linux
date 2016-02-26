/*******************************************************************************
 * Filename:  target_core_configfs.c
 *
 * This file contains ConfigFS logic for the Generic Target Engine project.
 *
 * (c) Copyright 2008-2013 Datera, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * based on configfs Copyright (C) 2005 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/syscalls.h>
#include <linux/configfs.h>
#include <linux/spinlock.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_configfs.h>
#include <target/configfs_macros.h>

#include "target_core_internal.h"
#include "target_core_alua.h"
#include "target_core_pr.h"
#include "target_core_rd.h"
#include "target_core_xcopy.h"

#define TB_CIT_SETUP(_name, _item_ops, _group_ops, _attrs)		\
static void target_core_setup_##_name##_cit(struct se_subsystem_api *sa) \
{									\
	struct target_backend_cits *tbc = &sa->tb_cits;			\
	struct config_item_type *cit = &tbc->tb_##_name##_cit;		\
									\
	cit->ct_item_ops = _item_ops;					\
	cit->ct_group_ops = _group_ops;					\
	cit->ct_attrs = _attrs;						\
	cit->ct_owner = sa->owner;					\
	pr_debug("Setup generic %s\n", __stringify(_name));		\
}

extern struct t10_alua_lu_gp *default_lu_gp;

static LIST_HEAD(g_tf_list);
static DEFINE_MUTEX(g_tf_lock);

struct target_core_configfs_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(void *, char *);
	ssize_t (*store)(void *, const char *, size_t);
};

static struct config_group target_core_hbagroup;
static struct config_group alua_group;
static struct config_group alua_lu_gps_group;

static inline struct se_hba *
item_to_hba(struct config_item *item)
{
	return container_of(to_config_group(item), struct se_hba, hba_group);
}

/*
 * Attributes for /sys/kernel/config/target/
 */
static ssize_t target_core_attr_show(struct config_item *item,
				      struct configfs_attribute *attr,
				      char *page)
{
	return sprintf(page, "Target Engine Core ConfigFS Infrastructure %s"
		" on %s/%s on "UTS_RELEASE"\n", TARGET_CORE_CONFIGFS_VERSION,
		utsname()->sysname, utsname()->machine);
}

static struct configfs_item_operations target_core_fabric_item_ops = {
	.show_attribute = target_core_attr_show,
};

static struct configfs_attribute target_core_item_attr_version = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "version",
	.ca_mode	= S_IRUGO,
};

static struct target_fabric_configfs *target_core_get_fabric(
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!name)
		return NULL;

	mutex_lock(&g_tf_lock);
	list_for_each_entry(tf, &g_tf_list, tf_list) {
		if (!strcmp(tf->tf_name, name)) {
			atomic_inc(&tf->tf_access_cnt);
			mutex_unlock(&g_tf_lock);
			return tf;
		}
	}
	mutex_unlock(&g_tf_lock);

	return NULL;
}

/*
 * Called from struct target_core_group_ops->make_group()
 */
static struct config_group *target_core_register_fabric(
	struct config_group *group,
	const char *name)
{
	struct target_fabric_configfs *tf;
	int ret;

	pr_debug("Target_Core_ConfigFS: REGISTER -> group: %p name:"
			" %s\n", group, name);

	tf = target_core_get_fabric(name);
	if (!tf) {
		pr_err("target_core_register_fabric() trying autoload for %s\n",
			name);

		/*
		 * Below are some hardcoded request_module() calls to automatically
		 * local fabric modules when the following is called:
		 *
		 * mkdir -p /sys/kernel/config/target/$MODULE_NAME
		 *
		 * Note that this does not limit which TCM fabric module can be
		 * registered, but simply provids auto loading logic for modules with
		 * mkdir(2) system calls with known TCM fabric modules.
		 */

		if (!strncmp(name, "iscsi", 5)) {
			/*
			 * Automatically load the LIO Target fabric module when the
			 * following is called:
			 *
			 * mkdir -p $CONFIGFS/target/iscsi
			 */
			ret = request_module("iscsi_target_mod");
			if (ret < 0) {
				pr_err("request_module() failed for"
				       " iscsi_target_mod.ko: %d\n", ret);
				return ERR_PTR(-EINVAL);
			}
		} else if (!strncmp(name, "loopback", 8)) {
			/*
			 * Automatically load the tcm_loop fabric module when the
			 * following is called:
			 *
			 * mkdir -p $CONFIGFS/target/loopback
			 */
			ret = request_module("tcm_loop");
			if (ret < 0) {
				pr_err("request_module() failed for"
				       " tcm_loop.ko: %d\n", ret);
				return ERR_PTR(-EINVAL);
			}
		}

		tf = target_core_get_fabric(name);
	}

	if (!tf) {
		pr_err("target_core_get_fabric() failed for %s\n",
		       name);
		return ERR_PTR(-EINVAL);
	}
	pr_debug("Target_Core_ConfigFS: REGISTER -> Located fabric:"
			" %s\n", tf->tf_name);
	/*
	 * On a successful target_core_get_fabric() look, the returned
	 * struct target_fabric_configfs *tf will contain a usage reference.
	 */
	pr_debug("Target_Core_ConfigFS: REGISTER tfc_wwn_cit -> %p\n",
			&tf->tf_cit_tmpl.tfc_wwn_cit);

	config_group_init_type_name(&tf->tf_group, name, &tf->tf_wwn_cit);

	config_group_init_type_name(&tf->tf_disc_group, "discovery_auth",
			&tf->tf_discovery_cit);
	configfs_add_default_group(&tf->tf_disc_group, &tf->tf_group);

	pr_debug("Target_Core_ConfigFS: REGISTER -> Allocated Fabric:"
			" %s\n", tf->tf_group.cg_item.ci_name);
	/*
	 * Setup tf_ops.tf_subsys pointer for usage with configfs_depend_item()
	 */
	tf->tf_ops.tf_subsys = tf->tf_subsys;
	tf->tf_fabric = &tf->tf_group.cg_item;
	pr_debug("Target_Core_ConfigFS: REGISTER -> Set tf->tf_fabric"
			" for %s\n", name);

	return &tf->tf_group;
}

/*
 * Called from struct target_core_group_ops->drop_item()
 */
static void target_core_deregister_fabric(
	struct config_group *group,
	struct config_item *item)
{
	struct target_fabric_configfs *tf = container_of(
		to_config_group(item), struct target_fabric_configfs, tf_group);

	pr_debug("Target_Core_ConfigFS: DEREGISTER -> Looking up %s in"
		" tf list\n", config_item_name(item));

	pr_debug("Target_Core_ConfigFS: DEREGISTER -> located fabric:"
			" %s\n", tf->tf_name);
	atomic_dec(&tf->tf_access_cnt);

	pr_debug("Target_Core_ConfigFS: DEREGISTER -> Releasing"
			" tf->tf_fabric for %s\n", tf->tf_name);
	tf->tf_fabric = NULL;

	pr_debug("Target_Core_ConfigFS: DEREGISTER -> Releasing ci"
			" %s\n", config_item_name(item));

	configfs_remove_default_groups(&tf->tf_group);
	config_item_put(item);
}

static struct configfs_group_operations target_core_fabric_group_ops = {
	.make_group	= &target_core_register_fabric,
	.drop_item	= &target_core_deregister_fabric,
};

/*
 * All item attributes appearing in /sys/kernel/target/ appear here.
 */
static struct configfs_attribute *target_core_fabric_item_attrs[] = {
	&target_core_item_attr_version,
	NULL,
};

/*
 * Provides Fabrics Groups and Item Attributes for /sys/kernel/config/target/
 */
static struct config_item_type target_core_fabrics_item = {
	.ct_item_ops	= &target_core_fabric_item_ops,
	.ct_group_ops	= &target_core_fabric_group_ops,
	.ct_attrs	= target_core_fabric_item_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem target_core_fabrics = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "target",
			.ci_type = &target_core_fabrics_item,
		},
	},
};

struct configfs_subsystem *target_core_subsystem[] = {
	&target_core_fabrics,
	NULL,
};

/*##############################################################################
// Start functions called by external Target Fabrics Modules
//############################################################################*/

/*
 * First function called by fabric modules to:
 *
 * 1) Allocate a struct target_fabric_configfs and save the *fabric_cit pointer.
 * 2) Add struct target_fabric_configfs to g_tf_list
 * 3) Return struct target_fabric_configfs to fabric module to be passed
 *    into target_fabric_configfs_register().
 */
struct target_fabric_configfs *target_fabric_configfs_init(
	struct module *fabric_mod,
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!(name)) {
		pr_err("Unable to locate passed fabric name\n");
		return ERR_PTR(-EINVAL);
	}
	if (strlen(name) >= TARGET_FABRIC_NAME_SIZE) {
		pr_err("Passed name: %s exceeds TARGET_FABRIC"
			"_NAME_SIZE\n", name);
		return ERR_PTR(-EINVAL);
	}

	tf = kzalloc(sizeof(struct target_fabric_configfs), GFP_KERNEL);
	if (!tf)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&tf->tf_list);
	atomic_set(&tf->tf_access_cnt, 0);
	/*
	 * Setup the default generic struct config_item_type's (cits) in
	 * struct target_fabric_configfs->tf_cit_tmpl
	 */
	tf->tf_module = fabric_mod;
	target_fabric_setup_cits(tf);

	tf->tf_subsys = target_core_subsystem[0];
	snprintf(tf->tf_name, TARGET_FABRIC_NAME_SIZE, "%s", name);

	mutex_lock(&g_tf_lock);
	list_add_tail(&tf->tf_list, &g_tf_list);
	mutex_unlock(&g_tf_lock);

	config_group_init_type_name(&dev->dev_attrib.da_group, "attrib",
			&tb->tb_dev_attrib_cit);
	configfs_add_default_group(&dev->dev_attrib.da_group, &dev->dev_group);

	config_group_init_type_name(&dev->dev_pr_group, "pr",
			&tb->tb_dev_pr_cit);
	configfs_add_default_group(&dev->dev_pr_group, &dev->dev_group);

	config_group_init_type_name(&dev->t10_wwn.t10_wwn_group, "wwn",
			&tb->tb_dev_wwn_cit);
	configfs_add_default_group(&dev->t10_wwn.t10_wwn_group,
			&dev->dev_group);

	config_group_init_type_name(&dev->t10_alua.alua_tg_pt_gps_group,
			"alua", &tb->tb_dev_alua_tg_pt_gps_cit);
	configfs_add_default_group(&dev->t10_alua.alua_tg_pt_gps_group,
			&dev->dev_group);

	config_group_init_type_name(&dev->dev_stat_grps.stat_group,
			"statistics", &tb->tb_dev_stat_cit);
	configfs_add_default_group(&dev->dev_stat_grps.stat_group,
			&dev->dev_group);

	/*
	 * Add core/$HBA/$DEV/alua/default_tg_pt_gp
	 */
	tg_pt_gp = core_alua_allocate_tg_pt_gp(dev, "default_tg_pt_gp", 1);
	if (!tg_pt_gp)
		goto out_free_device;
	dev->t10_alua.default_tg_pt_gp = tg_pt_gp;

	config_group_init_type_name(&tg_pt_gp->tg_pt_gp_group,
			"default_tg_pt_gp", &target_core_alua_tg_pt_gp_cit);
	configfs_add_default_group(&tg_pt_gp->tg_pt_gp_group,
			&dev->t10_alua.alua_tg_pt_gps_group);

	/*
	 * Add core/$HBA/$DEV/statistics/ default groups
	 */
	target_stat_setup_dev_default_groups(dev);

	mutex_unlock(&hba->hba_access_mutex);
	return &dev->dev_group;

out_free_device:
	target_free_device(dev);
out_unlock:
	mutex_unlock(&hba->hba_access_mutex);
	return ERR_PTR(errno);
}

static void target_core_drop_subdev(
	struct config_group *group,
	struct config_item *item)
{
	struct config_group *dev_cg = to_config_group(item);
	struct se_device *dev =
		container_of(dev_cg, struct se_device, dev_group);
	struct se_hba *hba;

	hba = item_to_hba(&dev->se_hba->hba_group.cg_item);

	mutex_lock(&hba->hba_access_mutex);

	configfs_remove_default_groups(&dev->dev_stat_grps.stat_group);
	configfs_remove_default_groups(&dev->t10_alua.alua_tg_pt_gps_group);

	/*
	 * core_alua_free_tg_pt_gp() is called from ->default_tg_pt_gp
	 * directly from target_core_alua_tg_pt_gp_release().
	 */
	dev->t10_alua.default_tg_pt_gp = NULL;

	configfs_remove_default_groups(dev_cg);

	/*
	 * se_dev is released from target_core_dev_item_ops->release()
	 */
	config_item_put(item);
	mutex_unlock(&hba->hba_access_mutex);
}

static struct configfs_group_operations target_core_hba_group_ops = {
	.make_group		= target_core_make_subdev,
	.drop_item		= target_core_drop_subdev,
};

CONFIGFS_EATTR_STRUCT(target_core_hba, se_hba);
#define SE_HBA_ATTR(_name, _mode)				\
static struct target_core_hba_attribute				\
		target_core_hba_##_name =			\
		__CONFIGFS_EATTR(_name, _mode,			\
		target_core_hba_show_attr_##_name,		\
		target_core_hba_store_attr_##_name);

#define SE_HBA_ATTR_RO(_name)					\
static struct target_core_hba_attribute				\
		target_core_hba_##_name =			\
		__CONFIGFS_EATTR_RO(_name,			\
		target_core_hba_show_attr_##_name);

static ssize_t target_core_hba_show_attr_hba_info(
	struct se_hba *hba,
	char *page)
{
	return sprintf(page, "HBA Index: %d plugin: %s version: %s\n",
			hba->hba_id, hba->transport->name,
			TARGET_CORE_CONFIGFS_VERSION);
}

SE_HBA_ATTR_RO(hba_info);

static ssize_t target_core_hba_show_attr_hba_mode(struct se_hba *hba,
				char *page)
{
	int hba_mode = 0;

	if (hba->hba_flags & HBA_FLAGS_PSCSI_MODE)
		hba_mode = 1;

	return sprintf(page, "%d\n", hba_mode);
}

static ssize_t target_core_hba_store_attr_hba_mode(struct se_hba *hba,
				const char *page, size_t count)
{
	struct se_subsystem_api *transport = hba->transport;
	unsigned long mode_flag;
	int ret;

	if (transport->pmode_enable_hba == NULL)
		return -EINVAL;

	ret = kstrtoul(page, 0, &mode_flag);
	if (ret < 0) {
		pr_err("Unable to extract hba mode flag: %d\n", ret);
		return ret;
	}

	if (hba->dev_count) {
		pr_err("Unable to set hba_mode with active devices\n");
		return -EINVAL;
	}

	ret = transport->pmode_enable_hba(hba, mode_flag);
	if (ret < 0)
		return -EINVAL;
	if (ret > 0)
		hba->hba_flags |= HBA_FLAGS_PSCSI_MODE;
	else if (ret == 0)
		hba->hba_flags &= ~HBA_FLAGS_PSCSI_MODE;

	return count;
}

SE_HBA_ATTR(hba_mode, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(target_core_hba, se_hba, hba_group);

static void target_core_hba_release(struct config_item *item)
{
	struct se_hba *hba = container_of(to_config_group(item),
				struct se_hba, hba_group);
	core_delete_hba(hba);
}

static struct configfs_attribute *target_core_hba_attrs[] = {
	&target_core_hba_hba_info.attr,
	&target_core_hba_hba_mode.attr,
	NULL,
};

static struct configfs_item_operations target_core_hba_item_ops = {
	.release		= target_core_hba_release,
	.show_attribute		= target_core_hba_attr_show,
	.store_attribute	= target_core_hba_attr_store,
};

static struct config_item_type target_core_hba_cit = {
	.ct_item_ops		= &target_core_hba_item_ops,
	.ct_group_ops		= &target_core_hba_group_ops,
	.ct_attrs		= target_core_hba_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *target_core_call_addhbatotarget(
	struct config_group *group,
	const char *name)
{
	char *se_plugin_str, *str, *str2;
	struct se_hba *hba;
	char buf[TARGET_CORE_NAME_MAX_LEN];
	unsigned long plugin_dep_id = 0;
	int ret;

	memset(buf, 0, TARGET_CORE_NAME_MAX_LEN);
	if (strlen(name) >= TARGET_CORE_NAME_MAX_LEN) {
		pr_err("Passed *name strlen(): %d exceeds"
			" TARGET_CORE_NAME_MAX_LEN: %d\n", (int)strlen(name),
			TARGET_CORE_NAME_MAX_LEN);
		return ERR_PTR(-ENAMETOOLONG);
	}
	snprintf(buf, TARGET_CORE_NAME_MAX_LEN, "%s", name);

	str = strstr(buf, "_");
	if (!str) {
		pr_err("Unable to locate \"_\" for $SUBSYSTEM_PLUGIN_$HOST_ID\n");
		return ERR_PTR(-EINVAL);
	}
	se_plugin_str = buf;
	/*
	 * Special case for subsystem plugins that have "_" in their names.
	 * Namely rd_direct and rd_mcp..
	 */
	str2 = strstr(str+1, "_");
	if (str2) {
		*str2 = '\0'; /* Terminate for *se_plugin_str */
		str2++; /* Skip to start of plugin dependent ID */
		str = str2;
	} else {
		*str = '\0'; /* Terminate for *se_plugin_str */
		str++; /* Skip to start of plugin dependent ID */
	}

	ret = kstrtoul(str, 0, &plugin_dep_id);
	if (ret < 0) {
		pr_err("kstrtoul() returned %d for"
				" plugin_dep_id\n", ret);
		return ERR_PTR(ret);
	}
	/*
	 * Load up TCM subsystem plugins if they have not already been loaded.
	 */
	transport_subsystem_check_init();

	hba = core_alloc_hba(se_plugin_str, plugin_dep_id, 0);
	if (IS_ERR(hba))
		return ERR_CAST(hba);

	config_group_init_type_name(&hba->hba_group, name,
			&target_core_hba_cit);

	return &hba->hba_group;
}

static void target_core_call_delhbafromtarget(
	struct config_group *group,
	struct config_item *item)
{
	/*
	 * core_delete_hba() is called from target_core_hba_item_ops->release()
	 * -> target_core_hba_release()
	 */
	config_item_put(item);
}

static struct configfs_group_operations target_core_group_ops = {
	.make_group	= target_core_call_addhbatotarget,
	.drop_item	= target_core_call_delhbafromtarget,
};

static struct config_item_type target_core_cit = {
	.ct_item_ops	= NULL,
	.ct_group_ops	= &target_core_group_ops,
	.ct_attrs	= NULL,
	.ct_owner	= THIS_MODULE,
};

/* Stop functions for struct config_item_type target_core_hba_cit */

void target_core_setup_sub_cits(struct se_subsystem_api *sa)
{
	target_core_setup_dev_cit(sa);
	target_core_setup_dev_attrib_cit(sa);
	target_core_setup_dev_pr_cit(sa);
	target_core_setup_dev_wwn_cit(sa);
	target_core_setup_dev_alua_tg_pt_gps_cit(sa);
	target_core_setup_dev_stat_cit(sa);
}
EXPORT_SYMBOL(target_core_setup_sub_cits);

static int __init target_core_init_configfs(void)
{
	struct configfs_subsystem *subsys = &target_core_fabrics;
	struct t10_alua_lu_gp *lu_gp;
	int ret;

	pr_debug("TARGET_CORE[0]: Loading Generic Kernel Storage"
		" Engine: %s on %s/%s on "UTS_RELEASE"\n",
		TARGET_CORE_VERSION, utsname()->sysname, utsname()->machine);

	subsys = target_core_subsystem[0];
	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);

	ret = init_se_kmem_caches();
	if (ret < 0)
		return ret;
	/*
	 * Create $CONFIGFS/target/core default group for HBA <-> Storage Object
	 * and ALUA Logical Unit Group and Target Port Group infrastructure.
	 */
	config_group_init_type_name(&target_core_hbagroup, "core",
			&target_core_cit);
	configfs_add_default_group(&target_core_hbagroup, &subsys->su_group);

	/*
	 * Create ALUA infrastructure under /sys/kernel/config/target/core/alua/
	 */
	config_group_init_type_name(&alua_group, "alua", &target_core_alua_cit);
	configfs_add_default_group(&alua_group, &target_core_hbagroup);

	/*
	 * Add ALUA Logical Unit Group and Target Port Group ConfigFS
	 * groups under /sys/kernel/config/target/core/alua/
	 */
	config_group_init_type_name(&alua_lu_gps_group, "lu_gps",
			&target_core_alua_lu_gps_cit);
	configfs_add_default_group(&alua_lu_gps_group, &alua_group);

	/*
	 * Add core/alua/lu_gps/default_lu_gp
	 */
	lu_gp = core_alua_allocate_lu_gp("default_lu_gp", 1);
	if (IS_ERR(lu_gp)) {
		ret = -ENOMEM;
		goto out_global;
	}

	config_group_init_type_name(&lu_gp->lu_gp_group, "default_lu_gp",
				&target_core_alua_lu_gp_cit);
	configfs_add_default_group(&lu_gp->lu_gp_group, &alua_lu_gps_group);

	default_lu_gp = lu_gp;

	/*
	 * Register the target_core_mod subsystem with configfs.
	 */
	ret = configfs_register_subsystem(subsys);
	if (ret < 0) {
		pr_err("Error %d while registering subsystem %s\n",
			ret, subsys->su_group.cg_item.ci_namebuf);
		goto out_global;
	}
	pr_debug("TARGET_CORE[0]: Initialized ConfigFS Fabric"
		" Infrastructure: "TARGET_CORE_CONFIGFS_VERSION" on %s/%s"
		" on "UTS_RELEASE"\n", utsname()->sysname, utsname()->machine);
	/*
	 * Register built-in RAMDISK subsystem logic for virtual LUN 0
	 */
	ret = rd_module_init();
	if (ret < 0)
		goto out;

	ret = core_dev_setup_virtual_lun0();
	if (ret < 0)
		goto out;

	ret = target_xcopy_setup_pt();
	if (ret < 0)
		goto out;

	return 0;

out:
	configfs_unregister_subsystem(subsys);
	core_dev_release_virtual_lun0();
	rd_module_exit();
out_global:
	if (default_lu_gp) {
		core_alua_free_lu_gp(default_lu_gp);
		default_lu_gp = NULL;
	}
	release_se_kmem_caches();
	return ret;
}

static void __exit target_core_exit_configfs(void)
{
	configfs_remove_default_groups(&alua_lu_gps_group);
	configfs_remove_default_groups(&alua_group);
	configfs_remove_default_groups(&target_core_hbagroup);

	/*
	 * We expect subsys->su_group.default_groups to be released
	 * by configfs subsystem provider logic..
	 */
	configfs_unregister_subsystem(&target_core_fabrics);

	core_alua_free_lu_gp(default_lu_gp);
	default_lu_gp = NULL;

	pr_debug("TARGET_CORE[0]: Released ConfigFS Fabric"
			" Infrastructure\n");

	core_dev_release_virtual_lun0();
	rd_module_exit();
	target_xcopy_release_pt();
	release_se_kmem_caches();
}

MODULE_DESCRIPTION("Target_Core_Mod/ConfigFS");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(target_core_init_configfs);
module_exit(target_core_exit_configfs);
