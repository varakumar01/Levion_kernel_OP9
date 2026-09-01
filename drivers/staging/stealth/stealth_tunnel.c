// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "[stealth_net] tunnel: " fmt

#include "stealth_net.h"
#include <linux/capability.h>
#include <linux/if.h>
#include <linux/mutex.h>

enum stealth_tunnel_mode {
	STEALTH_TUNNEL_OFF = 0,
	STEALTH_TUNNEL_AUDIT = 1,
	STEALTH_TUNNEL_ENFORCE = 2,
};

static atomic_t tunnel_mode = ATOMIC_INIT(STEALTH_TUNNEL_OFF);
static atomic_t tunnel_ifindex = ATOMIC_INIT(0);
static atomic_t tunnel_daemon_uid = ATOMIC_INIT(-1);
static atomic64_t tunnel_checked = ATOMIC64_INIT(0);
static atomic64_t tunnel_bypasses = ATOMIC64_INIT(0);
static atomic64_t tunnel_drops = ATOMIC64_INIT(0);
static DEFINE_MUTEX(tunnel_config_lock);
static struct proc_dir_entry *tunnel_proc_entry;

static const char *tunnel_mode_name(int mode)
{
	switch (mode) {
	case STEALTH_TUNNEL_AUDIT:
		return "audit";
	case STEALTH_TUNNEL_ENFORCE:
		return "enforce";
	default:
		return "off";
	}
}

static bool tunnel_skb_uid(const struct sk_buff *skb, uid_t *uid)
{
	struct sock *sk = skb_to_full_sk(skb);

	if (!sk || !sk_fullsock(sk))
		return false;
	*uid = from_kuid_munged(&init_user_ns,
				 sock_net_uid(sock_net(sk), sk));
	return true;
}

bool stealth_tunnel_filter(const struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
	int mode = atomic_read(&tunnel_mode);
	int allowed_ifindex;
	uid_t uid, daemon_uid;

	if (mode == STEALTH_TUNNEL_OFF || !state->out ||
	    (state->out->flags & IFF_LOOPBACK))
		return false;

	atomic64_inc(&tunnel_checked);
	if (!tunnel_skb_uid(skb, &uid))
		goto check_interface;
	daemon_uid = (uid_t)atomic_read(&tunnel_daemon_uid);
	if (uid == daemon_uid)
		return false;

check_interface:
	allowed_ifindex = atomic_read(&tunnel_ifindex);
	if (allowed_ifindex > 0 && state->out->ifindex == allowed_ifindex)
		return false;

	atomic64_inc(&tunnel_bypasses);
	if (mode != STEALTH_TUNNEL_ENFORCE)
		return false;

	atomic64_inc(&tunnel_drops);
	return true;
}

static int tunnel_proc_show(struct seq_file *m, void *v)
{
	int daemon_uid = atomic_read(&tunnel_daemon_uid);

	seq_printf(m, "mode=%s\n", tunnel_mode_name(atomic_read(&tunnel_mode)));
	seq_printf(m, "ifindex=%d\n", atomic_read(&tunnel_ifindex));
	if (daemon_uid < 0)
		seq_puts(m, "daemon_uid=unset\n");
	else
		seq_printf(m, "daemon_uid=%u\n", (uid_t)daemon_uid);
	seq_printf(m, "checked=%lld\n", atomic64_read(&tunnel_checked));
	seq_printf(m, "bypasses=%lld\n", atomic64_read(&tunnel_bypasses));
	seq_printf(m, "drops=%lld\n", atomic64_read(&tunnel_drops));
	seq_puts(m, "# mode off|audit|enforce\n");
	seq_puts(m, "# ifindex <positive-number>\n");
	seq_puts(m, "# daemon_uid <uid>|unset\n");
	seq_puts(m, "# reset_stats\n");
	return 0;
}

static int tunnel_proc_open(struct inode *inode, struct file *file)
{
	if (!stealth_admin_capable())
		return -EPERM;
	return single_open(file, tunnel_proc_show, NULL);
}

static ssize_t tunnel_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *pos)
{
	char kbuf[64];
	char cmd[16], value[24];
	unsigned int number;
	int args, ret = 0;

	if (!stealth_admin_capable())
		return -EPERM;
	if (!count || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	strim(kbuf);

	if (!strcmp(kbuf, "reset_stats")) {
		atomic64_set(&tunnel_checked, 0);
		atomic64_set(&tunnel_bypasses, 0);
		atomic64_set(&tunnel_drops, 0);
		return count;
	}

	args = sscanf(kbuf, "%15s %23s", cmd, value);
	if (args != 2)
		return -EINVAL;

	mutex_lock(&tunnel_config_lock);
	if (!strcmp(cmd, "ifindex")) {
		ret = kstrtouint(value, 10, &number);
		if (!ret && (!number || number > INT_MAX))
			ret = -EINVAL;
		if (!ret)
			atomic_set(&tunnel_ifindex, number);
	} else if (!strcmp(cmd, "daemon_uid")) {
		if (!strcmp(value, "unset")) {
			atomic_set(&tunnel_daemon_uid, -1);
		} else {
			ret = kstrtouint(value, 10, &number);
			if (!ret && number > INT_MAX)
				ret = -ERANGE;
			if (!ret)
				atomic_set(&tunnel_daemon_uid, number);
		}
	} else if (!strcmp(cmd, "mode")) {
		if (!strcmp(value, "off")) {
			atomic_set(&tunnel_mode, STEALTH_TUNNEL_OFF);
		} else if (!strcmp(value, "audit")) {
			atomic_set(&tunnel_mode, STEALTH_TUNNEL_AUDIT);
		} else if (!strcmp(value, "enforce")) {
			if (atomic_read(&tunnel_ifindex) <= 0 ||
			    atomic_read(&tunnel_daemon_uid) < 0)
				ret = -EINVAL;
			else
				atomic_set(&tunnel_mode, STEALTH_TUNNEL_ENFORCE);
		} else {
			ret = -EINVAL;
		}
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&tunnel_config_lock);

	if (ret)
		return ret;
	return count;
}

static const struct proc_ops tunnel_proc_ops = {
	.proc_open = tunnel_proc_open,
	.proc_read = seq_read,
	.proc_write = tunnel_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int stealth_tunnel_init(void)
{
	tunnel_proc_entry = proc_create(PROC_TUNNEL_FILENAME, 0600, NULL,
					&tunnel_proc_ops);
	if (!tunnel_proc_entry)
		return -ENOMEM;
	return 0;
}

void stealth_tunnel_cleanup(void)
{
	/* Disable enforcement before removing its control plane. */
	atomic_set(&tunnel_mode, STEALTH_TUNNEL_OFF);
	if (tunnel_proc_entry) {
		proc_remove(tunnel_proc_entry);
		tunnel_proc_entry = NULL;
	}
}
