// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_events_entry;
static DECLARE_WAIT_QUEUE_HEAD(events_waitq);

void stealth_notify_event(void)
{
	wake_up_interruptible(&events_waitq);
}

static void format_rule_ip(char *buf, size_t sz, struct dns_rule_node *entry)
{
	const char *fmt = (entry->ip_version == 6) ? "%pI6c" : "%pI4";
	void *ip_ptr = (entry->ip_version == 6) ? (void *)&entry->spoofed_ip.v6 : (void *)&entry->spoofed_ip.v4;
	if (entry->action == ACTION_SPOOF) { snprintf(buf, sz, fmt, ip_ptr); return; }
	strscpy(buf, "-", sz);
}

static int stealth_proc_show(struct seq_file *m, void *v)
{
	struct rule_snapshot {
		char domain[MAX_DOMAIN_WIRE_LEN + 1];
		union stealth_ip_addr spoofed_ip;
		uid_t target_uid;
		enum rule_action action;
		u8 ip_version;
		s64 hits;
	};
	char ip_buf[48];
	size_t ip_buf_sz = sizeof(ip_buf);
	struct dns_rule_node *entry;
	struct rule_snapshot *snapshot = NULL;
	size_t count = 0, copied = 0, i;
	int bkt;

	seq_printf(m, "Total hooked packets: %d\n", atomic_read(&total_packets_hooked));
	seq_printf(m, "Total DNS parsed: %d\n", atomic_read(&total_dns_detected));
	seq_printf(m, "Audit all UIDs: %s\n", audit_all_enabled() ? "on" : "off");
	seq_puts(m, "# UID\tACTION\tHITS\tTARGET_IP\tDOMAIN\n");
	spin_lock_bh(&rules_lock);
	hash_for_each(dns_rules_hash, bkt, entry, hnode)
		count++;
	spin_unlock_bh(&rules_lock);

	if (count) {
		snapshot = kvcalloc(count, sizeof(*snapshot), GFP_KERNEL);
		if (!snapshot)
			return -ENOMEM;
	}

	spin_lock_bh(&rules_lock);
	hash_for_each(dns_rules_hash, bkt, entry, hnode) {
		if (copied == count)
			break;
		strscpy(snapshot[copied].domain, entry->domain,
			sizeof(snapshot[copied].domain));
		snapshot[copied].spoofed_ip = entry->spoofed_ip;
		snapshot[copied].target_uid = entry->target_uid;
		snapshot[copied].action = entry->action;
		snapshot[copied].ip_version = entry->ip_version;
		snapshot[copied].hits = atomic64_read(&entry->hit_count);
		copied++;
	}
	spin_unlock_bh(&rules_lock);

	for (i = 0; i < copied; i++) {
		struct dns_rule_node display = {
			.spoofed_ip = snapshot[i].spoofed_ip,
			.ip_version = snapshot[i].ip_version,
			.action = snapshot[i].action,
		};

		format_rule_ip(ip_buf, ip_buf_sz, &display);
		seq_printf(m, "%u\t%-6s\t%lld\t%-15s\t%s\n",
			snapshot[i].target_uid, action_to_str(snapshot[i].action),
			snapshot[i].hits, ip_buf, snapshot[i].domain);
	}
	kvfree(snapshot);
	return 0;
}

static int stealth_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stealth_proc_show, NULL);
}

static ssize_t stealth_events_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char line[MAX_DOMAIN_WIRE_LEN + 64];
	size_t line_sz = sizeof(line);
	struct stealth_event ev;
	int len, ret;

	if (!count) return 0;
	if (count < line_sz) return -EINVAL;

	if (file->f_flags & O_NONBLOCK) {
		if (!pop_event(&ev)) return -EAGAIN;
		goto format_event;
	}
	for (;;) {
		ret = wait_event_interruptible(events_waitq, events_fifo_has_data());
		if (ret) return -ERESTARTSYS;
		if (pop_event(&ev)) break;
	}
format_event:
	len = snprintf(line, line_sz, "UID:%u | ACT:%s | IPv%d | DOMAIN:%s\n",
		       ev.uid, action_to_str(ev.action), ev.ip_ver, ev.domain);
	if (copy_to_user(buf, line, len)) return -EFAULT;

	return len;
}

static __poll_t stealth_events_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &events_waitq, wait);

	if (events_fifo_has_data()) return EPOLLIN | EPOLLRDNORM;
	return 0;
}

static int parse_action_str(const char *act_str, enum rule_action *act)
{
	if (!strcmp(act_str, "audit")) { *act = ACTION_AUDIT; return 0; }
	if (!strcmp(act_str, "drop"))  { *act = ACTION_DROP;  return 0; }
	if (!strcmp(act_str, "block")) { *act = ACTION_BLOCK; return 0; }
	if (!strcmp(act_str, "spoof")) { *act = ACTION_SPOOF; return 0; }
	return -EINVAL;
}

static int parse_ip_address(const char *ip_str, u8 *ver, __be32 *v4, struct in6_addr *v6)
{
	if (in4_pton(ip_str, -1, (u8 *)v4, -1, NULL) > 0) { *ver = 4; return 0; }
	if (in6_pton(ip_str, -1, (u8 *)v6, -1, NULL) > 0) { *ver = 6; return 0; }
	return -EINVAL;
}

static ssize_t stealth_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	char kbuf[256];
	char cmd[16] = {0}, arg1[MAX_DOMAIN_WIRE_LEN + 1] = {0}, arg2[64] = {0}, arg3[16] = {0};
	char act_str[16] = {0}, dom[MAX_DOMAIN_WIRE_LEN + 1] = {0}, ip[64] = {0};
	struct in6_addr v6_ip;
	size_t kbuf_sz = sizeof(kbuf), len;
	unsigned int uid = 0;
	enum rule_action act;
	__be32 v4_ip = 0;
	u8 ip_ver = 0;
	int args, parsed, ret;

	if (!capable(CAP_NET_ADMIN)) return -EPERM;
	if (count == 0 || count >= kbuf_sz) return -EINVAL;
	if (copy_from_user(kbuf, buf, count)) return -EFAULT;
	kbuf[count] = '\0';
	len = strlen(kbuf);
	while (len > 0 && (kbuf[len - 1] == '\n' || kbuf[len - 1] == '\r' || kbuf[len - 1] == ' ')) {
		kbuf[len - 1] = '\0';
		len--;
	}
	if (!strcmp(kbuf, "flush")) {
		rules_flush();
		events_fifo_flush();
		return count;
	}
	if (!strcmp(kbuf, "all") || !strcmp(kbuf, "all on") ||
	    !strcmp(kbuf, "all 1") || !strcmp(kbuf, "all enable")) {
		audit_all_set(true);
		return count;
	}
	if (!strcmp(kbuf, "all off") || !strcmp(kbuf, "all 0") ||
	    !strcmp(kbuf, "all disable") || !strcmp(kbuf, "noall")) {
		audit_all_set(false);
		events_fifo_flush();
		return count;
	}
	if (kbuf[0] == '+') {
		parsed = sscanf(kbuf, "+ %u %15s %255s %63s", &uid, act_str, dom, ip);
		if (parsed < 3) return -EINVAL;
		if (parse_action_str(act_str, &act)) return -EINVAL;

		if (act == ACTION_SPOOF) {
			if (parsed < 4) return -EINVAL;
			if (parse_ip_address(ip, &ip_ver, &v4_ip, &v6_ip)) return -EINVAL;
		}
		ret = rule_add_or_update(uid, act, dom, ip_ver, v4_ip,
			(ip_ver == 6) ? &v6_ip : NULL);
		if (ret)
			return ret;
		return count;
	}
	if (kbuf[0] == '-') {
		if (sscanf(kbuf, "- %u %255s", &uid, dom) != 2) return -EINVAL;
		rule_delete(uid, dom);
		return count;
	}
	args = sscanf(kbuf, "%15s %255s %63s %15s", cmd, arg1, arg2, arg3);
	if (args < 2) return -EINVAL;
	if (!strcmp(cmd, "unblock") || !strcmp(cmd, "del") || !strcmp(cmd, "rm")) {
		if (args >= 3 && kstrtouint(arg2, 10, &uid)) return -EINVAL;
		rule_delete(uid, arg1);
		return count;
	}
	if (!strcmp(cmd, "block") || !strcmp(cmd, "drop") || !strcmp(cmd, "audit")) {
		if (parse_action_str(cmd, &act)) return -EINVAL;
		if (args >= 3 && kstrtouint(arg2, 10, &uid)) return -EINVAL;
		ret = rule_add_or_update(uid, act, arg1, 0, 0, NULL);
		if (ret) return ret;
		return count;
	}
	if (!strcmp(cmd, "spoof")) {
		if (args < 3) return -EINVAL;
		if (parse_ip_address(arg2, &ip_ver, &v4_ip, &v6_ip)) return -EINVAL;
		if (args >= 4 && kstrtouint(arg3, 10, &uid)) return -EINVAL;
		ret = rule_add_or_update(uid, ACTION_SPOOF, arg1, ip_ver, v4_ip,
			(ip_ver == 6) ? &v6_ip : NULL);
		if (ret)
			return ret;
		return count;
	}
	return -EINVAL;
}

static const struct proc_ops stealth_proc_ops = {
	.proc_open    = stealth_proc_open,
	.proc_read    = seq_read,
	.proc_write   = stealth_proc_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops stealth_events_ops = {
	.proc_read    = stealth_events_read,
	.proc_poll    = stealth_events_poll,
	.proc_lseek   = noop_llseek,
};

int stealth_proc_init(void)
{
	proc_entry = proc_create(PROC_FILENAME, 0660, NULL, &stealth_proc_ops);
	if (!proc_entry) return -ENOMEM;
	proc_events_entry = proc_create(PROC_EVENTS_FILENAME, 0440, NULL, &stealth_events_ops);
	if (!proc_events_entry) {
		proc_remove(proc_entry);
		return -ENOMEM;
	}
	return 0;
}

void stealth_proc_cleanup(void)
{
	if (proc_events_entry) proc_remove(proc_events_entry);
	if (proc_entry) proc_remove(proc_entry);
}
