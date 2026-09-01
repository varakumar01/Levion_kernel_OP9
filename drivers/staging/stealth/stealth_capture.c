// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

#include <linux/capability.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/ktime.h>
#include <linux/poll.h>
#include <linux/wait.h>

#define CAPTURE_PROC "stealth_capture"
#define CAPTURE_CTL_PROC "stealth_capture_ctl"
#define CAPTURE_FIFO_RECORDS 256
#define CAPTURE_LINE_LEN 512
#define CAPTURE_PAYLOAD_LEN 64

struct capture_record {
	u16 len;
	char line[CAPTURE_LINE_LEN];
};

static DECLARE_KFIFO(capture_fifo, struct capture_record,
			     CAPTURE_FIFO_RECORDS);
static DEFINE_SPINLOCK(capture_lock);
static DECLARE_WAIT_QUEUE_HEAD(capture_waitq);
static atomic_t capture_enabled = ATOMIC_INIT(0);
static atomic_t capture_uid = ATOMIC_INIT(-1);
static atomic_t capture_proto = ATOMIC_INIT(0);
static atomic64_t capture_records = ATOMIC64_INIT(0);
static atomic64_t capture_dropped = ATOMIC64_INIT(0);
static char capture_iface[IFNAMSIZ];
static DEFINE_SPINLOCK(capture_config_lock);
static struct proc_dir_entry *capture_entry;
static struct proc_dir_entry *capture_ctl_entry;

static uid_t capture_packet_uid(struct sk_buff *skb)
{
	struct sock *sk = skb_to_full_sk(skb);

	if (!sk || !sk_fullsock(sk))
		return 0;
	return from_kuid_munged(&init_user_ns, sock_i_uid(sk));
}

static bool capture_matches(uid_t uid, u8 protocol, const char *ifname)
{
	char configured[IFNAMSIZ];
	int wanted_uid = atomic_read(&capture_uid);
	int wanted_proto = atomic_read(&capture_proto);

	if (!atomic_read(&capture_enabled))
		return false;
	if (wanted_uid >= 0 && uid != wanted_uid)
		return false;
	if (wanted_proto && protocol != wanted_proto &&
	    !(wanted_proto == IPPROTO_ICMP && protocol == IPPROTO_ICMPV6))
		return false;
	spin_lock_bh(&capture_config_lock);
	strscpy(configured, capture_iface, sizeof(configured));
	spin_unlock_bh(&capture_config_lock);
	return !configured[0] || !strncmp(configured, ifname, IFNAMSIZ);
}

static void capture_push(struct capture_record *record)
{
	spin_lock_bh(&capture_lock);
	if (kfifo_is_full(&capture_fifo)) {
		atomic64_inc(&capture_dropped);
		spin_unlock_bh(&capture_lock);
		return;
	}
	kfifo_in(&capture_fifo, record, 1);
	atomic64_inc(&capture_records);
	spin_unlock_bh(&capture_lock);
	wake_up_interruptible(&capture_waitq);
}

void stealth_capture_packet(struct sk_buff *skb,
			    const struct nf_hook_state *state, int trans_off,
			    u8 protocol, bool outbound, const char *verdict,
			    const char *reason)
{
	struct capture_record record = { };
	struct tcphdr _th, *th;
	struct udphdr _uh, *uh;
	struct iphdr _iph, *iph;
	struct ipv6hdr _ip6h, *ip6h;
	const struct net_device *dev = outbound ? state->out : state->in;
	const char *ifname = dev ? dev->name : "-";
	uid_t uid = capture_packet_uid(skb);
	u16 sport = 0, dport = 0;
	u8 flags = 0;
	u8 payload[CAPTURE_PAYLOAD_LEN];
	int payload_off = trans_off, payload_len = 0;
	u64 now;

	if (!capture_matches(uid, protocol, ifname))
		return;
	if (protocol == IPPROTO_TCP) {
		th = skb_header_pointer(skb, trans_off, sizeof(_th), &_th);
		if (th) {
			sport = ntohs(th->source); dport = ntohs(th->dest);
			flags = *((u8 *)th + 13);
			payload_off = trans_off + th->doff * 4;
		}
	} else if (protocol == IPPROTO_UDP) {
		uh = skb_header_pointer(skb, trans_off, sizeof(_uh), &_uh);
		if (uh) { sport = ntohs(uh->source); dport = ntohs(uh->dest); payload_off = trans_off + sizeof(*uh); }
	}
	if (payload_off >= 0 && payload_off < skb->len) {
		payload_len = min_t(int, skb->len - payload_off, CAPTURE_PAYLOAD_LEN);
		if (skb_copy_bits(skb, payload_off, payload, payload_len))
			payload_len = 0;
	}
	now = ktime_get_boottime_ns();
	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (iph && iph->version == 4) {
		record.len = scnprintf(record.line, sizeof(record.line),
			"%llu UID=%u %s IF=%s IPv4 %pI4:%u -> %pI4:%u PROTO=%u FLAGS=0x%02x LEN=%u %s REASON=%s PAYLOAD=%*phN\n",
			now, uid, outbound ? "OUT" : "IN", ifname,
			&iph->saddr, sport, &iph->daddr, dport, protocol, flags,
			skb->len, verdict, reason, payload_len, payload);
		capture_push(&record);
		return;
	}
	ip6h = skb_header_pointer(skb, 0, sizeof(_ip6h), &_ip6h);
	if (ip6h && ip6h->version == 6) {
		record.len = scnprintf(record.line, sizeof(record.line),
			"%llu UID=%u %s IF=%s IPv6 %pI6c:%u -> %pI6c:%u PROTO=%u FLAGS=0x%02x LEN=%u %s REASON=%s PAYLOAD=%*phN\n",
			now, uid, outbound ? "OUT" : "IN", ifname,
			&ip6h->saddr, sport, &ip6h->daddr, dport, protocol, flags,
			skb->len, verdict, reason, payload_len, payload);
		capture_push(&record);
	}
}

static ssize_t capture_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct capture_record record;
	int ret;

	if (!stealth_admin_capable())
		return -EPERM;
	if (count < CAPTURE_LINE_LEN)
		return -EMSGSIZE;
	if (file->f_flags & O_NONBLOCK) {
		if (kfifo_is_empty(&capture_fifo))
			return -EAGAIN;
	} else {
		ret = wait_event_interruptible(capture_waitq,
					       !kfifo_is_empty(&capture_fifo) ||
					       !atomic_read(&capture_enabled));
		if (ret)
			return ret;
		if (kfifo_is_empty(&capture_fifo) &&
		    !atomic_read(&capture_enabled))
			return 0;
	}
	spin_lock_bh(&capture_lock);
	if (!kfifo_out(&capture_fifo, &record, 1)) {
		spin_unlock_bh(&capture_lock);
		return -EAGAIN;
	}
	spin_unlock_bh(&capture_lock);
	if (copy_to_user(buf, record.line, record.len))
		return -EFAULT;
	return record.len;
}

static __poll_t capture_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &capture_waitq, wait);
	return kfifo_is_empty(&capture_fifo) ? 0 : EPOLLIN | EPOLLRDNORM;
}

static int capture_open(struct inode *inode, struct file *file)
{
	if (!stealth_admin_capable())
		return -EPERM;
	return nonseekable_open(inode, file);
}

static const struct proc_ops capture_ops = {
	.proc_open = capture_open,
	.proc_read = capture_read,
	.proc_poll = capture_poll,
	.proc_lseek = noop_llseek,
};

static int capture_ctl_show(struct seq_file *m, void *v)
{
	char iface[IFNAMSIZ];

	spin_lock_bh(&capture_config_lock);
	strscpy(iface, capture_iface, sizeof(iface));
	spin_unlock_bh(&capture_config_lock);
	seq_printf(m, "enabled: %d\nuid: %d\nprotocol: %d\ninterface: %s\n",
		atomic_read(&capture_enabled), atomic_read(&capture_uid),
		atomic_read(&capture_proto), iface[0] ? iface : "all");
	seq_printf(m, "records: %lld\ndropped: %lld\nqueued: %u\n",
		atomic64_read(&capture_records), atomic64_read(&capture_dropped),
		kfifo_len(&capture_fifo));
	return 0;
}

static int capture_ctl_open(struct inode *inode, struct file *file)
{
	if (!stealth_admin_capable())
		return -EPERM;
	return single_open(file, capture_ctl_show, NULL);
}

static ssize_t capture_ctl_write(struct file *file, const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	char buf[64], cmd[16], value[IFNAMSIZ];
	int val;

	if (!stealth_admin_capable()) return -EPERM;
	if (!count || count >= sizeof(buf)) return -EINVAL;
	if (copy_from_user(buf, ubuf, count)) return -EFAULT;
	buf[count] = '\0'; strim(buf);
	if (!strcmp(buf, "clear")) {
		spin_lock_bh(&capture_lock);
		kfifo_reset(&capture_fifo);
		atomic64_set(&capture_records, 0);
		atomic64_set(&capture_dropped, 0);
		spin_unlock_bh(&capture_lock); return count;
	}
	if (sscanf(buf, "%15s %15s", cmd, value) != 2) return -EINVAL;
	if (!strcmp(cmd, "enable")) {
		if (kstrtoint(value, 0, &val) || val < 0 || val > 1) return -EINVAL;
		atomic_set(&capture_enabled, val); return count;
	}
	if (!strcmp(cmd, "uid")) {
		if (!strcmp(value, "all")) val = -1;
		else if (kstrtoint(value, 0, &val) || val < 0) return -EINVAL;
		atomic_set(&capture_uid, val); return count;
	}
	if (!strcmp(cmd, "protocol")) {
		if (!strcmp(value, "all")) val = 0;
		else if (!strcmp(value, "tcp")) val = IPPROTO_TCP;
		else if (!strcmp(value, "udp")) val = IPPROTO_UDP;
		else if (!strcmp(value, "icmp")) val = IPPROTO_ICMP;
		else return -EINVAL;
		atomic_set(&capture_proto, val); return count;
	}
	if (!strcmp(cmd, "iface")) {
		spin_lock_bh(&capture_config_lock);
		if (!strcmp(value, "all")) capture_iface[0] = '\0';
		else strscpy(capture_iface, value, sizeof(capture_iface));
		spin_unlock_bh(&capture_config_lock); return count;
	}
	return -EINVAL;
}

static const struct proc_ops capture_ctl_ops = {
	.proc_open = capture_ctl_open, .proc_read = seq_read,
	.proc_write = capture_ctl_write, .proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int stealth_capture_init(void)
{
	INIT_KFIFO(capture_fifo);
	capture_entry = proc_create(CAPTURE_PROC, 0400, NULL, &capture_ops);
	if (!capture_entry) return -ENOMEM;
	capture_ctl_entry = proc_create(CAPTURE_CTL_PROC, 0600, NULL,
					&capture_ctl_ops);
	if (!capture_ctl_entry) {
		proc_remove(capture_entry); capture_entry = NULL; return -ENOMEM;
	}
	return 0;
}

void stealth_capture_cleanup(void)
{
	atomic_set(&capture_enabled, 0);
	wake_up_interruptible(&capture_waitq);
	if (capture_ctl_entry) proc_remove(capture_ctl_entry);
	if (capture_entry) proc_remove(capture_entry);
	capture_ctl_entry = NULL; capture_entry = NULL;
}
