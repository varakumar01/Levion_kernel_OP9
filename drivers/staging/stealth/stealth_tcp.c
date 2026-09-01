// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

#include <linux/capability.h>
#include <linux/sock_diag.h>
#include <linux/workqueue.h>
#include <net/tcp.h>

#define TCP_PROC_FILENAME "stealth_tcp"
#define TCP_CA_LIST_LEN 256

static struct proc_dir_entry *tcp_proc_entry;
static atomic_t hardening = ATOMIC_INIT(0);
static atomic_t mss_clamp = ATOMIC_INIT(0);
static atomic_t rst_guard = ATOMIC_INIT(0);
static atomic_t syn_rate_limit = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(syn_rate_lock);
static unsigned long syn_rate_window;
static u32 syn_rate_count;
static atomic64_t packets = ATOMIC64_INIT(0);
static atomic64_t drops = ATOMIC64_INIT(0);
static atomic64_t invalid_drops = ATOMIC64_INIT(0);
static atomic64_t syn_rate_drops = ATOMIC64_INIT(0);
static atomic64_t rst_drops = ATOMIC64_INIT(0);
static atomic64_t retransmits = ATOMIC64_INIT(0);
static atomic64_t packet_loss = ATOMIC64_INIT(0);
static atomic64_t syn_failures = ATOMIC64_INIT(0);
static atomic_t active = ATOMIC_INIT(0);
static atomic64_t resets = ATOMIC64_INIT(0);
static atomic64_t closed = ATOMIC64_INIT(0);
static atomic64_t rtt_samples = ATOMIC64_INIT(0);
static atomic64_t rtt_total = ATOMIC64_INIT(0);
static atomic_t rtt_last = ATOMIC_INIT(0);

struct tcp_socket_sample {
	struct hlist_node node;
	u64 cookie;
	uid_t uid;
	int ifindex;
	u32 retrans;
	u32 lost;
	bool established;
	bool syn_seen;
	unsigned long updated;
};

#define TCP_SAMPLE_BITS 8
#define TCP_SAMPLE_MAX 512
static DEFINE_HASHTABLE(socket_samples, TCP_SAMPLE_BITS);
static DEFINE_SPINLOCK(sample_lock);
static atomic_t sample_count = ATOMIC_INIT(0);
static struct delayed_work sample_gc_work;

static void sample_gc(struct work_struct *work)
{
	struct tcp_socket_sample *e;
	struct hlist_node *tmp;
	unsigned long now = jiffies;
	int bkt;

	spin_lock_bh(&sample_lock);
	hash_for_each_safe(socket_samples, bkt, tmp, e, node) {
		if (!time_after(now, e->updated +
			(e->syn_seen && !e->established ? 15 * HZ : 120 * HZ)))
			continue;
		if (e->syn_seen && !e->established)
			atomic64_inc(&syn_failures);
		if (e->established)
			atomic_dec_if_positive(&active);
		hash_del(&e->node); kfree(e); atomic_dec(&sample_count);
	}
	spin_unlock_bh(&sample_lock);
	schedule_delayed_work(&sample_gc_work, 30 * HZ);
}

static void sample_socket(struct sk_buff *skb, const struct nf_hook_state *state,
			  const struct tcphdr *th, bool outbound)
{
	struct sock *sk = skb_to_full_sk(skb);
	struct tcp_socket_sample *e;
	struct tcp_sock *tp;
	u64 cookie;
	u32 rtt, retrans, lost;
	int ifindex = outbound && state->out ? state->out->ifindex :
		state->in ? state->in->ifindex : 0;
	uid_t uid;

	if (!sk || !sk_fullsock(sk) || sk->sk_protocol != IPPROTO_TCP)
		return;
	uid = from_kuid_munged(&init_user_ns, sock_i_uid(sk));
	cookie = sock_gen_cookie(sk);
	tp = tcp_sk(sk);
	rtt = READ_ONCE(tp->srtt_us) >> 3;
	retrans = READ_ONCE(tp->total_retrans);
	lost = READ_ONCE(tp->lost_out);
	spin_lock_bh(&sample_lock);
	hash_for_each_possible(socket_samples, e, node, cookie) {
		if (e->cookie != cookie)
			continue;
		if (retrans > e->retrans)
			atomic64_add(retrans - e->retrans, &retransmits);
		if (lost > e->lost)
			atomic64_add(lost - e->lost, &packet_loss);
		e->retrans = retrans; e->lost = lost; e->updated = jiffies;
		if (!e->established && sk->sk_state == TCP_ESTABLISHED) {
			e->established = true; atomic_inc(&active);
		}
		if (e->established && (th->fin || th->rst)) {
			e->established = false; atomic_dec_if_positive(&active);
			atomic64_inc(&closed);
		}
		goto out;
	}
	if (atomic_read(&sample_count) >= TCP_SAMPLE_MAX)
		goto out;
	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		goto out;
	e->cookie = cookie; e->uid = uid; e->ifindex = ifindex;
	e->retrans = retrans; e->lost = lost; e->updated = jiffies;
	e->syn_seen = th->syn && !th->ack;
	e->established = sk->sk_state == TCP_ESTABLISHED && !th->fin && !th->rst;
	if (e->established) atomic_inc(&active);
	hash_add(socket_samples, &e->node, cookie); atomic_inc(&sample_count);
out:
	spin_unlock_bh(&sample_lock);
	if (rtt) {
		atomic_set(&rtt_last, rtt); atomic64_add(rtt, &rtt_total);
		atomic64_inc(&rtt_samples);
	}
}

static bool invalid_flags(const struct tcphdr *th)
{
	return (th->syn && th->fin) || (th->syn && th->rst) ||
	       (th->fin && th->rst) ||
	       (!th->syn && !th->ack && !th->fin && !th->rst &&
		!th->psh && !th->urg);
}

static void clamp_syn_mss(struct sk_buff *skb, struct tcphdr *th, u16 clamp)
{
	u8 *opt = (u8 *)(th + 1);
	int len = th->doff * 4 - sizeof(*th), i = 0;
	__be16 old, new = htons(clamp);

	while (i < len) {
		u8 kind = opt[i], olen;

		if (kind == TCPOPT_EOL)
			return;
		if (kind == TCPOPT_NOP) {
			i++;
			continue;
		}
		if (i + 1 >= len || (olen = opt[i + 1]) < 2 || i + olen > len)
			return;
		if (kind == TCPOPT_MSS && olen == TCPOLEN_MSS) {
			memcpy(&old, &opt[i + 2], sizeof(old));
			if (ntohs(old) > clamp) {
				inet_proto_csum_replace2(&th->check, skb, old, new, false);
				memcpy(&opt[i + 2], &new, sizeof(new));
			}
			return;
		}
		i += olen;
	}
}

bool stealth_tcp_filter(struct sk_buff *skb, const struct nf_hook_state *state,
			int off, u8 protocol, bool outbound)
{
	struct tcphdr *th;
	int hlen;
	u16 clamp;
	unsigned int limit;

	if (protocol != IPPROTO_TCP)
		return false;
	atomic64_inc(&packets);
	if (off < 0 || off + sizeof(*th) > skb->len ||
	    !pskb_may_pull(skb, off + sizeof(*th)))
		return false;
	th = (struct tcphdr *)(skb->data + off);
	if (th->doff < 5 || off + th->doff * 4 > skb->len) {
		if (atomic_read(&hardening))
			goto drop;
		return false;
	}
	if (!outbound && atomic_read(&hardening) && invalid_flags(th)) {
		atomic64_inc(&invalid_drops);
		goto drop;
	}
	if (!outbound && atomic_read(&hardening)) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

		if (ct && ctinfo == IP_CT_UNTRACKED) {
			atomic64_inc(&invalid_drops);
			goto drop;
		}
	}
	limit = atomic_read(&syn_rate_limit);
	if (!outbound && th->syn && !th->ack && limit) {
		spin_lock_bh(&syn_rate_lock);
		if (time_after(jiffies, syn_rate_window + HZ)) {
			syn_rate_window = jiffies;
			syn_rate_count = 0;
		}
		syn_rate_count++;
		if (syn_rate_count > limit) {
			spin_unlock_bh(&syn_rate_lock);
			atomic64_inc(&syn_rate_drops);
			goto drop;
		}
		spin_unlock_bh(&syn_rate_lock);
	}
	if (!outbound && th->rst && atomic_read(&rst_guard)) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

		if (!ct || (ctinfo != IP_CT_ESTABLISHED_REPLY &&
			    ctinfo != IP_CT_ESTABLISHED)) {
			atomic64_inc(&rst_drops);
			goto drop;
		}
	}
	if (th->rst) atomic64_inc(&resets);
	sample_socket(skb, state, th, outbound);
	clamp = atomic_read(&mss_clamp);
	if (outbound && clamp && th->syn && state->out &&
	    (!strncmp(state->out->name, "wg", 2) ||
	     !strncmp(state->out->name, "tun", 3))) {
		hlen = th->doff * 4;
		if (!skb_ensure_writable(skb, off + hlen)) {
			th = (struct tcphdr *)(skb->data + off);
			clamp_syn_mss(skb, th, clamp);
		}
	}
	return false;
drop:
	atomic64_inc(&drops);
	return true;
}

static int tcp_show(struct seq_file *m, void *v)
{
	char active_ca[TCP_CA_NAME_MAX], available[TCP_CA_LIST_LEN];
	struct tcp_socket_sample *e, *snapshot;
	int bkt, copied = 0, i;
	s64 n = atomic64_read(&rtt_samples);

	snapshot = kvcalloc(TCP_SAMPLE_MAX, sizeof(*snapshot), GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;

	tcp_get_default_congestion_control(&init_net, active_ca);
	tcp_get_available_congestion_control(available, sizeof(available));
	seq_printf(m, "congestion_control: %s\navailable: %s\n", active_ca, available);
	seq_printf(m, "hardening: %d\nmss_clamp: %d\n",
		atomic_read(&hardening), atomic_read(&mss_clamp));
	seq_printf(m, "rst_guard: %d\nactive_connections: %d\n",
		atomic_read(&rst_guard), atomic_read(&active));
	seq_printf(m, "syn_rate_limit: %d\n", atomic_read(&syn_rate_limit));
	seq_printf(m, "packets: %lld\ndrops: %lld\nretransmits: %lld\n",
		atomic64_read(&packets), atomic64_read(&drops),
		atomic64_read(&retransmits));
	seq_printf(m, "invalid_drops: %lld\nsyn_rate_drops: %lld\nrst_drops: %lld\n",
		atomic64_read(&invalid_drops), atomic64_read(&syn_rate_drops),
		atomic64_read(&rst_drops));
	seq_printf(m, "packet_loss: %lld\nsyn_failures: %lld\n",
		atomic64_read(&packet_loss), atomic64_read(&syn_failures));
	seq_printf(m, "resets: %lld\nclosed_sockets: %lld\n",
		atomic64_read(&resets), atomic64_read(&closed));
	seq_printf(m, "rtt_last_us: %d\nrtt_avg_us: %lld\n",
		atomic_read(&rtt_last), n ? div64_s64(atomic64_read(&rtt_total), n) : 0);
	spin_lock_bh(&sample_lock);
	hash_for_each(socket_samples, bkt, e, node) {
		if (copied == TCP_SAMPLE_MAX)
			break;
		snapshot[copied++] = *e;
	}
	spin_unlock_bh(&sample_lock);
	seq_puts(m, "# UID IFINDEX COOKIE ESTABLISHED RETRANS LOST AGE\n");
	for (i = 0; i < copied; i++)
		seq_printf(m, "%u %d %llu %d %u %u %lus\n",
			snapshot[i].uid, snapshot[i].ifindex, snapshot[i].cookie,
			snapshot[i].established, snapshot[i].retrans,
			snapshot[i].lost, (jiffies - snapshot[i].updated) / HZ);
	kvfree(snapshot);
	return 0;
}

static int tcp_open(struct inode *inode, struct file *file)
{
	if (!stealth_admin_capable())
		return -EPERM;
	return single_open(file, tcp_show, NULL);
}

static void reset_stats(void)
{
	atomic64_set(&packets, 0); atomic64_set(&drops, 0);
	atomic64_set(&invalid_drops, 0); atomic64_set(&syn_rate_drops, 0);
	atomic64_set(&rst_drops, 0);
	atomic64_set(&retransmits, 0); atomic64_set(&packet_loss, 0);
	atomic64_set(&syn_failures, 0); atomic64_set(&resets, 0);
	atomic64_set(&closed, 0); atomic64_set(&rtt_samples, 0);
	atomic64_set(&rtt_total, 0); atomic_set(&rtt_last, 0);
}

static ssize_t tcp_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char buf[64], cmd[16], value[32];
	unsigned int val;
	int ret;

	if (!stealth_admin_capable()) return -EPERM;
	if (!count || count >= sizeof(buf)) return -EINVAL;
	if (copy_from_user(buf, ubuf, count)) return -EFAULT;
	buf[count] = '\0'; strim(buf);
	if (!strcmp(buf, "reset")) { reset_stats(); return count; }
	if (sscanf(buf, "%15s %31s", cmd, value) != 2) return -EINVAL;
	if (!strcmp(cmd, "cc")) {
		ret = tcp_set_default_congestion_control(&init_net, value);
		return ret ? ret : count;
	}
	if (kstrtouint(value, 0, &val)) return -EINVAL;
	if (!strcmp(cmd, "hardening")) {
		if (val > 1) return -EINVAL;
		atomic_set(&hardening, val); return count;
	}
	if (!strcmp(cmd, "rst_guard")) {
		if (val > 1) return -EINVAL;
		atomic_set(&rst_guard, val); return count;
	}
	if (!strcmp(cmd, "syn_rate")) {
		if (val > 100000) return -ERANGE;
		atomic_set(&syn_rate_limit, val); return count;
	}
	if (!strcmp(cmd, "mss")) {
		if (val && (val < 536 || val > 8960)) return -ERANGE;
		atomic_set(&mss_clamp, val); return count;
	}
	return -EINVAL;
}

static const struct proc_ops tcp_ops = {
	.proc_open = tcp_open, .proc_read = seq_read, .proc_write = tcp_write,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

int stealth_tcp_init(void)
{
	hash_init(socket_samples);
	INIT_DELAYED_WORK(&sample_gc_work, sample_gc);
	schedule_delayed_work(&sample_gc_work, 30 * HZ);
	tcp_proc_entry = proc_create(TCP_PROC_FILENAME, 0600, NULL, &tcp_ops);
	return tcp_proc_entry ? 0 : -ENOMEM;
}

void stealth_tcp_cleanup(void)
{
	struct tcp_socket_sample *e;
	struct hlist_node *tmp;
	int bkt;

	cancel_delayed_work_sync(&sample_gc_work);
	if (tcp_proc_entry) proc_remove(tcp_proc_entry);
	tcp_proc_entry = NULL;
	spin_lock_bh(&sample_lock);
	hash_for_each_safe(socket_samples, bkt, tmp, e, node) {
		hash_del(&e->node); kfree(e);
	}
	spin_unlock_bh(&sample_lock);
}
