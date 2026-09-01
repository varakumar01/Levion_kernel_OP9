// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

#include <linux/capability.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/workqueue.h>

#define IDS_PROC_FILENAME "stealth_ids"
#define IDS_HASH_BITS 7
#define IDS_MAX_SOURCES 256
#define IDS_MAX_PORTS 16
#define IDS_MAX_TRUSTED 16
#define IDS_WINDOW_HZ (10 * HZ)
#define IDS_GC_HZ (30 * HZ)
#define IDS_IDLE_HZ (300 * HZ)

struct ids_source {
	struct hlist_node node;
	u32 netns;
	int ifindex;
	u8 ip_version;
	union stealth_ip_addr ip;
	u16 ports[IDS_MAX_PORTS];
	u8 port_count;
	u16 probes;
	u16 echo_count;
	u64 packets;
	u64 alerts;
	unsigned long window_start;
	unsigned long banned_until;
	unsigned long last_seen;
};

struct ids_trusted {
	bool valid;
	u8 ip_version;
	union stealth_ip_addr ip;
};

static DEFINE_HASHTABLE(ids_sources, IDS_HASH_BITS);
static DEFINE_SPINLOCK(ids_lock);
static struct ids_trusted trusted[IDS_MAX_TRUSTED];
static atomic_t ids_enabled = ATOMIC_INIT(0);
static atomic_t ids_threshold = ATOMIC_INIT(8);
static atomic_t ids_ban_seconds = ATOMIC_INIT(60);
static atomic_t ids_count = ATOMIC_INIT(0);
static atomic64_t ids_alerts = ATOMIC64_INIT(0);
static atomic64_t ids_drops = ATOMIC64_INIT(0);
static struct delayed_work ids_gc_work;
static struct proc_dir_entry *ids_proc_entry;

static bool ids_ip_equal(u8 ver, const union stealth_ip_addr *a,
			 const union stealth_ip_addr *b)
{
	return ver == 4 ? a->v4 == b->v4 : ipv6_addr_equal(&a->v6, &b->v6);
}

static bool ids_is_trusted(u8 ver, const union stealth_ip_addr *ip)
{
	int i;

	for (i = 0; i < IDS_MAX_TRUSTED; i++)
		if (trusted[i].valid && trusted[i].ip_version == ver &&
		    ids_ip_equal(ver, &trusted[i].ip, ip))
			return true;
	return false;
}

static bool ids_canary_port(u16 port)
{
	return port == 22 || port == 23 || port == 2323 ||
	       port == 5555 || port == 8080;
}

static u32 ids_hash(u32 netns, int ifindex, u8 ver,
		    const union stealth_ip_addr *ip)
{
	size_t len = ver == 4 ? sizeof(ip->v4) : sizeof(ip->v6);
	return jhash(ver == 4 ? (void *)&ip->v4 : (void *)&ip->v6,
		     len, netns ^ ifindex ^ ver);
}

static struct ids_source *ids_find(u32 netns, int ifindex, u8 ver,
				   const union stealth_ip_addr *ip, u32 key)
{
	struct ids_source *entry;

	hash_for_each_possible(ids_sources, entry, node, key)
		if (entry->netns == netns && entry->ifindex == ifindex &&
		    entry->ip_version == ver && ids_ip_equal(ver, &entry->ip, ip))
			return entry;
	return NULL;
}

static bool ids_add_port(struct ids_source *entry, u16 port)
{
	int i;

	for (i = 0; i < entry->port_count; i++)
		if (entry->ports[i] == port)
			return false;
	if (entry->port_count < IDS_MAX_PORTS)
		entry->ports[entry->port_count++] = port;
	return true;
}

static void ids_ban(struct ids_source *entry, unsigned long now)
{
	entry->banned_until = now + atomic_read(&ids_ban_seconds) * HZ;
	entry->alerts++;
	atomic64_inc(&ids_alerts);
}

bool stealth_ids_filter(struct sk_buff *skb,
			const struct nf_hook_state *state, int trans_off,
			u8 protocol)
{
	struct ids_source *entry;
	struct tcphdr _th, *th = NULL;
	struct udphdr _uh, *uh = NULL;
	struct icmphdr _ih, *ih = NULL;
	struct icmp6hdr _i6h, *i6h = NULL;
	struct iphdr _iph, *iph;
	struct ipv6hdr _ip6h, *ip6h;
	union stealth_ip_addr src = { };
	unsigned long now = jiffies;
	u32 netns, key;
	u16 dport = 0;
	u8 ver;
	bool probe = false, immediate = false, drop = false;

	if (!atomic_read(&ids_enabled) || !state->in ||
	    state->in->flags & IFF_LOOPBACK)
		return false;
	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (iph && iph->version == 4) {
		ver = 4; src.v4 = iph->saddr;
	} else {
		ip6h = skb_header_pointer(skb, 0, sizeof(_ip6h), &_ip6h);
		if (!ip6h || ip6h->version != 6) return false;
		ver = 6; src.v6 = ip6h->saddr;
	}
	if (protocol == IPPROTO_TCP) {
		th = skb_header_pointer(skb, trans_off, sizeof(_th), &_th);
		if (!th) return false;
		dport = ntohs(th->dest);
		probe = th->syn && !th->ack;
		immediate = (th->syn && th->fin) ||
			    (th->fin && th->psh && th->urg) ||
			    (!th->syn && !th->ack && !th->fin && !th->rst &&
			     !th->psh && !th->urg);
		if (th->ack && !th->syn) {
			enum ip_conntrack_info ctinfo;
			struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

			if (ct && ctinfo == IP_CT_NEW)
				immediate = true;
		}
	} else if (protocol == IPPROTO_UDP) {
		uh = skb_header_pointer(skb, trans_off, sizeof(_uh), &_uh);
		if (!uh) return false;
		dport = ntohs(uh->dest); probe = true;
	} else if (protocol == IPPROTO_ICMP) {
		ih = skb_header_pointer(skb, trans_off, sizeof(_ih), &_ih);
		probe = ih && ih->type == ICMP_ECHO;
	} else if (protocol == IPPROTO_ICMPV6) {
		i6h = skb_header_pointer(skb, trans_off, sizeof(_i6h), &_i6h);
		probe = i6h && i6h->icmp6_type == ICMPV6_ECHO_REQUEST;
	}
	netns = state->net->ns.inum;
	key = ids_hash(netns, state->in->ifindex, ver, &src);
	spin_lock_bh(&ids_lock);
	if (ids_is_trusted(ver, &src)) goto out;
	entry = ids_find(netns, state->in->ifindex, ver, &src, key);
	if (!entry && atomic_read(&ids_count) < IDS_MAX_SOURCES) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (entry) {
			entry->netns = netns; entry->ifindex = state->in->ifindex;
			entry->ip_version = ver; entry->ip = src;
			entry->window_start = now; entry->last_seen = now;
			hash_add(ids_sources, &entry->node, key); atomic_inc(&ids_count);
		}
	}
	if (!entry) goto out;
	entry->packets++; entry->last_seen = now;
	if (time_before(now, entry->banned_until)) { drop = true; goto out; }
	if (time_after(now, entry->window_start + IDS_WINDOW_HZ)) {
		entry->window_start = now; entry->port_count = 0;
		entry->probes = 0; entry->echo_count = 0;
	}
	if (probe && dport) {
		entry->probes++;
		ids_add_port(entry, dport);
		immediate |= ids_canary_port(dport);
	}
	if (probe && !dport) entry->echo_count++;
	if (immediate || entry->port_count >= atomic_read(&ids_threshold) ||
	    entry->echo_count >= atomic_read(&ids_threshold) * 2) {
		ids_ban(entry, now); drop = true;
	}
out:
	spin_unlock_bh(&ids_lock);
	if (drop) atomic64_inc(&ids_drops);
	return drop;
}

static void ids_gc(struct work_struct *work)
{
	struct ids_source *entry;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&ids_lock);
	hash_for_each_safe(ids_sources, bkt, tmp, entry, node) {
		if (!time_after(jiffies, entry->last_seen + IDS_IDLE_HZ)) continue;
		hash_del(&entry->node); kfree(entry); atomic_dec(&ids_count);
	}
	spin_unlock_bh(&ids_lock);
	schedule_delayed_work(&ids_gc_work, IDS_GC_HZ);
}

static int ids_show(struct seq_file *m, void *v)
{
	struct ids_source *entry, *snapshot;
	int bkt, copied = 0, i;

	snapshot = kvcalloc(IDS_MAX_SOURCES, sizeof(*snapshot), GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;

	seq_printf(m, "enabled: %d\nthreshold: %d\nban_seconds: %d\n",
		atomic_read(&ids_enabled), atomic_read(&ids_threshold),
		atomic_read(&ids_ban_seconds));
	seq_printf(m, "sources: %d\nalerts: %lld\ndrops: %lld\n",
		atomic_read(&ids_count), atomic64_read(&ids_alerts),
		atomic64_read(&ids_drops));
	seq_puts(m, "# IP IFACE PORTS PROBES PACKETS ALERTS BAN_LEFT\n");
	spin_lock_bh(&ids_lock);
	hash_for_each(ids_sources, bkt, entry, node) {
		if (copied == IDS_MAX_SOURCES) break;
		snapshot[copied++] = *entry;
	}
	spin_unlock_bh(&ids_lock);
	for (i = 0; i < copied; i++) {
		entry = &snapshot[i];
		seq_printf(m, entry->ip_version == 4 ? "%pI4" : "%pI6c",
			entry->ip_version == 4 ? (void *)&entry->ip.v4 :
			(void *)&entry->ip.v6);
		seq_printf(m, " %d %u %u %llu %llu %lus\n", entry->ifindex,
			entry->port_count, entry->probes, entry->packets, entry->alerts,
			time_before(jiffies, entry->banned_until) ?
			(entry->banned_until - jiffies) / HZ : 0);
	}
	kvfree(snapshot);
	return 0;
}

static int ids_open(struct inode *inode, struct file *file)
{
	if (!stealth_admin_capable())
		return -EPERM;
	return single_open(file, ids_show, NULL);
}

static void ids_clear(void)
{
	struct ids_source *entry; struct hlist_node *tmp; int bkt;
	spin_lock_bh(&ids_lock);
	hash_for_each_safe(ids_sources, bkt, tmp, entry, node) {
		hash_del(&entry->node); kfree(entry);
	}
	atomic_set(&ids_count, 0); spin_unlock_bh(&ids_lock);
}

static int ids_parse_ip(const char *str, u8 *ver, union stealth_ip_addr *ip)
{
	if (in4_pton(str, -1, (u8 *)&ip->v4, -1, NULL)) { *ver = 4; return 0; }
	if (in6_pton(str, -1, (u8 *)&ip->v6, -1, NULL)) { *ver = 6; return 0; }
	return -EINVAL;
}

static ssize_t ids_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char buf[64], cmd[16], value[48];
	union stealth_ip_addr ip; unsigned int val; u8 ver; int i;

	if (!stealth_admin_capable()) return -EPERM;
	if (!count || count >= sizeof(buf)) return -EINVAL;
	if (copy_from_user(buf, ubuf, count)) return -EFAULT;
	buf[count] = '\0'; strim(buf);
	if (!strcmp(buf, "clear")) { ids_clear(); return count; }
	if (sscanf(buf, "%15s %47s", cmd, value) != 2) return -EINVAL;
	if (!strcmp(cmd, "enable") || !strcmp(cmd, "threshold") ||
	    !strcmp(cmd, "ban")) {
		if (kstrtouint(value, 0, &val)) return -EINVAL;
		if (!strcmp(cmd, "enable")) {
			if (val > 1) return -EINVAL; atomic_set(&ids_enabled, val);
		} else if (!strcmp(cmd, "threshold")) {
			if (val < 3 || val > IDS_MAX_PORTS) return -ERANGE;
			atomic_set(&ids_threshold, val);
		} else {
			if (val < 5 || val > 3600) return -ERANGE;
			atomic_set(&ids_ban_seconds, val);
		}
		return count;
	}
	if (ids_parse_ip(value, &ver, &ip)) return -EINVAL;
	spin_lock_bh(&ids_lock);
	for (i = 0; i < IDS_MAX_TRUSTED; i++) {
		if (!strcmp(cmd, "untrust") && trusted[i].valid &&
		    trusted[i].ip_version == ver && ids_ip_equal(ver, &trusted[i].ip, &ip))
			trusted[i].valid = false;
		if (!strcmp(cmd, "trust") && !trusted[i].valid) {
			trusted[i].valid = true; trusted[i].ip_version = ver;
			trusted[i].ip = ip; break;
		}
	}
	spin_unlock_bh(&ids_lock);
	return (!strcmp(cmd, "trust") || !strcmp(cmd, "untrust")) ? count : -EINVAL;
}

static const struct proc_ops ids_ops = {
	.proc_open = ids_open, .proc_read = seq_read, .proc_write = ids_write,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

int stealth_ids_init(void)
{
	hash_init(ids_sources); memset(trusted, 0, sizeof(trusted));
	INIT_DELAYED_WORK(&ids_gc_work, ids_gc);
	ids_proc_entry = proc_create(IDS_PROC_FILENAME, 0600, NULL, &ids_ops);
	if (!ids_proc_entry) return -ENOMEM;
	schedule_delayed_work(&ids_gc_work, IDS_GC_HZ); return 0;
}

void stealth_ids_cleanup(void)
{
	cancel_delayed_work_sync(&ids_gc_work);
	if (ids_proc_entry) proc_remove(ids_proc_entry);
	ids_proc_entry = NULL; ids_clear();
}
