// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

#include <linux/etherdevice.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/netevent.h>

#define NEIGH_HASH_BITS		6
#define MAX_NEIGH_ENTRIES	256
#define NEIGH_ENTRY_TIMEOUT_HZ	(HZ * 300)
#define NEIGH_GC_INTERVAL_HZ	(HZ * 60)
#define POISON_WINDOW_HZ	(HZ * 3)
#define MIN_FLIPS_FOR_POISON	3

struct stealth_neigh_node {
	struct net		*net;
	int			ifindex;
	u8			ip_version;
	union stealth_ip_addr	ip;
	u8			mac[ETH_ALEN];
	u8			prev_mac[ETH_ALEN];
	char			dev_name[IFNAMSIZ];
	char			host_name[64];
	unsigned long		first_seen;
	unsigned long		last_seen;
	unsigned long		last_mac_change;
	unsigned long		poison_window_start;
	u32			fast_flips;
	atomic64_t		rx_bytes;
	atomic64_t		tx_bytes;
	atomic_t		arp_changes;
	atomic_t		poison_alerts;
	bool			is_blocked;
	struct hlist_node	hnode;
	struct rcu_head		rcu;
};

struct stealth_neigh_snapshot {
	u32			netns_inum;
	int			ifindex;
	u8			ip_version;
	union stealth_ip_addr	ip;
	u8			mac[ETH_ALEN];
	char			dev_name[IFNAMSIZ];
	char			host_name[64];
	unsigned long		last_seen;
	u64			rx_bytes;
	u64			tx_bytes;
	int			arp_changes;
	int			poison_alerts;
	bool			is_blocked;
};

static DEFINE_HASHTABLE(neigh_hash, NEIGH_HASH_BITS);
static DEFINE_SPINLOCK(neigh_lock);
static struct proc_dir_entry *proc_neigh_entry;
static atomic_t neigh_entries_count = ATOMIC_INIT(0);
static struct delayed_work neigh_gc_work;
static atomic64_t arp_frames_observed = ATOMIC64_INIT(0);
static atomic64_t radar_probes_sent = ATOMIC64_INIT(0);

struct stealth_radar_scan {
	struct delayed_work work;
	struct mutex lock;
	struct net_device *dev;
	__be32 source;
	u32 next_host;
	u32 last;
	bool active;
};

static struct stealth_radar_scan radar_scan;

static void radar_scan_work(struct work_struct *work)
{
	struct stealth_radar_scan *scan =
		container_of(to_delayed_work(work), struct stealth_radar_scan, work);
	struct net_device *dev;
	__be32 source, target;
	int batch = 8;

	mutex_lock(&scan->lock);
	dev = scan->dev;
	source = scan->source;
	while (scan->active && scan->next_host <= scan->last && batch--) {
		target = htonl(scan->next_host++);
		if (target == source)
			continue;
		arp_send(ARPOP_REQUEST, ETH_P_ARP, target, dev, source,
			 NULL, dev->dev_addr, NULL);
		atomic64_inc(&radar_probes_sent);
	}
	if (scan->active && scan->next_host <= scan->last) {
		schedule_delayed_work(&scan->work, msecs_to_jiffies(20));
		mutex_unlock(&scan->lock);
		return;
	}
	if (scan->active) {
		scan->active = false;
		scan->dev = NULL;
		dev_put(dev);
	}
	mutex_unlock(&scan->lock);
}

static int radar_start_scan(const char *ifname)
{
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	u32 address, mask, network, broadcast, hosts;
	int ret = 0;

	mutex_lock(&radar_scan.lock);
	if (radar_scan.active) {
		ret = -EBUSY;
		goto out_unlock;
	}
	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		ret = -ENODEV;
		goto out_unlock;
	}
	if (!(dev->flags & IFF_UP) || dev->type != ARPHRD_ETHER) {
		ret = -ENETDOWN;
		goto out_put;
	}
	rtnl_lock();
	in_dev = __in_dev_get_rtnl(dev);
	ifa = in_dev ? rcu_dereference_rtnl(in_dev->ifa_list) : NULL;
	if (!ifa) {
		rtnl_unlock();
		ret = -EADDRNOTAVAIL;
		goto out_put;
	}
	address = ntohl(ifa->ifa_local);
	mask = ntohl(ifa->ifa_mask);
	rtnl_unlock();
	hosts = ~mask;
	if (hosts < 2 || hosts > 255) {
		ret = -E2BIG;
		goto out_put;
	}
	network = address & mask;
	broadcast = network | hosts;
	radar_scan.dev = dev;
	radar_scan.source = htonl(address);
	radar_scan.next_host = network + 1;
	radar_scan.last = broadcast - 1;
	radar_scan.active = true;
	schedule_delayed_work(&radar_scan.work, 0);
	goto out_unlock;
out_put:
	dev_put(dev);
out_unlock:
	mutex_unlock(&radar_scan.lock);
	return ret;
}

static const char *get_mac_type(const u8 *mac)
{
	if (mac[0] & 0x02)
		return "LAA/Random";
	return "Universal";
}

static u32 neigh_calc_hash(u8 ip_ver, const void *ip_ptr)
{
	size_t len = (ip_ver == 4) ? sizeof(__be32) : sizeof(struct in6_addr);
	return jhash(ip_ptr, len, ip_ver);
}

static bool neigh_ip_equal(const struct stealth_neigh_node *entry, u8 ip_ver, const void *ip_ptr)
{
	if (entry->ip_version != ip_ver)
		return false;
	if (ip_ver == 4)
		return !memcmp(&entry->ip.v4, ip_ptr, sizeof(entry->ip.v4));
	return ipv6_addr_equal(&entry->ip.v6, (const struct in6_addr *)ip_ptr);
}

static bool neigh_key_equal(const struct stealth_neigh_node *entry,
			    const struct net *net, int ifindex, u8 ip_ver,
			    const void *ip_ptr)
{
	return net_eq(entry->net, net) && entry->ifindex == ifindex &&
	       neigh_ip_equal(entry, ip_ver, ip_ptr);
}

static void neigh_node_free_rcu(struct rcu_head *rcu)
{
	struct stealth_neigh_node *entry;
	entry = container_of(rcu, struct stealth_neigh_node, rcu);
	put_net(entry->net);
	kfree(entry);
}

static void neigh_gc_func(struct work_struct *work)
{
	struct stealth_neigh_node *entry;
	struct hlist_node *tmp;
	unsigned long now = jiffies, last;
	int bkt;

	spin_lock_bh(&neigh_lock);
	hash_for_each_safe(neigh_hash, bkt, tmp, entry, hnode) {
		last = READ_ONCE(entry->last_seen);
		if (!time_after(now, last + NEIGH_ENTRY_TIMEOUT_HZ))
			continue;
		hash_del_rcu(&entry->hnode);
		atomic_dec(&neigh_entries_count);
		call_rcu(&entry->rcu, neigh_node_free_rcu);
	}
	spin_unlock_bh(&neigh_lock);
	schedule_delayed_work(&neigh_gc_work, NEIGH_GC_INTERVAL_HZ);
}

static void neigh_handle_mac_change(struct stealth_neigh_node *entry,
				    const u8 *new_mac, const char *dev, unsigned long now)
{
	unsigned long last_change = READ_ONCE(entry->last_mac_change);
	unsigned long delta = now - last_change;
	bool is_bounce = ether_addr_equal(entry->prev_mac, new_mac);
	bool dev_changed = dev && strncmp(entry->dev_name, dev, IFNAMSIZ);
	bool is_poison_burst;

	atomic_inc(&entry->arp_changes);
	if (time_after(now, entry->poison_window_start + POISON_WINDOW_HZ)) {
		entry->poison_window_start = now;
		entry->fast_flips = 0;
	}
	entry->fast_flips = (delta < POISON_WINDOW_HZ) ? (entry->fast_flips + 1) : 1;
	if (dev_changed)
		goto update_state;
	is_poison_burst = atomic_read(&stealth_ghost_mode) >= 2 ||
			  (entry->fast_flips >= MIN_FLIPS_FOR_POISON) ||
			  (is_bounce && delta < POISON_WINDOW_HZ && entry->fast_flips >= 2);
	if (is_poison_burst) {
		atomic_inc(&entry->poison_alerts);
		if (atomic_read(&stealth_ghost_mode) >= 2 &&
		    !READ_ONCE(entry->is_blocked)) {
			WRITE_ONCE(entry->is_blocked, true);
			atomic64_inc(&stealth_mitm_blocks);
			if (entry->ip_version == 4)
				pr_warn_ratelimited("[%s] possible ARP poisoning: %pI4 changed MAC repeatedly on %s; traffic blocked\n",
					TAG, &entry->ip.v4, entry->dev_name);
			else
				pr_warn_ratelimited("[%s] possible NDP poisoning: %pI6c changed MAC repeatedly on %s; traffic blocked\n",
					TAG, &entry->ip.v6, entry->dev_name);
		}
	}
update_state:
	ether_addr_copy(entry->prev_mac, entry->mac);
	ether_addr_copy(entry->mac, new_mac);
	WRITE_ONCE(entry->last_mac_change, now);
}

static struct stealth_neigh_node *neigh_alloc_entry(struct net *net, int ifindex,
						    u8 ip_ver, const void *ip_ptr,
						    const u8 *mac, const char *dev,
						    unsigned long now)
{
	struct stealth_neigh_node *entry;
	size_t entry_sz = sizeof(*entry);
	size_t dev_sz = sizeof(entry->dev_name);
	size_t host_sz = sizeof(entry->host_name);
	const char *dev_str = dev ? dev : "-";

	entry = kzalloc(entry_sz, GFP_ATOMIC);
	if (!entry)
		return NULL;
	entry->net = get_net(net);
	entry->ifindex = ifindex;
	entry->ip_version = ip_ver;
	if (ip_ver == 4)
		memcpy(&entry->ip.v4, ip_ptr, sizeof(entry->ip.v4));
	if (ip_ver == 6)
		memcpy(&entry->ip.v6, ip_ptr, sizeof(entry->ip.v6));
	ether_addr_copy(entry->mac, mac);
	strscpy(entry->dev_name, dev_str, dev_sz);
	strscpy(entry->host_name, "-", host_sz);
	entry->first_seen = now;
	entry->last_seen = now;
	entry->last_mac_change = now;
	entry->poison_window_start = now;
	atomic64_set(&entry->rx_bytes, 0);
	atomic64_set(&entry->tx_bytes, 0);
	atomic_set(&entry->arp_changes, 0);
	atomic_set(&entry->poison_alerts, 0);
	return entry;
}

static void neigh_update_or_add(struct net *net, int ifindex, u8 ip_ver,
				const void *ip_ptr, const u8 *mac,
				const char *dev)
{
	struct stealth_neigh_node *entry;
	unsigned long now = jiffies;
	u32 hash_key = neigh_calc_hash(ip_ver, ip_ptr);
	size_t dev_sz;

	spin_lock_bh(&neigh_lock);
	hash_for_each_possible(neigh_hash, entry, hnode, hash_key) {
		if (!neigh_key_equal(entry, net, ifindex, ip_ver, ip_ptr))
			continue;
		if (!ether_addr_equal(entry->mac, mac))
			neigh_handle_mac_change(entry, mac, dev, now);
		if (dev) {
			dev_sz = sizeof(entry->dev_name);
			strscpy(entry->dev_name, dev, dev_sz);
		}
		WRITE_ONCE(entry->last_seen, now);
		spin_unlock_bh(&neigh_lock);
		return;
	}
	if (atomic_read(&neigh_entries_count) >= MAX_NEIGH_ENTRIES) {
		spin_unlock_bh(&neigh_lock);
		return;
	}
	entry = neigh_alloc_entry(net, ifindex, ip_ver, ip_ptr, mac, dev, now);
	if (!entry) {
		spin_unlock_bh(&neigh_lock);
		return;
	}
	hash_add_rcu(neigh_hash, &entry->hnode, hash_key);
	atomic_inc(&neigh_entries_count);
	spin_unlock_bh(&neigh_lock);
}

static int stealth_arp_receive(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt,
			       struct net_device *orig_dev)
{
	struct arphdr *arp;
	u8 *ptr, mac[ETH_ALEN];
	__be32 sender_ip;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NET_RX_DROP;
	if (!dev || dev->addr_len != ETH_ALEN ||
	    !pskb_may_pull(skb, arp_hdr_len(dev)))
		goto out;
	arp = arp_hdr(skb);
	if (!arp || arp->ar_hrd != htons(ARPHRD_ETHER) ||
	    arp->ar_pro != htons(ETH_P_IP) || arp->ar_hln != ETH_ALEN ||
	    arp->ar_pln != sizeof(sender_ip))
		goto out;
	ptr = (u8 *)(arp + 1);
	ether_addr_copy(mac, ptr);
	memcpy(&sender_ip, ptr + ETH_ALEN, sizeof(sender_ip));
	if (!is_zero_ether_addr(mac) && !is_multicast_ether_addr(mac) &&
	    sender_ip != htonl(INADDR_ANY)) {
		atomic64_inc(&arp_frames_observed);
		neigh_update_or_add(dev_net(dev), dev->ifindex, 4,
				    &sender_ip, mac, dev->name);
	}
out:
	consume_skb(skb);
	return NET_RX_SUCCESS;
}

static struct packet_type stealth_arp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_ARP),
	.func = stealth_arp_receive,
};

void stealth_neigh_set_hostname(struct net *net, int ifindex, u8 ip_ver,
				const void *ip_ptr, const char *name)
{
	struct stealth_neigh_node *entry;
	u32 hash_key;
	size_t host_sz;

	if (!net || ifindex <= 0 || (ip_ver != 4 && ip_ver != 6) ||
	    !ip_ptr || !name || !name[0])
		return;
	hash_key = neigh_calc_hash(ip_ver, ip_ptr);
	spin_lock_bh(&neigh_lock);
	hash_for_each_possible(neigh_hash, entry, hnode, hash_key) {
		if (!neigh_key_equal(entry, net, ifindex, ip_ver, ip_ptr))
			continue;
		host_sz = sizeof(entry->host_name);
		strscpy(entry->host_name, name, host_sz);
		break;
	}
	spin_unlock_bh(&neigh_lock);
}

void stealth_neigh_account_traffic(struct net *net, int ifindex, u8 ip_ver,
				   const void *ip_ptr, u32 bytes, bool is_tx)
{
	struct stealth_neigh_node *entry;
	u32 hash_key;

	if (!net || ifindex <= 0 || (ip_ver != 4 && ip_ver != 6) || !ip_ptr)
		return;
	hash_key = neigh_calc_hash(ip_ver, ip_ptr);
	spin_lock_bh(&neigh_lock);
	hash_for_each_possible(neigh_hash, entry, hnode, hash_key) {
		if (!neigh_key_equal(entry, net, ifindex, ip_ver, ip_ptr))
			continue;
		if (is_tx)
			atomic64_add(bytes, &entry->tx_bytes);
		if (!is_tx)
			atomic64_add(bytes, &entry->rx_bytes);
		WRITE_ONCE(entry->last_seen, jiffies);
		break;
	}
	spin_unlock_bh(&neigh_lock);
}

bool stealth_neigh_is_ip_blocked(struct net *net, int ifindex, u8 ip_ver,
				 const void *ip_ptr)
{
	struct stealth_neigh_node *entry;
	u32 hash_key;
	bool blocked = false;

	if (!net || ifindex <= 0 || (ip_ver != 4 && ip_ver != 6) || !ip_ptr)
		return false;
	hash_key = neigh_calc_hash(ip_ver, ip_ptr);
	rcu_read_lock();
	hash_for_each_possible_rcu(neigh_hash, entry, hnode, hash_key) {
		if (!neigh_key_equal(entry, net, ifindex, ip_ver, ip_ptr))
			continue;
		blocked = READ_ONCE(entry->is_blocked);
		break;
	}
	rcu_read_unlock();
	return blocked;
}

static void stealth_neigh_table_clear(void)
{
	struct stealth_neigh_node *entry;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&neigh_lock);
	hash_for_each_safe(neigh_hash, bkt, tmp, entry, hnode) {
		hash_del_rcu(&entry->hnode);
		call_rcu(&entry->rcu, neigh_node_free_rcu);
	}
	atomic_set(&neigh_entries_count, 0);
	spin_unlock_bh(&neigh_lock);
}

static int stealth_neigh_set_block_state(const char *ip_str, bool blocked)
{
	struct stealth_neigh_node *entry;
	union stealth_ip_addr ip;
	const void *ip_ptr = NULL;
	u8 ip_ver = 0;
	u32 hash_key;
	bool found = false;

	if (in4_pton(ip_str, -1, (u8 *)&ip.v4, -1, NULL)) {
		ip_ver = 4;
		ip_ptr = &ip.v4;
	}
	if (!ip_ver && in6_pton(ip_str, -1, (u8 *)&ip.v6, -1, NULL)) {
		ip_ver = 6;
		ip_ptr = &ip.v6;
	}
	if (!ip_ver)
		return -EINVAL;
	hash_key = neigh_calc_hash(ip_ver, ip_ptr);
	spin_lock_bh(&neigh_lock);
	hash_for_each_possible(neigh_hash, entry, hnode, hash_key) {
		if (!neigh_ip_equal(entry, ip_ver, ip_ptr))
			continue;
		WRITE_ONCE(entry->is_blocked, blocked);
		if (!blocked) {
			entry->fast_flips = 0;
			entry->poison_window_start = jiffies;
		}
		found = true;
	}
	spin_unlock_bh(&neigh_lock);
	if (found)
		return 0;
	return -ENOENT;
}

static int stealth_neigh_event_handler(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct neighbour *n = ptr;
	u8 mac[ETH_ALEN];
	u8 nud_state;
	const char *dev_name = NULL;

	if (event != NETEVENT_NEIGH_UPDATE || !n)
		return NOTIFY_DONE;
	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	ether_addr_copy(mac, n->ha);
	read_unlock_bh(&n->lock);

	if (!(nud_state & (NUD_REACHABLE | NUD_PERMANENT | NUD_STALE | NUD_DELAY | NUD_PROBE)))
		return NOTIFY_DONE;
	if (is_zero_ether_addr(mac))
		return NOTIFY_DONE;
	if (n->dev)
		dev_name = n->dev->name;
	else
		return NOTIFY_DONE;
	if (n->dev->addr_len != ETH_ALEN)
		return NOTIFY_DONE;
	if (n->tbl->family == AF_INET)
		neigh_update_or_add(dev_net(n->dev), n->dev->ifindex, 4,
				    n->primary_key, mac, dev_name);
	if (n->tbl->family == AF_INET6)
		neigh_update_or_add(dev_net(n->dev), n->dev->ifindex, 6,
				    n->primary_key, mac, dev_name);
	return NOTIFY_DONE;
}

static struct notifier_block stealth_neigh_nb = {
	.notifier_call = stealth_neigh_event_handler,
};

static int stealth_neigh_show(struct seq_file *m, void *v)
{
	struct stealth_neigh_snapshot *snapshot = NULL;
	struct stealth_neigh_node *entry;
	size_t count = 0, copied = 0, i;
	size_t snap_sz = sizeof(*snapshot);
	size_t ip_buf_sz;
	char ip_buf[48];
	const char *state_str;
	unsigned long ago_sec;
	int bkt;
	bool scan_active;
	char scan_dev[IFNAMSIZ] = "-";

	mutex_lock(&radar_scan.lock);
	scan_active = radar_scan.active;
	if (radar_scan.dev)
		strscpy(scan_dev, radar_scan.dev->name, sizeof(scan_dev));
	mutex_unlock(&radar_scan.lock);
	seq_printf(m, "# RADAR active=%d dev=%s arp_seen=%lld probes=%lld\n",
		scan_active, scan_dev, atomic64_read(&arp_frames_observed),
		atomic64_read(&radar_probes_sent));

	spin_lock_bh(&neigh_lock);
	hash_for_each(neigh_hash, bkt, entry, hnode)
		count++;
	spin_unlock_bh(&neigh_lock);

	if (count) {
		snapshot = kvcalloc(count, snap_sz, GFP_KERNEL);
		if (!snapshot)
			return -ENOMEM;
	}
	spin_lock_bh(&neigh_lock);
	hash_for_each(neigh_hash, bkt, entry, hnode) {
		if (copied == count)
			break;
		snapshot[copied].netns_inum = entry->net->ns.inum;
		snapshot[copied].ifindex = entry->ifindex;
		snapshot[copied].ip_version = entry->ip_version;
		snapshot[copied].ip = entry->ip;
		ether_addr_copy(snapshot[copied].mac, entry->mac);
		strscpy(snapshot[copied].dev_name, entry->dev_name,
			sizeof(snapshot[copied].dev_name));
		strscpy(snapshot[copied].host_name, entry->host_name,
			sizeof(snapshot[copied].host_name));
		snapshot[copied].last_seen = READ_ONCE(entry->last_seen);
		snapshot[copied].rx_bytes = atomic64_read(&entry->rx_bytes);
		snapshot[copied].tx_bytes = atomic64_read(&entry->tx_bytes);
		snapshot[copied].arp_changes = atomic_read(&entry->arp_changes);
		snapshot[copied].poison_alerts = atomic_read(&entry->poison_alerts);
		snapshot[copied].is_blocked = READ_ONCE(entry->is_blocked);
		copied++;
	}
	spin_unlock_bh(&neigh_lock);
	seq_puts(m, "# NETNS IFINDEX IP MAC HOST TYPE DEV SEEN RX TX CHG POIS STATE\n");
	ip_buf_sz = sizeof(ip_buf);
	for (i = 0; i < copied; i++) {
		ago_sec = (jiffies - snapshot[i].last_seen) / HZ;
		state_str = snapshot[i].is_blocked ? "BLOCKED" : "ACTIVE";
		if (snapshot[i].ip_version == 6)
			snprintf(ip_buf, ip_buf_sz, "%pI6c", &snapshot[i].ip.v6);
		if (snapshot[i].ip_version == 4)
			snprintf(ip_buf, ip_buf_sz, "%pI4", &snapshot[i].ip.v4);
		seq_printf(m, "%u %d %s %pM %s %s %s %lus %lluKB %lluKB %d %d %s\n",
			   snapshot[i].netns_inum, snapshot[i].ifindex,
			   ip_buf, snapshot[i].mac, snapshot[i].host_name,
			   get_mac_type(snapshot[i].mac), snapshot[i].dev_name,
			   ago_sec, snapshot[i].rx_bytes >> 10,
			   snapshot[i].tx_bytes >> 10, snapshot[i].arp_changes,
			   snapshot[i].poison_alerts, state_str);
	}
	kvfree(snapshot);
	return 0;
}

static int stealth_neigh_open(struct inode *inode, struct file *file)
{
	if (!stealth_admin_capable())
		return -EPERM;
	return single_open(file, stealth_neigh_show, NULL);
}

static ssize_t stealth_neigh_write(struct file *file, const char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	char kbuf[64], cmd[16], ip_str[48];
	size_t kbuf_sz = sizeof(kbuf);
	size_t len;
	int ret;

	if (!stealth_admin_capable())
		return -EPERM;
	if (!count || count >= kbuf_sz)
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	len = strlen(kbuf);
	while (len && (kbuf[len - 1] == '\n' || kbuf[len - 1] == '\r' || kbuf[len - 1] == ' '))
		kbuf[--len] = '\0';
	if (!strcmp(kbuf, "clear")) {
		stealth_neigh_table_clear();
		return count;
	}
	if (sscanf(kbuf, "%15s %47s", cmd, ip_str) != 2)
		return -EINVAL;
	if (!strcmp(cmd, "block")) {
		ret = stealth_neigh_set_block_state(ip_str, true);
		if (ret)
			return ret;
		return count;
	}
	if (!strcmp(cmd, "unblock")) {
		ret = stealth_neigh_set_block_state(ip_str, false);
		if (ret)
			return ret;
		return count;
	}
	if (!strcmp(cmd, "scan")) {
		ret = radar_start_scan(ip_str);
		if (ret)
			return ret;
		return count;
	}
	return -EINVAL;
}

static const struct proc_ops stealth_neigh_proc_ops = {
	.proc_open    = stealth_neigh_open,
	.proc_read    = seq_read,
	.proc_write   = stealth_neigh_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int stealth_neigh_init(void)
{
	int ret;

	hash_init(neigh_hash);
	atomic_set(&neigh_entries_count, 0);
	mutex_init(&radar_scan.lock);
	INIT_DELAYED_WORK(&radar_scan.work, radar_scan_work);
	radar_scan.active = false;
	radar_scan.dev = NULL;
	proc_neigh_entry = proc_create(PROC_NEIGH_FILENAME, 0600, NULL, &stealth_neigh_proc_ops);
	if (!proc_neigh_entry)
		return -ENOMEM;
	ret = register_netevent_notifier(&stealth_neigh_nb);
	if (ret) {
		proc_remove(proc_neigh_entry);
		proc_neigh_entry = NULL;
		return ret;
	}
	INIT_DELAYED_WORK(&neigh_gc_work, neigh_gc_func);
	schedule_delayed_work(&neigh_gc_work, NEIGH_GC_INTERVAL_HZ);
	dev_add_pack(&stealth_arp_packet_type);
	return 0;
}

void stealth_neigh_cleanup(void)
{
	struct net_device *scan_dev = NULL;

	dev_remove_pack(&stealth_arp_packet_type);
	unregister_netevent_notifier(&stealth_neigh_nb);
	cancel_delayed_work_sync(&neigh_gc_work);
	cancel_delayed_work_sync(&radar_scan.work);
	mutex_lock(&radar_scan.lock);
	if (radar_scan.active) {
		scan_dev = radar_scan.dev;
		radar_scan.dev = NULL;
		radar_scan.active = false;
	}
	mutex_unlock(&radar_scan.lock);
	if (scan_dev)
		dev_put(scan_dev);
	if (proc_neigh_entry) {
		proc_remove(proc_neigh_entry);
		proc_neigh_entry = NULL;
	}
	stealth_neigh_table_clear();
	rcu_barrier();
}
