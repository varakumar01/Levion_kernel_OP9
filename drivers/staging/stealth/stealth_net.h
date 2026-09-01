/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STEALTH_NET_H
#define _STEALTH_NET_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/kfifo.h>
#include <linux/jiffies.h>
#include <linux/refcount.h>
#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>

#define TAG "stealth_net"
#define PROC_FILENAME "stealth_dns"
#define PROC_EVENTS_FILENAME "stealth_events"
#define PROC_NEIGH_FILENAME "stealth_neigh"
#define PROC_TUNNEL_FILENAME "stealth_tunnel"

#define DNS_PORT 53
#define HTTPS_PORT 443

#define MAX_LABEL_LEN 63
#define MAX_DOMAIN_WIRE_LEN 255
#define MAX_QUESTION_BYTES 260
#define HASH_BITS_EXP 8
#define EVENT_FIFO_SIZE 4096

#define QUIC_FLOW_HASH_BITS 6
#define MAX_QUIC_FLOWS 64
#define QUIC_FLOW_TIMEOUT_HZ (HZ * 2)
#define MAX_CRYPTO_STREAM_LEN 4096

#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_OPCODE 0x7800
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_NXDOMAIN 3

enum rule_action {
	ACTION_AUDIT = 0,
	ACTION_BLOCK = 1,
	ACTION_SPOOF = 2,
	ACTION_DROP  = 3,
};

union stealth_ip_addr {
	__be32 v4;
	struct in6_addr v6;
};

struct stealth_rule_match {
	enum rule_action action;
	u8 ip_version;
	union stealth_ip_addr spoofed_ip;
};

struct dns_rule_node {
	char domain[MAX_DOMAIN_WIRE_LEN + 1];
	union stealth_ip_addr spoofed_ip;
	u8 ip_version;
	uid_t target_uid;
	enum rule_action action;
	atomic64_t hit_count;
	struct hlist_node hnode;
};

struct stealth_event {
	uid_t uid;
	u8 action;
	u8 ip_ver;
	char domain[MAX_DOMAIN_WIRE_LEN + 1];
};

struct dns_hdr {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
} __attribute__((packed));

struct dns_ans_v4 {
	__be16 name_ptr;
	__be16 type;
	__be16 class;
	__be32 ttl;
	__be16 rdlength;
	__be32 rdata;
} __attribute__((packed));

struct dns_ans_v6 {
	__be16 name_ptr;
	__be16 type;
	__be16 class;
	__be32 ttl;
	__be16 rdlength;
	struct in6_addr rdata;
} __attribute__((packed));

struct quic_flow_entry {
	struct hlist_node hnode;
	refcount_t refcnt;
	spinlock_t lock;

	u8 dcid[20];
	u8 dcil;

	u8 key[16];
	u8 iv[12];
	u8 hp_key[16];
	bool keys_initialized;

	u64 largest_pn;
	bool have_largest_pn;

	unsigned long last_seen;
	bool completed;

	size_t assembled_len;
	u8 crypto_buf[MAX_CRYPTO_STREAM_LEN];
	DECLARE_BITMAP(bitmap, MAX_CRYPTO_STREAM_LEN);
};

struct stealth_crypto_ctx {
	struct crypto_shash *hmac_tfm;
	struct crypto_sync_skcipher *hp_tfm;
	struct crypto_aead *aead_tfm;
	spinlock_t lock;
};

extern struct stealth_crypto_ctx quic_crypto_ctx;
extern atomic_t total_packets_hooked;
extern atomic_t total_dns_detected;
extern atomic_t stealth_enabled;
extern atomic_t stealth_ghost_mode;
extern atomic64_t stealth_ghost_drops;
extern atomic64_t stealth_mitm_blocks;
extern spinlock_t rules_lock;
extern struct hlist_head dns_rules_hash[1 << HASH_BITS_EXP];

/* This module controls global networking state, so capabilities from a
 * nested user namespace must never authorize its control plane. */
static inline bool stealth_admin_capable(void)
{
	return ns_capable(&init_user_ns, CAP_NET_ADMIN);
}

/* Event Queue & WaitQueue API */
void events_fifo_init(void);
void events_fifo_flush(void);
bool events_fifo_has_data(void);
void push_event(uid_t uid, u8 action, u8 ip_ver, const char *domain);
bool pop_event(struct stealth_event *ev);
void stealth_notify_event(void);

/* Rules Management API */
void rules_table_init(void);
void rules_table_cleanup(void);
bool lookup_rule(const char *domain, uid_t uid, struct stealth_rule_match *out_match);
int rule_add_or_update(uid_t uid, enum rule_action act, const char *domain, u8 ip_ver, __be32 v4_ip, const struct in6_addr *v6_ip);
void rule_delete(uid_t uid, const char *domain);
void rules_flush(void);
bool audit_all_enabled(void);
void audit_all_set(bool enabled);
const char *action_to_str(enum rule_action act);

/* Parsers & Crypto API */
int stealth_crypto_init(void);
void stealth_crypto_cleanup(void);
int parse_tls_sni(const struct sk_buff *skb, int offset, int avail_len, char *out_sni, int max_len);
int parse_quic_sni(const struct sk_buff *skb, int offset, int avail_len, char *out_sni, int max_sni_len);
int parse_qname_strict(const struct sk_buff *skb, int offset, int avail_len, char *out_domain, int out_len, uint16_t *qtype, uint16_t *qclass);

/* Crafters & Injection API */
struct sk_buff *craft_clean_dns_reply_ipv4(struct sk_buff *orig_skb,
	const u8 *qbuf, int qlen, uint16_t orig_id, uint16_t orig_flags,
	const union stealth_ip_addr *resolved_ip, u8 answer_ip_version,
	uint8_t rcode, bool has_answer);
struct sk_buff *craft_clean_dns_reply_ipv6(struct sk_buff *orig_skb,
	const u8 *qbuf, int qlen, uint16_t orig_id, uint16_t orig_flags,
	const union stealth_ip_addr *resolved_ip, u8 answer_ip_version,
	uint8_t rcode, bool has_answer);
int send_ipv4_reply(struct net *net, struct sk_buff *skb);
int send_ipv6_reply(struct net *net, struct sk_buff *skb);

/* Netfilter Hooks API */
extern struct nf_hook_ops stealth_net_hooks[];
extern size_t stealth_net_hooks_count;

/* Sysfs & ProcFS API */
int stealth_sysfs_init(void);
void stealth_sysfs_cleanup(void);
int stealth_proc_init(void);
void stealth_proc_cleanup(void);
int stealth_tcp_init(void);
void stealth_tcp_cleanup(void);
bool stealth_tcp_filter(struct sk_buff *skb, const struct nf_hook_state *state,
			int trans_off, u8 protocol, bool outbound);
int stealth_capture_init(void);
void stealth_capture_cleanup(void);
void stealth_capture_packet(struct sk_buff *skb,
			    const struct nf_hook_state *state, int trans_off,
			    u8 protocol, bool outbound, const char *verdict,
			    const char *reason);
int stealth_ids_init(void);
void stealth_ids_cleanup(void);
bool stealth_ids_filter(struct sk_buff *skb,
			const struct nf_hook_state *state, int trans_off,
			u8 protocol);

/* Userspace tunnel policy / leak guard API */
int stealth_tunnel_init(void);
void stealth_tunnel_cleanup(void);
bool stealth_tunnel_filter(const struct sk_buff *skb,
			   const struct nf_hook_state *state);

/* Neighbour/ARP/NDP monitoring API */
int stealth_neigh_init(void);
void stealth_neigh_cleanup(void);
void stealth_neigh_set_hostname(struct net *net, int ifindex, u8 ip_ver,
				const void *ip_ptr, const char *name);
void stealth_neigh_account_traffic(struct net *net, int ifindex, u8 ip_ver,
				   const void *ip_ptr, u32 bytes, bool is_tx);
bool stealth_neigh_is_ip_blocked(struct net *net, int ifindex, u8 ip_ver,
				 const void *ip_ptr);

#endif /* _STEALTH_NET_H */
