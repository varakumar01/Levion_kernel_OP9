// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

DEFINE_HASHTABLE(dns_rules_hash, HASH_BITS_EXP);
DEFINE_SPINLOCK(rules_lock);
static atomic_t audit_all = ATOMIC_INIT(0);

void rules_table_init(void)
{
	hash_init(dns_rules_hash);
}

static inline u32 calc_rule_hash(const char *domain, uid_t uid)
{
	u32 hash = jhash(domain, strlen(domain), 0);
	return jhash_1word(uid, hash);
}

static inline char normalize_char(unsigned char c)
{
	if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
	if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') return c;
	return 0;
}

static int normalize_domain(char *dst, size_t dst_size, const char *src)
{
	const char *p = src, *label_start;
	size_t out_pos = 0, label_len, i;
	char norm_c;

	if (!src || !dst || dst_size == 0)
		return -EINVAL;
	if (src[0] == '*' && src[1] == '\0') {
		if (dst_size < 2)
		return -EINVAL;
		dst[0] = '*'; dst[1] = '\0';
		return 0;
	}
	if (src[0] == '*' && src[1] == '.') {
		if (dst_size < 3)
		return -EINVAL;
		dst[0] = '*'; dst[1] = '.';
		out_pos = 2; p = src + 2;
	}
	if (*p == '\0' || *p == '.')
		return -EINVAL;
	while (*p) {
		label_start = p; label_len = 0;
		while (*p && *p != '.') { label_len++; p++; }
		if (label_len == 0 || label_len > MAX_LABEL_LEN)
			return -EINVAL;
		if (label_start[0] == '-' || label_start[label_len - 1] == '-')
			return -EINVAL;
		if (out_pos + label_len + (*p == '.' ? 1 : 0) >= dst_size)
			return -EINVAL;
		for (i = 0; i < label_len; i++) {
			norm_c = normalize_char((unsigned char)label_start[i]);
			if (!norm_c)
			return -EINVAL;
			dst[out_pos++] = norm_c;
		}
		if (*p == '.') {
			if (*(p + 1) == '\0' || *(p + 1) == '.')
			return -EINVAL;
			dst[out_pos++] = '.'; p++;
		}
	}
	dst[out_pos] = '\0';
	return 0;
}

const char *action_to_str(enum rule_action act)
{
	switch (act) {
	case ACTION_DROP:  return "DROP";
	case ACTION_BLOCK: return "BLOCK";
	case ACTION_SPOOF: return "SPOOF";
	default:           return "AUDIT";
	}
}

static bool match_wildcard_domain(const char *target, const char *pattern, size_t *suffix_len_out)
{
	size_t target_len, suffix_len, offset;
	const char *suffix;

	if (pattern[0] != '*' || pattern[1] != '.')
		return false;
	suffix = pattern + 2;
	target_len = strlen(target);
	suffix_len = strlen(suffix);
	if (target_len <= suffix_len + 1)
		return false;
	offset = target_len - suffix_len;
	if (target[offset - 1] != '.' || strcmp(target + offset, suffix) != 0)
		return false;
	if (suffix_len_out) *suffix_len_out = suffix_len;
	return true;
}

static struct dns_rule_node *lookup_rule_by_uid_locked(const char *domain, uid_t uid)
{
	struct dns_rule_node *entry, *best_wildcard = NULL, *global_fallback = NULL;
	size_t matched_len = 0, best_suffix_len = 0;
	u32 hash = calc_rule_hash(domain, uid);
	int bkt;

	hash_for_each_possible(dns_rules_hash, entry, hnode, hash) {
		if (entry->target_uid == uid && strcmp(entry->domain, domain) == 0)
		return entry;
	}
	hash_for_each(dns_rules_hash, bkt, entry, hnode) {
		if (entry->target_uid != uid) continue;
		if (entry->domain[0] == '*' && entry->domain[1] == '\0') {
			global_fallback = entry;
			continue;
		}
		if (match_wildcard_domain(domain, entry->domain, &matched_len)) {
			if (matched_len > best_suffix_len) {
				best_suffix_len = matched_len;
				best_wildcard = entry;
			}
		}
	}
	return best_wildcard ? best_wildcard : global_fallback;
}

bool lookup_rule(const char *domain, uid_t uid, struct stealth_rule_match *out_match)
{
	char norm_domain[MAX_DOMAIN_WIRE_LEN + 1];
	size_t norm_domain_sz = sizeof(norm_domain);
	struct dns_rule_node *found = NULL;

	if (!domain || !out_match)
		return false;
	if (normalize_domain(norm_domain, norm_domain_sz, domain) != 0)
		return false;
	spin_lock_bh(&rules_lock);
	if (uid != 0) found = lookup_rule_by_uid_locked(norm_domain, uid);
	if (!found) found = lookup_rule_by_uid_locked(norm_domain, 0);
	if (!found) {
		spin_unlock_bh(&rules_lock);
		if (!atomic_read(&audit_all))
			return false;
		memset(out_match, 0, sizeof(*out_match));
		out_match->action = ACTION_AUDIT;
		return true;
	}
	out_match->action = found->action;
	out_match->ip_version = found->ip_version;
	out_match->spoofed_ip = found->spoofed_ip;
	atomic64_inc(&found->hit_count);
	spin_unlock_bh(&rules_lock);
	return true;
}

bool audit_all_enabled(void)
{
	return atomic_read(&audit_all) != 0;
}

void audit_all_set(bool enabled)
{
	atomic_set(&audit_all, enabled ? 1 : 0);
}

static void apply_rule_ip(struct dns_rule_node *node, u8 ver, __be32 v4, const struct in6_addr *v6)
{
	size_t ip_sz = sizeof(node->spoofed_ip);
	node->ip_version = ver;
	memset(&node->spoofed_ip, 0, ip_sz);
	if (ver == 4) node->spoofed_ip.v4 = v4;
	else if (ver == 6 && v6) node->spoofed_ip.v6 = *v6;
}

int rule_add_or_update(uid_t uid, enum rule_action act, const char *domain,
		       u8 ip_ver, __be32 v4_ip, const struct in6_addr *v6_ip)
{
	char norm_domain[MAX_DOMAIN_WIRE_LEN + 1];
	size_t norm_domain_sz = sizeof(norm_domain);
	struct dns_rule_node *entry, *existing;
	size_t entry_sz = sizeof(*entry);
	u32 hash;

	if (normalize_domain(norm_domain, norm_domain_sz, domain) != 0)
		return -EINVAL;
	entry = kzalloc(entry_sz, GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	hash = calc_rule_hash(norm_domain, uid);
	spin_lock_bh(&rules_lock);
	hash_for_each_possible(dns_rules_hash, existing, hnode, hash) {
		if (existing->target_uid != uid || strcmp(existing->domain, norm_domain) != 0)
		continue;
		existing->action = act;
		apply_rule_ip(existing, ip_ver, v4_ip, v6_ip);
		spin_unlock_bh(&rules_lock);
		kfree(entry);
		return 0;
	}
	strscpy(entry->domain, norm_domain, sizeof(entry->domain));
	entry->target_uid = uid;
	entry->action = act;
	apply_rule_ip(entry, ip_ver, v4_ip, v6_ip);
	atomic64_set(&entry->hit_count, 0);
	hash_add(dns_rules_hash, &entry->hnode, hash);
	spin_unlock_bh(&rules_lock);
	return 0;
}

void rule_delete(uid_t uid, const char *domain)
{
	char norm_domain[MAX_DOMAIN_WIRE_LEN + 1];
	size_t norm_domain_sz = sizeof(norm_domain);
	struct dns_rule_node *entry;
	struct hlist_node *tmp;
	u32 hash;

	if (normalize_domain(norm_domain, norm_domain_sz, domain) != 0)
		return;
	hash = calc_rule_hash(norm_domain, uid);
	spin_lock_bh(&rules_lock);
	hash_for_each_possible_safe(dns_rules_hash, entry, tmp, hnode, hash) {
		if (entry->target_uid == uid && strcmp(entry->domain, norm_domain) == 0) {
			hash_del(&entry->hnode);
			kfree(entry);
			break;
		}
	}
	spin_unlock_bh(&rules_lock);
}

void rules_flush(void)
{
	struct dns_rule_node *entry;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&rules_lock);
	hash_for_each_safe(dns_rules_hash, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	spin_unlock_bh(&rules_lock);
	audit_all_set(false);
}

void rules_table_cleanup(void)
{
	rules_flush();
}
