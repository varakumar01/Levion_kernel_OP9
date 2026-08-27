// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

static struct sk_buff *craft_spoof_reply(struct sk_buff *skb, const u8 *qbuf,
	int qlen, uint16_t id, uint16_t flags, uint16_t qtype,
	const struct stealth_rule_match *m, bool is_ipv6)
{
	bool has_answer = (qtype == DNS_TYPE_A && m->ip_version == 4) ||
		(qtype == DNS_TYPE_AAAA && m->ip_version == 6);

	if (is_ipv6)
		return craft_clean_dns_reply_ipv6(skb, qbuf, qlen, id, flags,
			&m->spoofed_ip, m->ip_version, DNS_RCODE_NOERROR, has_answer);
	return craft_clean_dns_reply_ipv4(skb, qbuf, qlen, id, flags,
		&m->spoofed_ip, m->ip_version, DNS_RCODE_NOERROR, has_answer);
}

static unsigned int hook_dns_core(struct sk_buff *skb, const struct nf_hook_state *state,
	int trans_off, bool is_ipv6)
{
	struct udphdr _udph, *udph;
	struct dns_hdr _dnsh, *dnsh;
	struct sock *sk;
	struct stealth_rule_match match;
	struct sk_buff *reply = NULL;
	uid_t uid = 0;
	char domain[MAX_DOMAIN_WIRE_LEN + 1];
	u8 qbuf[MAX_DOMAIN_WIRE_LEN + 4];
	int udp_len = sizeof(*udph);
	int dns_hdr_len = sizeof(*dnsh);
	int dom_len = sizeof(domain);
	int qbuf_len = sizeof(qbuf);
	int payload_off, avail_len, qlen, ret;
	uint16_t qtype = 0, qclass = 0;
	uint16_t orig_id, orig_flags;

	if (unlikely(skb->len < trans_off + udp_len))
		return NF_ACCEPT;
	udph = skb_header_pointer(skb, trans_off, udp_len, &_udph);
	if (unlikely(!udph || udph->dest != htons(DNS_PORT)))
		return NF_ACCEPT;
	if (unlikely(ntohs(udph->len) < udp_len + dns_hdr_len))
		return NF_ACCEPT;
	if (unlikely(ntohs(udph->len) > skb->len - trans_off))
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (sk && sk_fullsock(sk))
		uid = from_kuid_munged(&init_user_ns, sock_net_uid(state->net, sk));
	payload_off = trans_off + udp_len;
	dnsh = skb_header_pointer(skb, payload_off, dns_hdr_len, &_dnsh);
	if (unlikely(!dnsh))
		return NF_ACCEPT;
	orig_id = dnsh->id;
	orig_flags = ntohs(dnsh->flags);
	if (unlikely((orig_flags & (DNS_FLAG_QR | DNS_FLAG_OPCODE)) != 0 ||
	    ntohs(dnsh->qdcount) != 1))
		return NF_ACCEPT;
	avail_len = ntohs(udph->len) - udp_len - dns_hdr_len;
	if (unlikely(avail_len <= 0))
		return NF_ACCEPT;
	qlen = parse_qname_strict(skb, payload_off + dns_hdr_len, avail_len,
		domain, dom_len, &qtype, &qclass);
	if (unlikely(qlen < 0 || qlen > qbuf_len || qlen > MAX_QUESTION_BYTES || qclass != DNS_CLASS_IN))
		return NF_ACCEPT;
	if (unlikely(skb_copy_bits(skb, payload_off + dns_hdr_len, qbuf, qlen) < 0))
		return NF_ACCEPT;
	atomic_inc(&total_dns_detected);

	if (!lookup_rule(domain, uid, &match))
		return NF_ACCEPT;
	push_event(uid, match.action, is_ipv6 ? 6 : 4, domain);
	if (match.action == ACTION_AUDIT)
		return NF_ACCEPT;
	if (match.action == ACTION_DROP)
		goto drop_stolen;
	if (match.action == ACTION_BLOCK && is_ipv6)
		reply = craft_clean_dns_reply_ipv6(skb, qbuf, qlen, orig_id,
			orig_flags, NULL, 0, DNS_RCODE_NXDOMAIN, false);
	if (match.action == ACTION_BLOCK && !is_ipv6)
		reply = craft_clean_dns_reply_ipv4(skb, qbuf, qlen, orig_id,
			orig_flags, NULL, 0, DNS_RCODE_NXDOMAIN, false);
	if (match.action == ACTION_SPOOF)
		reply = craft_spoof_reply(skb, qbuf, qlen, orig_id, orig_flags,
			qtype, &match, is_ipv6);
	if (unlikely(!reply))
		return NF_ACCEPT;
	if (is_ipv6)
		ret = send_ipv6_reply(state->net, reply);
	else
		ret = send_ipv4_reply(state->net, reply);
	(void)ret;
drop_stolen:
	kfree_skb(skb);
	return NF_STOLEN;
}

static bool inspect_tls_sni(struct sk_buff *skb, int trans_off, int tot_len,
	char *domain, int dom_len)
{
	struct tcphdr _tcph, *tcph;
	int tcp_len = sizeof(*tcph);
	int payload_off, payload_len, tcp_hdr_len;

	tcph = skb_header_pointer(skb, trans_off, tcp_len, &_tcph);
	if (unlikely(!tcph || tcph->dest != htons(HTTPS_PORT)))
		return false;
	if (unlikely(tcph->doff < 5))
		return false;
	tcp_hdr_len = tcph->doff * 4;
	payload_off = trans_off + tcp_hdr_len;
	if (unlikely(payload_off > skb->len || payload_off > tot_len))
		return false;
	payload_len = tot_len - payload_off;
	if (unlikely(payload_len <= 0))
		return false;
	return parse_tls_sni(skb, payload_off, payload_len, domain, dom_len) == 0;
}

static bool inspect_quic_sni(struct sk_buff *skb, int trans_off,
	char *domain, int dom_len)
{
	struct udphdr _udph, *udph;
	int udp_len = sizeof(*udph);
	int payload_off, payload_len, udp_total_len;

	udph = skb_header_pointer(skb, trans_off, udp_len, &_udph);
	if (unlikely(!udph || udph->dest != htons(HTTPS_PORT)))
		return false;
	udp_total_len = ntohs(udph->len);
	if (unlikely(udp_total_len < udp_len))
		return false;
	payload_off = trans_off + udp_len;
	payload_len = udp_total_len - udp_len;
	if (unlikely(payload_len < 64 || payload_off > skb->len || payload_len > skb->len - payload_off))
		return false;
	return parse_quic_sni(skb, payload_off, payload_len, domain, dom_len) == 0;
}

static void inspect_app_traffic(struct sk_buff *skb, const struct nf_hook_state *state,
	int trans_off, u8 protocol, int tot_len, bool is_ipv6,
	const void *remote_ip)
{
	struct sock *sk;
	struct stealth_rule_match match;
	uid_t uid = 0;
	char domain_buf[MAX_DOMAIN_WIRE_LEN + 1];
	char host_event[MAX_DOMAIN_WIRE_LEN + 16];
	int dom_len = sizeof(domain_buf);
	int host_len = sizeof(host_event);
	bool found = false;
	bool is_block;

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return;
	uid = from_kuid_munged(&init_user_ns, sock_net_uid(state->net, sk));
	if (protocol == IPPROTO_TCP)
		found = inspect_tls_sni(skb, trans_off, tot_len, domain_buf, dom_len);
	if (protocol == IPPROTO_UDP)
		found = inspect_quic_sni(skb, trans_off, domain_buf, dom_len);
	if (!found)
		return;
	if (state->out)
		stealth_neigh_set_hostname(state->net, state->out->ifindex,
					   is_ipv6 ? 6 : 4, remote_ip,
					   domain_buf);
	if (!lookup_rule(domain_buf, uid, &match))
		return;
	is_block = match.action == ACTION_BLOCK || match.action == ACTION_DROP;
	if (is_block) {
		snprintf(host_event, host_len, "BYPASS:%s", domain_buf);
		push_event(uid, match.action, is_ipv6 ? 6 : 4, host_event);
		return;
	}
	snprintf(host_event, host_len, "HOST:%s", domain_buf);
	push_event(uid, match.action, is_ipv6 ? 6 : 4, host_event);
}

static unsigned int hook_dns_ipv4(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct iphdr _iph, *iph;
	int ip_len = sizeof(*iph);
	int ip_hl, tot_len;

	if (unlikely(!atomic_read(&stealth_enabled)))
		return NF_ACCEPT;
	atomic_inc(&total_packets_hooked);
	iph = skb_header_pointer(skb, 0, ip_len, &_iph);
	if (unlikely(!iph || iph->ihl < 5 || skb->len < iph->ihl * 4))
		return NF_ACCEPT;
	ip_hl = iph->ihl * 4;
	tot_len = ntohs(iph->tot_len);
	if (unlikely(tot_len < ip_hl || tot_len > skb->len))
		return NF_ACCEPT;
	if (state->out) {
		stealth_neigh_account_traffic(state->net, state->out->ifindex, 4,
					       &iph->daddr, tot_len, true);
		if (unlikely(stealth_neigh_is_ip_blocked(state->net,
							 state->out->ifindex, 4,
							 &iph->daddr)))
			return NF_DROP;
	}
	inspect_app_traffic(skb, state, ip_hl, iph->protocol, tot_len, false,
		&iph->daddr);
	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	return hook_dns_core(skb, state, ip_hl, false);
}

static unsigned int hook_dns_ipv6(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct ipv6hdr _iph, *iph;
	int ip_len = sizeof(*iph);
	int trans_off, tot_len;
	u8 nexthdr;
	__be16 frag_off;

	if (unlikely(!atomic_read(&stealth_enabled)))
		return NF_ACCEPT;
	atomic_inc(&total_packets_hooked);
	iph = skb_header_pointer(skb, 0, ip_len, &_iph);
	if (unlikely(!iph))
		return NF_ACCEPT;
	tot_len = ip_len + ntohs(iph->payload_len);
	if (unlikely(tot_len > skb->len))
		return NF_ACCEPT;
	if (state->out) {
		stealth_neigh_account_traffic(state->net, state->out->ifindex, 6,
					       &iph->daddr, tot_len, true);
		if (unlikely(stealth_neigh_is_ip_blocked(state->net,
							 state->out->ifindex, 6,
							 &iph->daddr)))
			return NF_DROP;
	}
	nexthdr = iph->nexthdr;
	trans_off = ipv6_skip_exthdr(skb, ip_len, &nexthdr, &frag_off);
	if (unlikely(trans_off < 0 || frag_off != 0))
		return NF_ACCEPT;
	inspect_app_traffic(skb, state, trans_off, nexthdr, tot_len, true,
		&iph->daddr);
	if (nexthdr != IPPROTO_UDP)
		return NF_ACCEPT;

	return hook_dns_core(skb, state, trans_off, true);
}

static unsigned int hook_neigh_ipv4_in(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct iphdr _iph, *iph;
	int tot_len;

	if (unlikely(!atomic_read(&stealth_enabled)))
		return NF_ACCEPT;
	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (unlikely(!iph || iph->ihl < 5))
		return NF_ACCEPT;
	tot_len = ntohs(iph->tot_len);
	if (unlikely(tot_len < iph->ihl * 4 || tot_len > skb->len))
		return NF_ACCEPT;
	if (!state->in)
		return NF_ACCEPT;
	stealth_neigh_account_traffic(state->net, state->in->ifindex, 4,
				       &iph->saddr, tot_len, false);
	return stealth_neigh_is_ip_blocked(state->net, state->in->ifindex, 4,
		&iph->saddr) ?
		NF_DROP : NF_ACCEPT;
}

static unsigned int hook_neigh_ipv6_in(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct ipv6hdr _iph, *iph;
	int tot_len;

	if (unlikely(!atomic_read(&stealth_enabled)))
		return NF_ACCEPT;
	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (unlikely(!iph))
		return NF_ACCEPT;
	tot_len = sizeof(*iph) + ntohs(iph->payload_len);
	if (unlikely(tot_len > skb->len))
		return NF_ACCEPT;
	if (!state->in)
		return NF_ACCEPT;
	stealth_neigh_account_traffic(state->net, state->in->ifindex, 6,
				       &iph->saddr, tot_len, false);
	return stealth_neigh_is_ip_blocked(state->net, state->in->ifindex, 6,
		&iph->saddr) ?
		NF_DROP : NF_ACCEPT;
}

struct nf_hook_ops stealth_net_hooks[] = {
	{
		.hook = hook_dns_ipv4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = hook_dns_ipv6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = hook_neigh_ipv4_in,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = hook_neigh_ipv6_in,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	}
};

size_t stealth_net_hooks_count = ARRAY_SIZE(stealth_net_hooks);
