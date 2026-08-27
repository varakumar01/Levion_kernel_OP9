// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/ip6_route.h>

static int dns_answer_len(u8 ip_version, bool has_answer)
{
	if (!has_answer)
		return 0;
	if (ip_version == 4)
		return sizeof(struct dns_ans_v4);
	if (ip_version == 6)
		return sizeof(struct dns_ans_v6);
	return 0;
}

static void append_dns_answer(struct sk_buff *skb,
	const union stealth_ip_addr *resolved_ip, u8 ip_version)
{
	if (ip_version == 4) {
		struct dns_ans_v4 *ans = skb_put(skb, sizeof(*ans));

		ans->name_ptr = htons(0xC00C);
		ans->type = htons(DNS_TYPE_A);
		ans->class = htons(DNS_CLASS_IN);
		ans->ttl = htonl(60);
		ans->rdlength = htons(sizeof(resolved_ip->v4));
		ans->rdata = resolved_ip->v4;
	} else {
		struct dns_ans_v6 *ans = skb_put(skb, sizeof(*ans));

		ans->name_ptr = htons(0xC00C);
		ans->type = htons(DNS_TYPE_AAAA);
		ans->class = htons(DNS_CLASS_IN);
		ans->ttl = htonl(60);
		ans->rdlength = htons(sizeof(resolved_ip->v6));
		ans->rdata = resolved_ip->v6;
	}
}

struct sk_buff *craft_clean_dns_reply_ipv4(struct sk_buff *orig_skb,
	const u8 *qbuf, int qlen, uint16_t orig_id, uint16_t orig_flags,
	const union stealth_ip_addr *resolved_ip, u8 answer_ip_version,
	uint8_t rcode, bool has_answer)
{
	struct sk_buff *reply;
	struct iphdr *iph, *orig_iph, _orig_iph;
	struct udphdr *udph, *orig_udph, _orig_udph;
	struct dns_hdr *dnsh;
	int ip_len = sizeof(*iph);
	int udp_len = sizeof(*udph);
	int dns_hdr_len = sizeof(*dnsh);
	int ans_len;
	int dns_total_len;
	int alloc_len;
	int orig_ip_len;

	if (unlikely(qlen < 5))
		return NULL;
	has_answer = has_answer && resolved_ip &&
		(answer_ip_version == 4 || answer_ip_version == 6);
	ans_len = dns_answer_len(answer_ip_version, has_answer);
	dns_total_len = dns_hdr_len + qlen + ans_len;
	alloc_len = LL_MAX_HEADER + ip_len + udp_len + dns_total_len + 32;
	orig_iph = skb_header_pointer(orig_skb, 0, ip_len, &_orig_iph);
	if (unlikely(!orig_iph || orig_iph->version != 4))
		return NULL;
	orig_ip_len = orig_iph->ihl * 4;
	if (unlikely(orig_ip_len < ip_len))
		return NULL;
	if (unlikely(orig_ip_len + udp_len > orig_skb->len))
		return NULL;
	orig_udph = skb_header_pointer(orig_skb, orig_ip_len,
		udp_len, &_orig_udph);
	if (unlikely(!orig_udph))
		return NULL;
	reply = alloc_skb(alloc_len, GFP_ATOMIC);
	if (unlikely(!reply))
		return NULL;

	skb_reserve(reply, LL_MAX_HEADER);
	skb_reset_network_header(reply);

	iph = skb_put(reply, ip_len);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(ip_len + udp_len + dns_total_len);
	iph->id = 0;
	iph->frag_off = htons(IP_DF);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = orig_iph->daddr;
	iph->daddr = orig_iph->saddr;
	iph->check = 0;
	ip_send_check(iph);

	skb_set_transport_header(reply, ip_len);
	udph = skb_put(reply, udp_len);
	udph->source = orig_udph->dest;
	udph->dest = orig_udph->source;
	udph->len = htons(udp_len + dns_total_len);
	udph->check = 0;

	dnsh = skb_put(reply, dns_hdr_len);
	dnsh->id = orig_id;
	dnsh->flags = htons(DNS_FLAG_QR | DNS_FLAG_RA |
		(orig_flags & DNS_FLAG_RD) | (rcode & 0x0F));
	dnsh->qdcount = htons(1);
	dnsh->ancount = has_answer ? htons(1) : 0;
	dnsh->nscount = 0;
	dnsh->arcount = 0;

	skb_put_data(reply, qbuf, qlen);

	if (has_answer)
		append_dns_answer(reply, resolved_ip, answer_ip_version);

	reply->protocol = htons(ETH_P_IP);
	udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
		ntohs(udph->len), IPPROTO_UDP,
		csum_partial(udph, ntohs(udph->len), 0));
	if (udph->check == 0)
		udph->check = CSUM_MANGLED_0;

	return reply;
}

struct sk_buff *craft_clean_dns_reply_ipv6(struct sk_buff *orig_skb,
	const u8 *qbuf, int qlen, uint16_t orig_id, uint16_t orig_flags,
	const union stealth_ip_addr *resolved_ip, u8 answer_ip_version,
	uint8_t rcode, bool has_answer)
{
	struct sk_buff *reply;
	struct ipv6hdr *iph, *orig_iph, _orig_iph;
	struct udphdr *udph, *orig_udph, _orig_udph;
	struct dns_hdr *dnsh;
	bool valid_ans;
	int ip_len = sizeof(*iph);
	int udp_len = sizeof(*udph);
	int dns_hdr_len = sizeof(*dnsh);
	int ans_len;
	int dns_total_len;
	int payload_len;
	int alloc_len;
	int flow_lbl_len = sizeof(iph->flow_lbl);
	int proto_off = ip_len;
	unsigned short frag_off = 0;

	if (unlikely(qlen < 5))
		return NULL;
	valid_ans = has_answer && resolved_ip &&
		(answer_ip_version == 4 || answer_ip_version == 6);
	ans_len = dns_answer_len(answer_ip_version, valid_ans);
	dns_total_len = dns_hdr_len + qlen + ans_len;
	payload_len = udp_len + dns_total_len;
	alloc_len = LL_MAX_HEADER + ip_len + payload_len + 32;
	orig_iph = skb_header_pointer(orig_skb, 0, ip_len, &_orig_iph);
	if (unlikely(!orig_iph || orig_iph->version != 6))
		return NULL;
	proto_off = ipv6_find_hdr(orig_skb, &proto_off,
		IPPROTO_UDP, &frag_off, NULL);
	if (unlikely(proto_off < 0 || frag_off != 0))
		return NULL;
	if (unlikely(proto_off + udp_len > orig_skb->len))
		return NULL;
	orig_udph = skb_header_pointer(orig_skb, proto_off,
		udp_len, &_orig_udph);
	if (unlikely(!orig_udph))
		return NULL;
	reply = alloc_skb(alloc_len, GFP_ATOMIC);
	if (unlikely(!reply))
		return NULL;

	skb_reserve(reply, LL_MAX_HEADER);
	skb_reset_network_header(reply);

	iph = skb_put(reply, ip_len);
	iph->version = 6;
	iph->priority = 0;
	memset(iph->flow_lbl, 0, flow_lbl_len);
	iph->payload_len = htons(payload_len);
	iph->nexthdr = IPPROTO_UDP;
	iph->hop_limit = 64;
	iph->saddr = orig_iph->daddr;
	iph->daddr = orig_iph->saddr;

	skb_set_transport_header(reply, ip_len);
	udph = skb_put(reply, udp_len);
	udph->source = orig_udph->dest;
	udph->dest = orig_udph->source;
	udph->len = htons(payload_len);
	udph->check = 0;

	dnsh = skb_put(reply, dns_hdr_len);
	dnsh->id = orig_id;
	dnsh->flags = htons(DNS_FLAG_QR | DNS_FLAG_RA |
		(orig_flags & DNS_FLAG_RD) | (rcode & 0x0F));
	dnsh->qdcount = htons(1);
	dnsh->ancount = valid_ans ? htons(1) : 0;
	dnsh->nscount = 0;
	dnsh->arcount = 0;

	skb_put_data(reply, qbuf, qlen);

	if (valid_ans)
		append_dns_answer(reply, resolved_ip, answer_ip_version);

	reply->protocol = htons(ETH_P_IPV6);
	udph->check = csum_ipv6_magic(&iph->saddr, &iph->daddr,
		payload_len, IPPROTO_UDP,
		csum_partial(udph, payload_len, 0));
	if (udph->check == 0)
		udph->check = CSUM_MANGLED_0;

	return reply;
}

int send_ipv4_reply(struct net *net, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
	struct rtable *rt;
	struct flowi4 fl4 = {
		.daddr = iph->daddr,
		.saddr = iph->saddr,
		.flowi4_proto = IPPROTO_UDP,
		.fl4_dport = udph->dest,
		.fl4_sport = udph->source,
		.flowi4_mark = skb->mark,
	};

	rt = ip_route_output_key(net, &fl4);
	if (unlikely(IS_ERR(rt)))
		goto drop;

	skb_dst_set(skb, &rt->dst);
	skb->ip_summed = CHECKSUM_NONE;

	return ip_local_out(net, NULL, skb);

drop:
	kfree_skb(skb);
	return -EHOSTUNREACH;
}

int send_ipv6_reply(struct net *net, struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
	struct dst_entry *dst;
	struct flowi6 fl6 = {
		.daddr = iph->daddr,
		.saddr = iph->saddr,
		.flowi6_proto = IPPROTO_UDP,
		.fl6_dport = udph->dest,
		.fl6_sport = udph->source,
		.flowi6_mark = skb->mark,
	};

	dst = ip6_dst_lookup_flow(net, NULL, &fl6, NULL);
	if (unlikely(IS_ERR(dst)))
		goto drop;

	skb_dst_set(skb, dst);
	skb->ip_summed = CHECKSUM_NONE;

	return ip6_local_out(net, NULL, skb);

drop:
	kfree_skb(skb);
	return -EHOSTUNREACH;
}
