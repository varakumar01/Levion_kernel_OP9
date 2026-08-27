// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <asm/unaligned.h>

struct stealth_crypto_ctx quic_crypto_ctx;

static DEFINE_HASHTABLE(quic_flow_table, QUIC_FLOW_HASH_BITS);
static DEFINE_SPINLOCK(flow_table_lock);
static atomic_t active_flows_count = ATOMIC_INIT(0);

static const u8 quic_v1_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

static inline bool flow_get_not_zero(struct quic_flow_entry *flow)
{
	return refcount_inc_not_zero(&flow->refcnt);
}

static inline void flow_put(struct quic_flow_entry *flow)
{
	if (!flow)
		return;
	if (!refcount_dec_and_test(&flow->refcnt))
		return;
	kfree(flow);
	atomic_dec(&active_flows_count);
}

static void cleanup_expired_flows_locked(void)
{
	struct quic_flow_entry *flow;
	struct hlist_node *tmp;
	unsigned long now = jiffies;
	int bkt;

	hash_for_each_safe(quic_flow_table, bkt, tmp, flow, hnode) {
		spin_lock(&flow->lock);
		if (time_after(now, flow->last_seen + QUIC_FLOW_TIMEOUT_HZ) ||
		    flow->completed) {
			spin_unlock(&flow->lock);
			hash_del(&flow->hnode);
			flow_put(flow);
			continue;
		}
		spin_unlock(&flow->lock);
	}
}

static int hkdf_expand(struct crypto_shash *hmac_tfm, const u8 *prk,
		       size_t prk_len, const u8 *info, size_t info_len,
		       u8 *okm, size_t okm_len)
{
	SHASH_DESC_ON_STACK(desc, hmac_tfm);
	size_t t_len = 0, where = 0, to_copy;
	u8 counter = 1, t[32];
	int ret;

	desc->tfm = hmac_tfm;
	ret = crypto_shash_setkey(hmac_tfm, prk, prk_len);
	if (ret)
		return ret;
	while (where < okm_len) {
		ret = crypto_shash_init(desc);
		if (ret)
			return ret;
		if (t_len > 0) {
			ret = crypto_shash_update(desc, t, t_len);
			if (ret)
				return ret;
		}
		ret = crypto_shash_update(desc, info, info_len);
		if (ret)
			return ret;
		ret = crypto_shash_update(desc, &counter, 1);
		if (ret)
			return ret;
		ret = crypto_shash_final(desc, t);
		if (ret)
			return ret;
		t_len = 32;
		to_copy = min_t(size_t, okm_len - where, 32);
		memcpy(okm + where, t, to_copy);
		where += to_copy;
		if (counter == 255 && where < okm_len)
			return -EINVAL;
		counter++;
	}
	return 0;
}

static int hkdf_expand_label(struct crypto_shash *hmac_tfm, const u8 *secret,
			     const char *label, u8 *out, size_t out_len)
{
	u8 hkdf_label[64];
	size_t label_len = strlen(label);
	int pos = 0;

	if (label_len + 10 > sizeof(hkdf_label))
		return -EINVAL;
	hkdf_label[pos++] = (out_len >> 8) & 0xFF;
	hkdf_label[pos++] = out_len & 0xFF;
	hkdf_label[pos++] = label_len + 6;
	memcpy(&hkdf_label[pos], "tls13 ", 6);
	pos += 6;
	memcpy(&hkdf_label[pos], label, label_len);
	pos += label_len;
	hkdf_label[pos++] = 0x00;

	return hkdf_expand(hmac_tfm, secret, 32, hkdf_label, pos, out, out_len);
}

static int init_flow_crypto_keys(struct quic_flow_entry *flow)
{
	SHASH_DESC_ON_STACK(desc, quic_crypto_ctx.hmac_tfm);
	u8 initial_secret[32], client_secret[32];
	size_t salt_sz = sizeof(quic_v1_salt);
	int ret;

	desc->tfm = quic_crypto_ctx.hmac_tfm;
	ret = crypto_shash_setkey(quic_crypto_ctx.hmac_tfm, quic_v1_salt, salt_sz);
	if (ret)
		return ret;
	ret = crypto_shash_digest(desc, flow->dcid, flow->dcil, initial_secret);
	if (ret)
		return ret;
	ret = hkdf_expand_label(quic_crypto_ctx.hmac_tfm, initial_secret,
				"client in", client_secret, 32);
	if (ret)
		return ret;
	ret = hkdf_expand_label(quic_crypto_ctx.hmac_tfm, client_secret,
				"quic key", flow->key, 16);
	if (ret)
		return ret;
	ret = hkdf_expand_label(quic_crypto_ctx.hmac_tfm, client_secret,
				"quic iv", flow->iv, 12);
	if (ret)
		return ret;
	ret = hkdf_expand_label(quic_crypto_ctx.hmac_tfm, client_secret,
				"quic hp", flow->hp_key, 16);
	if (ret)
		return ret;
	flow->keys_initialized = true;
	return 0;
}

static struct quic_flow_entry *get_or_create_flow(const u8 *dcid, u8 dcil)
{
	struct quic_flow_entry *flow;
	size_t entry_sz = sizeof(*flow);
	u32 hash;

	if (dcil == 0 || dcil > 20)
		return NULL;
	hash = jhash(dcid, dcil, 0);
	spin_lock_bh(&flow_table_lock);
	cleanup_expired_flows_locked();
	hash_for_each_possible(quic_flow_table, flow, hnode, hash) {
		if (flow->dcil != dcil || memcmp(flow->dcid, dcid, dcil) != 0)
			continue;
		if (!flow_get_not_zero(flow))
			continue;
		spin_lock(&flow->lock);
		flow->last_seen = jiffies;
		spin_unlock(&flow->lock);

		spin_unlock_bh(&flow_table_lock);
		return flow;
	}
	if (atomic_read(&active_flows_count) >= MAX_QUIC_FLOWS) {
		spin_unlock_bh(&flow_table_lock);
		return NULL;
	}
	flow = kzalloc(entry_sz, GFP_ATOMIC);
	if (!flow) {
		spin_unlock_bh(&flow_table_lock);
		return NULL;
	}
	memcpy(flow->dcid, dcid, dcil);
	flow->dcil = dcil;
	flow->largest_pn = 0;
	flow->have_largest_pn = false;
	flow->assembled_len = 0;
	flow->last_seen = jiffies;
	flow->completed = false;
	spin_lock_init(&flow->lock);
	refcount_set(&flow->refcnt, 2);
	if (init_flow_crypto_keys(flow) != 0) {
		kfree(flow);
		spin_unlock_bh(&flow_table_lock);
		return NULL;
	}
	hash_add(quic_flow_table, &flow->hnode, hash);
	atomic_inc(&active_flows_count);
	spin_unlock_bh(&flow_table_lock);
	return flow;
}

int stealth_crypto_init(void)
{
	hash_init(quic_flow_table);
	spin_lock_init(&quic_crypto_ctx.lock);
	quic_crypto_ctx.hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(quic_crypto_ctx.hmac_tfm))
		return PTR_ERR(quic_crypto_ctx.hmac_tfm);
	quic_crypto_ctx.hp_tfm = crypto_alloc_sync_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(quic_crypto_ctx.hp_tfm)) {
		crypto_free_shash(quic_crypto_ctx.hmac_tfm);
		return PTR_ERR(quic_crypto_ctx.hp_tfm);
	}
	quic_crypto_ctx.aead_tfm = crypto_alloc_aead("gcm(aes)", 0,
		CRYPTO_ALG_ASYNC);
	if (IS_ERR(quic_crypto_ctx.aead_tfm)) {
		crypto_free_sync_skcipher(quic_crypto_ctx.hp_tfm);
		crypto_free_shash(quic_crypto_ctx.hmac_tfm);
		return PTR_ERR(quic_crypto_ctx.aead_tfm);
	}
	return 0;
}

void stealth_crypto_cleanup(void)
{
	struct quic_flow_entry *flow;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&flow_table_lock);
	hash_for_each_safe(quic_flow_table, bkt, tmp, flow, hnode) {
		hash_del(&flow->hnode);
		flow_put(flow);
	}
	spin_unlock_bh(&flow_table_lock);
	if (quic_crypto_ctx.aead_tfm && !IS_ERR(quic_crypto_ctx.aead_tfm))
		crypto_free_aead(quic_crypto_ctx.aead_tfm);
	if (quic_crypto_ctx.hp_tfm && !IS_ERR(quic_crypto_ctx.hp_tfm))
		crypto_free_sync_skcipher(quic_crypto_ctx.hp_tfm);
	if (quic_crypto_ctx.hmac_tfm && !IS_ERR(quic_crypto_ctx.hmac_tfm))
		crypto_free_shash(quic_crypto_ctx.hmac_tfm);
}

static int quic_read_vint_safe(const u8 **buf, const u8 *end, u64 *val)
{
	size_t remain;
	u8 len_type;

	if (!buf || !*buf || *buf >= end || !val)
		return -EINVAL;
	remain = (size_t)(end - *buf);
	len_type = (**buf & 0xC0) >> 6;
	if (len_type == 0) {
		*val = **buf & 0x3F;
		*buf += 1;
		return 0;
	}
	if (len_type == 1) {
		if (remain < 2)
			return -EINVAL;
		*val = get_unaligned_be16(*buf) & 0x3FFF;
		*buf += 2;
		return 0;
	}
	if (len_type == 2) {
		if (remain < 4)
			return -EINVAL;
		*val = get_unaligned_be32(*buf) & 0x3FFFFFFF;
		*buf += 4;
		return 0;
	}
	if (remain < 8)
		return -EINVAL;
	*val = get_unaligned_be64(*buf) & 0x3FFFFFFFFFFFFFFFULL;
	*buf += 8;
	return 0;
}

static u64 decode_packet_number(u64 largest_pn, u64 truncated_pn,
				u32 pn_nbits, bool have_pn)
{
	u64 pn_win = 1ULL << pn_nbits;
	u64 expected_pn, pn_hwin = pn_win / 2, pn_mask = pn_win - 1;
	u64 candidate_pn;
	if (!have_pn)
		return truncated_pn;
	if (largest_pn >= (1ULL << 62))
		return truncated_pn;
	expected_pn = largest_pn + 1;
	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
	if (candidate_pn <= expected_pn - pn_hwin &&
	    candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;
	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
		return candidate_pn - pn_win;
	return candidate_pn;
}

static bool is_valid_sni_hostname(const u8 *str, size_t len)
{
	size_t i, label_len = 0;
	u8 c;

	if (!str || len == 0 || len > MAX_DOMAIN_WIRE_LEN)
		return false;
	if (str[0] == '.' || str[len - 1] == '.' ||
	    str[0] == '-' || str[len - 1] == '-')
		return false;
	for (i = 0; i < len; i++) {
		c = str[i];
		if (c == '.') {
			if (label_len == 0 || label_len > MAX_LABEL_LEN)
				return false;
			if (str[i - 1] == '-' ||
			    (i + 1 < len && str[i + 1] == '-'))
				return false;
			label_len = 0;
			continue;
		}
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		    (c >= 'A' && c <= 'Z') || c == '-') {
			label_len++;
			continue;
		}
		return false;
	}

	if (label_len == 0 || label_len > MAX_LABEL_LEN)
		return false;
	return true;
}

static int extract_sni_from_client_hello(const u8 *data, int len,
					 char *out_sni, int max_len)
{
	int pos = 0, ext_len;
	const u8 *hello_end;
	u32 handshake_len;
	u8 sess_id_len, comp_methods_len;
	u16 cipher_suites_len, ext_type, cur_ext_len, list_len, sni_len;

	if (!data || !out_sni || max_len <= 1 || len < 38 || data[0] != 0x01)
		return -EINVAL;
	handshake_len = ((u32)data[1] << 16) | ((u32)data[2] << 8) | data[3];
	if (handshake_len > (u32)(len - 4))
		return -EAGAIN;
	hello_end = data + 4 + handshake_len;
	pos = 4 + 2 + 32;
	if (data + pos >= hello_end)
		return -EINVAL;
	sess_id_len = data[pos];
	if (sess_id_len > (size_t)(hello_end - (data + pos + 1)))
		return -EINVAL;
	pos += 1 + sess_id_len;

	if ((size_t)(hello_end - (data + pos)) < 2)
		return -EINVAL;
	cipher_suites_len = get_unaligned_be16(&data[pos]);
	if (cipher_suites_len > (size_t)(hello_end - (data + pos + 2)))
		return -EINVAL;
	pos += 2 + cipher_suites_len;

	if (data + pos >= hello_end)
		return -EINVAL;
	comp_methods_len = data[pos];
	if (comp_methods_len > (size_t)(hello_end - (data + pos + 1)))
		return -EINVAL;
	pos += 1 + comp_methods_len;
	if ((size_t)(hello_end - (data + pos)) < 2)
		return -EINVAL;
	ext_len = get_unaligned_be16(&data[pos]);
	pos += 2;
	if (ext_len > (size_t)(hello_end - (data + pos)))
		return -EINVAL;
	while (ext_len >= 4 && (size_t)(hello_end - (data + pos)) >= 4) {
		ext_type = get_unaligned_be16(&data[pos]);
		cur_ext_len = get_unaligned_be16(&data[pos + 2]);
		pos += 4;
		ext_len -= 4;
		if (cur_ext_len > ext_len ||
		    cur_ext_len > (size_t)(hello_end - (data + pos)))
			return -EINVAL;
		if (ext_type == 0x0000) {
			if (cur_ext_len < 5)
				return -EINVAL;
			list_len = get_unaligned_be16(&data[pos]);
			if (list_len != cur_ext_len - 2 || data[pos + 2] != 0x00)
				return -EINVAL;
			sni_len = get_unaligned_be16(&data[pos + 3]);
			if (sni_len != list_len - 3 || sni_len >= max_len)
				return -EINVAL;
			if ((size_t)(hello_end - (data + pos + 5)) < sni_len)
				return -EINVAL;
			if (!is_valid_sni_hostname(&data[pos + 5], sni_len))
				return -EINVAL;
			memcpy(out_sni, &data[pos + 5], sni_len);
			out_sni[sni_len] = '\0';
			return 0;
		}
		pos += cur_ext_len;
		ext_len -= cur_ext_len;
	}
	return -EINVAL;
}

static void update_flow_crypto_data(struct quic_flow_entry *flow, u64 offset,
				    const u8 *data, u64 len)
{
	unsigned long *bmp = (unsigned long *)flow->bitmap;
	unsigned long off_ul = (unsigned long)offset;
	size_t len_sz = (size_t)len;
	size_t off_sz = (size_t)offset;
	size_t max_sz = MAX_CRYPTO_STREAM_LEN;
	size_t remain_sz = max_sz - off_sz;
	size_t copy_len = min(len_sz, remain_sz);
	unsigned long copy_ul = (unsigned long)copy_len;

	if (offset >= MAX_CRYPTO_STREAM_LEN || len == 0)
		return;
	memcpy(flow->crypto_buf + offset, data, copy_len);
	bitmap_set(bmp, off_ul, copy_ul);
	flow->assembled_len = find_first_zero_bit(bmp, MAX_CRYPTO_STREAM_LEN);
}

static int skip_quic_vints(const u8 **buf, const u8 *end, int count)
{
	u64 val;
	int i;

	for (i = 0; i < count; i++) {
		if (quic_read_vint_safe(buf, end, &val) < 0)
			return -EINVAL;
	}
	return 0;
}

static int skip_quic_ack_frame(const u8 **buf, const u8 *end, u64 ftype)
{
	u64 ack_ranges, dummy, i;

	if (skip_quic_vints(buf, end, 2) < 0)
		return -EINVAL;
	if (quic_read_vint_safe(buf, end, &ack_ranges) < 0)
		return -EINVAL;
	if (quic_read_vint_safe(buf, end, &dummy) < 0)
		return -EINVAL;
	for (i = 0; i < ack_ranges; i++) {
		if (skip_quic_vints(buf, end, 2) < 0)
			return -EINVAL;
	}
	if (ftype == 0x03 && skip_quic_vints(buf, end, 3) < 0)
		return -EINVAL;
	return 0;
}

static int skip_quic_token_frame(const u8 **buf, const u8 *end)
{
	u64 token_len;

	if (quic_read_vint_safe(buf, end, &token_len) < 0)
		return -EINVAL;
	if (token_len > (u64)(end - *buf))
		return -EINVAL;
	*buf += token_len;
	return 0;
}

static int skip_quic_new_cid_frame(const u8 **buf, const u8 *end)
{
	u64 dummy, cid_len;

	if (skip_quic_vints(buf, end, 2) < 0)
		return -EINVAL;
	if (quic_read_vint_safe(buf, end, &cid_len) < 0)
		return -EINVAL;
	if (cid_len > 20 || cid_len + 16 > (u64)(end - *buf))
		return -EINVAL;
	*buf += cid_len + 16;
	return 0;
}

static int skip_quic_cc_frame(const u8 **buf, const u8 *end, u64 ftype)
{
	u64 dummy, reason_len;

	if (quic_read_vint_safe(buf, end, &dummy) < 0)
		return -EINVAL;
	if (ftype == 0x1c && quic_read_vint_safe(buf, end, &dummy) < 0)
		return -EINVAL;
	if (quic_read_vint_safe(buf, end, &reason_len) < 0)
		return -EINVAL;
	if (reason_len > (u64)(end - *buf))
		return -EINVAL;
	*buf += reason_len;
	return 0;
}

static int skip_quic_stream_frame(const u8 **buf, const u8 *end, u64 ftype)
{
	u64 stream_id, offset = 0, length = 0;

	if (quic_read_vint_safe(buf, end, &stream_id) < 0)
		return -EINVAL;
	if ((ftype & 0x04) && quic_read_vint_safe(buf, end, &offset) < 0)
		return -EINVAL;
	if (ftype & 0x02) {
		if (quic_read_vint_safe(buf, end, &length) < 0)
			return -EINVAL;
		if (length > (u64)(end - *buf))
			return -EINVAL;
		*buf += length;
		return 0;
	}
	*buf = end;
	return 0;
}

static int parse_quic_crypto_frame(const u8 **buf, const u8 *end,
				   struct quic_flow_entry *flow)
{
	u64 crypto_off, crypto_len;

	if (quic_read_vint_safe(buf, end, &crypto_off) < 0)
		return -EINVAL;
	if (quic_read_vint_safe(buf, end, &crypto_len) < 0)
		return -EINVAL;
	if (crypto_len > (u64)(end - *buf))
		return -EINVAL;
	update_flow_crypto_data(flow, crypto_off, *buf, crypto_len);
	*buf += crypto_len;
	return 0;
}

static int skip_or_parse_quic_frame(const u8 **fp_ptr, const u8 *fp_end,
				    struct quic_flow_entry *flow)
{
	u64 ftype;

	if (quic_read_vint_safe(fp_ptr, fp_end, &ftype) < 0)
		return -EINVAL;
	if (ftype >= 0x08 && ftype <= 0x0F)
		return skip_quic_stream_frame(fp_ptr, fp_end, ftype);
	switch (ftype) {
	case 0x00:
	case 0x01:
		return 0;
	case 0x02:
	case 0x03:
		return skip_quic_ack_frame(fp_ptr, fp_end, ftype);
	case 0x04:
		return skip_quic_vints(fp_ptr, fp_end, 3);
	case 0x05:
		return skip_quic_vints(fp_ptr, fp_end, 2);
	case 0x06:
		return parse_quic_crypto_frame(fp_ptr, fp_end, flow);
	case 0x07:
		return skip_quic_token_frame(fp_ptr, fp_end);
	case 0x10:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x16:
	case 0x17:
		return skip_quic_vints(fp_ptr, fp_end, 1);
	case 0x11:
	case 0x15:
		return skip_quic_vints(fp_ptr, fp_end, 2);
	case 0x18:
		return skip_quic_new_cid_frame(fp_ptr, fp_end);
	case 0x19:
		return skip_quic_vints(fp_ptr, fp_end, 1);
	case 0x1a:
	case 0x1b:
		if ((size_t)(fp_end - *fp_ptr) < 8)
			return -EINVAL;
		*fp_ptr += 8;
		return 0;
	case 0x1c:
	case 0x1d:
		return skip_quic_cc_frame(fp_ptr, fp_end, ftype);
	default:
		return -EINVAL;
	}
}

int parse_quic_sni(const struct sk_buff *skb, int offset, int avail_len,
		   char *out_sni, int max_sni_len)
{
	u8 packet_buf[1500], crypt_buf[1500], sample[16], mask[16], iv[12];
	size_t pkt_buf_sz = sizeof(packet_buf);
	size_t crypt_buf_sz = sizeof(crypt_buf);
	int len = min_t(int, avail_len, pkt_buf_sz);
	struct skcipher_request *hp_req = NULL;
	struct aead_request *aead_req = NULL;
	struct quic_flow_entry *flow = NULL;
	struct scatterlist sg_hp, sg_aead;
	const u8 *data, *p, *end, *fp, *fp_end;
	u32 version, truncated_pn = 0;
	u64 token_len, pkt_payload_len, full_pn = 0;
	int dcid_off, pn_off, header_len, cipher_len, total_aead_len;
	int ret = -EINVAL, sni_ret, i;
	u8 first_byte, dcil, scil, pn_len;

	if (!skb || !out_sni || max_sni_len <= 1 || avail_len <= 0)
		return -EINVAL;
	data = skb_header_pointer(skb, offset, len, packet_buf);
	if (!data || len < 64)
		return -EINVAL;
	if (data != packet_buf)
		memcpy(packet_buf, data, len);
	first_byte = packet_buf[0];
	if ((first_byte & 0x80) == 0 || ((first_byte & 0x30) >> 4) != 0x00)
		return -EINVAL;
	p = packet_buf + 1;
	end = packet_buf + len;
	if ((size_t)(end - p) < 4)
		return -EINVAL;
	version = get_unaligned_be32(p);
	p += 4;
	if (version != 0x00000001)
		return -EINVAL;
	if (p >= end)
		return -EINVAL;
	dcil = *p++;
	if (dcil == 0 || dcil > 20 || dcil > (size_t)(end - p))
		return -EINVAL;
	dcid_off = p - packet_buf;
	p += dcil;
	if (p >= end)
		return -EINVAL;
	scil = *p++;
	if (scil > (size_t)(end - p))
		return -EINVAL;
	p += scil;
	if (quic_read_vint_safe(&p, end, &token_len) < 0 ||
	    token_len > (u64)(end - p))
		return -EINVAL;
	p += token_len;

	if (quic_read_vint_safe(&p, end, &pkt_payload_len) < 0)
		return -EINVAL;
	pn_off = p - packet_buf;
	if (pkt_payload_len > (u64)(len - pn_off))
		return -EINVAL;
	flow = get_or_create_flow(packet_buf + dcid_off, dcil);
	if (!flow)
		return -EINVAL;
	spin_lock_bh(&flow->lock);
	if (flow->completed) {
		spin_unlock_bh(&flow->lock);
		ret = -EINVAL;
		goto out_put_flow;
	}
	spin_unlock_bh(&flow->lock);
	if ((size_t)(end - (packet_buf + pn_off)) < 4 + 16 ||
	    pkt_payload_len < 4 + 16) {
		ret = -EINVAL;
		goto out_put_flow;
	}
	memcpy(sample, packet_buf + pn_off + 4, 16);
	sg_init_one(&sg_hp, sample, 16);

	hp_req = skcipher_request_alloc(&quic_crypto_ctx.hp_tfm->base, GFP_ATOMIC);
	if (!hp_req) {
		ret = -ENOMEM;
		goto out_put_flow;
	}
	spin_lock_bh(&quic_crypto_ctx.lock);
	ret = crypto_sync_skcipher_setkey(quic_crypto_ctx.hp_tfm, flow->hp_key, 16);
	if (ret) {
		spin_unlock_bh(&quic_crypto_ctx.lock);
		goto out_free_hp;
	}
	skcipher_request_set_crypt(hp_req, &sg_hp, &sg_hp, 16, NULL);
	ret = crypto_skcipher_encrypt(hp_req);
	spin_unlock_bh(&quic_crypto_ctx.lock);
	if (ret)
		goto out_free_hp;
	memcpy(mask, sample, 16);
	packet_buf[0] ^= (mask[0] & 0x0F);
	pn_len = (packet_buf[0] & 0x03) + 1;
	header_len = pn_off + pn_len;
	if (pkt_payload_len < (u64)(pn_len + 16)) {
		ret = -EINVAL;
		goto out_free_hp;
	}
	cipher_len = pkt_payload_len - pn_len;

	for (i = 0; i < pn_len; i++) {
		packet_buf[pn_off + i] ^= mask[1 + i];
		truncated_pn = (truncated_pn << 8) | packet_buf[pn_off + i];
	}
	spin_lock_bh(&flow->lock);
	full_pn = decode_packet_number(flow->largest_pn, truncated_pn,
				       pn_len * 8, flow->have_largest_pn);
	spin_unlock_bh(&flow->lock);
	memcpy(iv, flow->iv, 12);
	for (i = 0; i < 8; i++)
		iv[12 - 1 - i] ^= (full_pn >> (i * 8)) & 0xFF;
	total_aead_len = header_len + cipher_len;
	if (total_aead_len > (int)crypt_buf_sz) {
		ret = -ENOMEM;
		goto out_free_hp;
	}
	memcpy(crypt_buf, packet_buf, header_len);
	memcpy(crypt_buf + header_len, packet_buf + header_len, cipher_len);
	sg_init_one(&sg_aead, crypt_buf, total_aead_len);
	aead_req = aead_request_alloc(quic_crypto_ctx.aead_tfm, GFP_ATOMIC);
	if (!aead_req) {
		ret = -ENOMEM;
		goto out_free_hp;
	}
	spin_lock_bh(&quic_crypto_ctx.lock);
	ret = crypto_aead_setkey(quic_crypto_ctx.aead_tfm, flow->key, 16);
	if (ret) {
		spin_unlock_bh(&quic_crypto_ctx.lock);
		goto out_free_aead;
	}
	ret = crypto_aead_setauthsize(quic_crypto_ctx.aead_tfm, 16);
	if (ret) {
		spin_unlock_bh(&quic_crypto_ctx.lock);
		goto out_free_aead;
	}
	aead_request_set_ad(aead_req, header_len);
	aead_request_set_crypt(aead_req, &sg_aead, &sg_aead, cipher_len, iv);
	ret = crypto_aead_decrypt(aead_req);
	spin_unlock_bh(&quic_crypto_ctx.lock);
	if (ret)
		goto out_free_aead;
	spin_lock_bh(&flow->lock);
	if (!flow->have_largest_pn || full_pn > flow->largest_pn) {
		flow->largest_pn = full_pn;
		flow->have_largest_pn = true;
	}
	spin_unlock_bh(&flow->lock);

	fp = crypt_buf + header_len;
	fp_end = fp + (cipher_len - 16);
	ret = -ENOENT;
	spin_lock_bh(&flow->lock);
	while (fp < fp_end) {
		if (skip_or_parse_quic_frame(&fp, fp_end, flow) < 0) {
			ret = -EINVAL;
			break;
		}
	}
	if (ret != -EINVAL && flow->assembled_len >= 38) {
		sni_ret = extract_sni_from_client_hello(flow->crypto_buf, flow->assembled_len, out_sni, max_sni_len);
		if (sni_ret == 0) {
			flow->completed = true;
			ret = 0;
		}
		if (sni_ret == -EAGAIN)
			ret = -EAGAIN;
	}
	spin_unlock_bh(&flow->lock);

out_free_aead:
	if (aead_req)
		aead_request_free(aead_req);
out_free_hp:
	if (hp_req)
		skcipher_request_free(hp_req);
out_put_flow:
	flow_put(flow);
	return ret;
}

int parse_tls_sni(const struct sk_buff *skb, int offset, int avail_len,
		  char *out_sni, int max_len)
{
	u8 buf[512];
	size_t buf_sz = sizeof(buf);
	int len = min_t(int, avail_len, buf_sz);
	const u8 *data;

	if (!skb || !out_sni || max_len <= 1 || avail_len <= 0)
		return -EINVAL;
	data = skb_header_pointer(skb, offset, len, buf);
	if (!data || len < 43)
		return -EINVAL;
	if (data[0] != 0x16 || data[1] != 0x03)
		return -EINVAL;
	if (data[2] != 0x01 && data[2] != 0x02 && data[2] != 0x03)
		return -EINVAL;
	return extract_sni_from_client_hello(&data[5], len - 5, out_sni, max_len);
}

int parse_qname_strict(const struct sk_buff *skb, int offset, int avail_len,
		       char *out_domain, int out_len, uint16_t *qtype,
		       uint16_t *qclass)
{
	int src = 0, dst = 0, wire_len = 0;
	u8 label_buf[MAX_LABEL_LEN];
	const u8 *byte_ptr, *label_ptr;
	u8 byte_val;
	__be16 type_class[2];
	const __be16 *tc_ptr;

	if (!skb || !out_domain || out_len <= 0 || !qtype || !qclass ||
	    avail_len <= 0)
		return -EINVAL;
	while (src < avail_len) {
		byte_ptr = skb_header_pointer(skb, offset + src, 1, &byte_val);
		if (!byte_ptr)
			return -EINVAL;
		byte_val = *byte_ptr;
		src++;
		wire_len++;
		if (byte_val == 0)
			break;
		if ((byte_val & 0xC0) != 0)
			return -EINVAL;
		if (byte_val > MAX_LABEL_LEN ||
		    (size_t)(avail_len - src) < byte_val)
			return -EINVAL;
		wire_len += byte_val;
		if (wire_len > MAX_DOMAIN_WIRE_LEN)
			return -EINVAL;
		if (dst + byte_val + (dst > 0 ? 1 : 0) + 1 > out_len)
			return -EINVAL;
		if (dst > 0)
			out_domain[dst++] = '.';
		label_ptr = skb_header_pointer(skb, offset + src, byte_val, label_buf);
		if (!label_ptr)
			return -EINVAL;
		memcpy(&out_domain[dst], label_ptr, byte_val);
		dst += byte_val;
		src += byte_val;
	}
	if (wire_len > MAX_DOMAIN_WIRE_LEN)
		return -EINVAL;
	out_domain[dst] = '\0';
	if ((size_t)(avail_len - src) < 4)
		return -EINVAL;
	tc_ptr = skb_header_pointer(skb, offset + src, 4, type_class);
	if (!tc_ptr)
		return -EINVAL;
	*qtype = get_unaligned_be16(&tc_ptr[0]);
	*qclass = get_unaligned_be16(&tc_ptr[1]);
	return src + 4;
}
