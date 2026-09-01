// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

atomic_t total_packets_hooked = ATOMIC_INIT(0);
atomic_t total_dns_detected = ATOMIC_INIT(0);
static int __net_init stealth_net_ns_init(struct net *net)
{
	return nf_register_net_hooks(net, stealth_net_hooks, stealth_net_hooks_count);
}
static void __net_exit stealth_net_ns_exit(struct net *net)
{
	nf_unregister_net_hooks(net, stealth_net_hooks, stealth_net_hooks_count);
}

static struct pernet_operations stealth_net_ops = {
	.init = stealth_net_ns_init,
	.exit = stealth_net_ns_exit,
};

static int __init stealth_net_init(void)
{
	int ret;

	rules_table_init();
	events_fifo_init();

	ret = stealth_crypto_init();
	if (unlikely(ret)) {
		pr_err("[%s] Failed to initialize crypto engine: %d\n", TAG, ret);
		goto err_crypto;
	}
	ret = stealth_proc_init();
	if (unlikely(ret))
		goto err_proc;
	ret = stealth_sysfs_init();
	if (unlikely(ret))
		goto err_sysfs;
	ret = stealth_neigh_init();
	if (unlikely(ret))
		goto err_neigh;
	ret = stealth_tcp_init();
	if (unlikely(ret))
		goto err_tcp;
	ret = stealth_capture_init();
	if (unlikely(ret))
		goto err_capture;
	ret = stealth_ids_init();
	if (unlikely(ret))
		goto err_ids;
	ret = stealth_tunnel_init();
	if (unlikely(ret))
		goto err_tunnel;
	ret = register_pernet_subsys(&stealth_net_ops);
	if (unlikely(ret < 0))
		goto err_pernet;
	pr_info("[%s] Stealth Net engine initialized in drivers/staging/stealth/\n", TAG);
	return 0;

err_pernet:
	stealth_tunnel_cleanup();
err_tunnel:
	stealth_ids_cleanup();
err_ids:
	stealth_capture_cleanup();
err_capture:
	stealth_tcp_cleanup();
err_tcp:
	stealth_neigh_cleanup();
err_neigh:
	stealth_sysfs_cleanup();
err_sysfs:
	stealth_proc_cleanup();
err_proc:
	stealth_crypto_cleanup();
err_crypto:
	rules_table_cleanup();
	return ret;
}

static void __exit stealth_net_exit(void)
{
	unregister_pernet_subsys(&stealth_net_ops);
	stealth_tunnel_cleanup();
	stealth_ids_cleanup();
	stealth_capture_cleanup();
	stealth_tcp_cleanup();
	stealth_neigh_cleanup();
	stealth_sysfs_cleanup();
	stealth_proc_cleanup();
	stealth_crypto_cleanup();
	rules_table_cleanup();
	pr_info("[%s] Stealth Net engine unloaded.\n", TAG);
}

module_init(stealth_net_init);
module_exit(stealth_net_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sakura Core");
MODULE_DESCRIPTION("Stealth Netfilter Engine in drivers/staging/stealth/");
