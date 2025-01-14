#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b422224, "init_net" },
	{ 0x85cafbf5, "nf_register_net_hook" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xd8eae794, "nf_unregister_net_hook" },
	{ 0xd36dc10c, "get_random_u32" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0xb47cca30, "csum_ipv6_magic" },
	{ 0x2472f2b, "__pskb_pull_tail" },
	{ 0xfaf9bb1b, "dev_get_by_index" },
	{ 0x46a241aa, "eth_type_trans" },
	{ 0xa672ce0a, "__dev_queue_xmit" },
	{ 0x2031ced4, "kfree_skb_reason" },
	{ 0xc9d7e676, "module_layout" },
};

MODULE_INFO(depends, "");

