#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

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



static const char ____versions[]
__used __section("__versions") =
	"\x10\x00\x00\x00\x7e\x3a\x2c\x12"
	"_printk\0"
	"\x1c\x00\x00\x00\xca\x39\x82\x5b"
	"__x86_return_thunk\0\0"
	"\x20\x00\x00\x00\xd0\x19\x95\xc4"
	"nf_unregister_net_hook\0\0"
	"\x1c\x00\x00\x00\x11\x40\xcb\x6b"
	"dev_get_by_index\0\0\0\0"
	"\x18\x00\x00\x00\x0c\xc1\x6d\xd3"
	"get_random_u32\0\0"
	"\x18\x00\x00\x00\xbc\xbb\x13\xe1"
	"csum_partial\0\0\0\0"
	"\x18\x00\x00\x00\x30\xca\x7c\xb4"
	"csum_ipv6_magic\0"
	"\x1c\x00\x00\x00\x23\xbb\x43\x32"
	"__pskb_pull_tail\0\0\0\0"
	"\x1c\x00\x00\x00\x60\xa6\x43\xbc"
	"kfree_skb_reason\0\0\0\0"
	"\x14\x00\x00\x00\xbb\x6d\xfb\xbd"
	"__fentry__\0\0"
	"\x14\x00\x00\x00\xe6\xd0\xd7\x26"
	"init_net\0\0\0\0"
	"\x20\x00\x00\x00\xea\x74\x9b\x39"
	"nf_register_net_hook\0\0\0\0"
	"\x18\x00\x00\x00\xd7\xd3\x75\x6d"
	"module_layout\0\0\0"
	"\x00\x00\x00\x00\x00\x00\x00\x00";

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F28DDBA1A318648CC840494");
