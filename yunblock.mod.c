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
	"\x14\x00\x00\x00\xae\x5f\x7f\x06"
	"skb_copy\0\0\0\0"
	"\x10\x00\x00\x00\x63\xcd\x9a\x9e"
	"arp_tbl\0"
	"\x18\x00\x00\x00\x24\xfd\xde\x35"
	"neigh_lookup\0\0\0\0"
	"\x1c\x00\x00\x00\xb1\xdd\x22\xdb"
	"__dev_queue_xmit\0\0\0\0"
	"\x1c\x00\x00\x00\x60\xa6\x43\xbc"
	"kfree_skb_reason\0\0\0\0"
	"\x18\x00\x00\x00\x1b\x88\x33\x31"
	"neigh_destroy\0\0\0"
	"\x20\x00\x00\x00\x5f\x69\x96\x02"
	"refcount_warn_saturate\0\0"
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


MODULE_INFO(srcversion, "4BD3A817F40A55A644F01D8");
