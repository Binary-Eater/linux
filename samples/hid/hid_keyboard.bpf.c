// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hid_bpf_helpers.h"

#define HID_GD_KEYBOARD 0x00010006

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_key_event, struct hid_bpf_ctx *hctx)
{
	// TODO fix size for generic keyboard report descriptor
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 5 /* size */);

	if (!data)
		return 0; /* EPERM check */

	if (hctx->hid->collection->usage != HID_GD_KEYBOARD) {
		bpf_printk("Received a non-keyboard HID report with usage %#x\n",
			   hctx->hid->collection->usage);
		return 0; /* EINVAL check */
	}

	// TODO figure out what can be dumped
	bpf_printk("event: size: %d", hctx->size);
	bpf_printk("incoming event: %02x %02x %02x", data[0], data[1], data[2]);
	bpf_printk("                %02x %02x %02x",
		   data[3],
		   data[4],
		   data[5]);
	bpf_printk("                %02x %02x %02x",
		   data[6],
		   data[7],
		   data[8]);
}

char _license[] SEC("license") = "GPL";
