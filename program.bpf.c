// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation


#include <vmlinux.h>

/* I am directly including the 
value of the constants instead of 
the linux/if_ether.h header file and linux/pkt_cls.h
because of redeclration conflicts with
vmlinux.h */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/


#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>


SEC("classifier/egress/bit_flip")
int random_bit_flip(struct __sk_buff *skb) {

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (data >= data_end) {
        return TC_ACT_OK;
    }
        
    // Calculate the length of the packet data as an unsigned integer
    __u32 data_len = (__u32)(data_end - data);

    // Ensure the packet has valid length
    if (data_len < 1) {
        return TC_ACT_OK;
    }

    // Get a random offset and flip a bit
    __u32 random_offset = bpf_get_prandom_u32() % data_len;
    __u8 byte;

    // Use bpf_skb_load_bytes() to load the byte at the random offset
    if (bpf_skb_load_bytes(skb, random_offset, &byte, sizeof(byte)) < 0) {
        return TC_ACT_OK;  // Error in loading byte, return OK
    }
    
    // Flip a random bit in the byte
    __u8 random_bit = 1 << (bpf_get_prandom_u32() % 8);
    byte ^= random_bit;

    // Use bpf_skb_store_bytes() to store the modified byte back to the packet
    if (bpf_skb_store_bytes(skb, random_offset, &byte, sizeof(byte), 0) < 0) {
        return TC_ACT_OK;  // Error in storing byte, return OK
    }

    return TC_ACT_OK;
}
