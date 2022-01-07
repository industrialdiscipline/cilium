// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2016-2022 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#define ENABLE_NODEPORT
#include <node_config.h>

#define DEBUG

#include <lib/dbg.h>
#include <lib/common.h>
#include <lib/nat.h>

__section("action/test-nat4-icmp-frag-needed-icmp")
int test_nat4_icmp_frag_needed_icmp(struct __ctx_buff __maybe_unused *ctx)
{
	struct ipv4_nat_entry ostate;
	struct ipv4_ct_tuple otuple = (struct ipv4_ct_tuple){
		.saddr = bpf_htonl(16843009),  /* 1.1.1.1 */
		.daddr = bpf_htonl(33686017),  /* 2.2.2.1 */
		.sport = bpf_htons(123),
		.nexthdr = IPPROTO_ICMP,
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(50529025),  /* 3.3.3.1 */
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	int ret;

	/* Assuming that, a Pod with IP(1.1.1.1) is sending a packet to
	 * IP(2.2.2.1). To join the world the packet will pass through
	 * Host(3.3.3.1).
	 *
	 * We instruct the SNAT table in such a way that the ICMP Error
	 * packet generated in input should join Pod.
	 */

	ret = snat_v4_new_mapping(ctx, &otuple, &ostate, &target);
	if (ret != 0)
		goto out;

	ret = snat_v4_process(ctx, NAT_DIR_INGRESS, &target, false);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

__section("action/test-nat4-icmp-frag-needed-tcp")
int test_nat4_icmp_frag_needed_tcp(struct __ctx_buff __maybe_unused *ctx)
{
	struct ipv4_nat_entry ostate;
	struct ipv4_ct_tuple otuple = (struct ipv4_ct_tuple){
		.saddr = bpf_htonl(16843009),  /* 1.1.1.1 */
		.daddr = bpf_htonl(33686017),  /* 2.2.2.1 */
		.sport = bpf_htons(3030),
		.dport = bpf_htons(8080),
		.nexthdr = IPPROTO_TCP,
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(50529025),  /* 3.3.3.1 */
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	int ret;

	/* Assuming that, a Pod with IP(1.1.1.1) is sending a packet to
	 * IP(2.2.2.1). To join the world the packet will pass through
	 * Host(3.3.3.1).
	 *
	 * We instruct the SNAT table in such a way that the ICMP Error
	 * packet generated in input should join Pod.
	 */

	ret = snat_v4_new_mapping(ctx, &otuple, &ostate, &target);
	if (ret != 0)
		goto out;

	ret = snat_v4_process(ctx, NAT_DIR_INGRESS, &target, false);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

__section("action/test-nat4-icmp-frag-needed-udp")
int test_nat4_icmp_frag_needed_udp(struct __ctx_buff __maybe_unused *ctx)
{
	struct ipv4_nat_entry ostate;
	struct ipv4_ct_tuple otuple = (struct ipv4_ct_tuple){
		.saddr = bpf_htonl(16843009),  /* 1.1.1.1 */
		.daddr = bpf_htonl(33686017),  /* 2.2.2.1 */
		.sport = bpf_htons(3030),
		.dport = bpf_htons(8080),
		.nexthdr = IPPROTO_UDP,
		.flags = 0,
	};
	struct ipv4_nat_target target = {
		.addr = bpf_htonl(50529025),  /* 3.3.3.1 */
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	int ret;

	/* Assuming that, a Pod with IP(1.1.1.1) is sending a packet to
	 * IP(2.2.2.1). To join the world the packet will pass through
	 * Host(3.3.3.1).
	 *
	 * We instruct the SNAT table in such a way that the ICMP Error
	 * packet generated in input should join Pod.
	 */

	ret = snat_v4_new_mapping(ctx, &otuple, &ostate, &target);
	if (ret != 0)
		goto out;

	ret = snat_v4_process(ctx, NAT_DIR_INGRESS, &target, false);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

__section("action/test-nat6-icmp-frag-needed-icmp")
int test_nat6_icmp_frag_needed_icmp(struct __ctx_buff __maybe_unused *ctx)
{
	struct ipv6_nat_entry ostate;
	struct ipv6_ct_tuple otuple = (struct ipv6_ct_tuple){
		.saddr.p1 = bpf_htonl(0x20010db8),
		.saddr.p2 = bpf_htonl(0x1),
		.saddr.p3 = bpf_htonl(0x0),
		.saddr.p4 = bpf_htonl(0x1),
		.daddr.p1 = bpf_htonl(0x20010db8),
		.daddr.p2 = bpf_htonl(0x2),
		.daddr.p3 = bpf_htonl(0x0),
		.daddr.p4 = bpf_htonl(0x1),
		.sport = bpf_htons(123),
		.nexthdr = IPPROTO_ICMPV6,
	};
	struct ipv6_nat_target target = {
		.addr.p1 = bpf_htonl(0x20010db8),
		.addr.p2 = bpf_htonl(0x3),
		.addr.p3 = bpf_htonl(0x0),
		.addr.p4 = bpf_htonl(0x1),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	int ret;

	/* Assuming that, a Pod with IP(2001:db8:0:1::1) is sending a packet to
	 * IP(2001:db8:0:2::1). To join the world the packet will pass through
	 * Host(2001:db8:0:3::1).
	 *
	 * We instruct the SNAT table in such a way that the ICMP Error
	 * packet generated in input should join Pod.
	 */

	ret = snat_v6_new_mapping(ctx, &otuple, &ostate, &target);
	if (ret != 0)
		goto out;

	ret = snat_v6_process(ctx, NAT_DIR_INGRESS, &target);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

__section("action/test-nat6-icmp-frag-needed-tcp")
int test_nat6_icmp_frag_needed_tcp(struct __ctx_buff __maybe_unused *ctx)
{
	struct ipv6_nat_entry ostate;
	struct ipv6_ct_tuple otuple = (struct ipv6_ct_tuple){
		.saddr.p1 = bpf_htonl(0x20010db8),
		.saddr.p2 = bpf_htonl(0x1),
		.saddr.p3 = bpf_htonl(0x0),
		.saddr.p4 = bpf_htonl(0x1),
		.daddr.p1 = bpf_htonl(0x20010db8),
		.daddr.p2 = bpf_htonl(0x2),
		.daddr.p3 = bpf_htonl(0x0),
		.daddr.p4 = bpf_htonl(0x1),
		.sport = bpf_htons(3030),
		.dport = bpf_htons(8080),
		.nexthdr = IPPROTO_TCP,
	};
	struct ipv6_nat_target target = {
		.addr.p1 = bpf_htonl(0x20010db8),
		.addr.p2 = bpf_htonl(0x3),
		.addr.p3 = bpf_htonl(0x0),
		.addr.p4 = bpf_htonl(0x1),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	int ret;

	/* Assuming that, a Pod with IP(2001:db8:0:1::1) is sending a packet to
	 * IP(2001:db8:0:2::1). To join the world the packet will pass through
	 * Host(2001:db8:0:3::1).
	 *
	 * We instruct the SNAT table in such a way that the ICMP Error
	 * packet generated in input should join Pod.
	 */

	ret = snat_v6_new_mapping(ctx, &otuple, &ostate, &target);
	if (ret != 0)
		goto out;

	ret = snat_v6_process(ctx, NAT_DIR_INGRESS, &target);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

__section("action/test-nat6-icmp-frag-needed-udp")
int test_nat6_icmp_frag_needed_udp(struct __ctx_buff __maybe_unused *ctx)
{
	struct ipv6_nat_entry ostate;
	struct ipv6_ct_tuple otuple = (struct ipv6_ct_tuple){
		.saddr.p1 = bpf_htonl(0x20010db8),
		.saddr.p2 = bpf_htonl(0x1),
		.saddr.p3 = bpf_htonl(0x0),
		.saddr.p4 = bpf_htonl(0x1),
		.daddr.p1 = bpf_htonl(0x20010db8),
		.daddr.p2 = bpf_htonl(0x2),
		.daddr.p3 = bpf_htonl(0x0),
		.daddr.p4 = bpf_htonl(0x1),
		.sport = bpf_htons(3030),
		.dport = bpf_htons(8080),
		.nexthdr = IPPROTO_UDP,
	};
	struct ipv6_nat_target target = {
		.addr.p1 = bpf_htonl(0x20010db8),
		.addr.p2 = bpf_htonl(0x3),
		.addr.p3 = bpf_htonl(0x0),
		.addr.p4 = bpf_htonl(0x1),
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MIN_NAT + 1,
	};
	int ret;

	/* Assuming that, a Pod with IP(2001:db8:0:1::1) is sending a packet to
	 * IP(2001:db8:0:2::1). To join the world the packet will pass through
	 * Host(2001:db8:0:3::1).
	 *
	 * We instruct the SNAT table in such a way that the ICMP Error
	 * packet generated in input should join Pod.
	 */

	ret = snat_v6_new_mapping(ctx, &otuple, &ostate, &target);
	if (ret != 0)
		goto out;

	ret = snat_v6_process(ctx, NAT_DIR_INGRESS, &target);
	cilium_dbg(ctx, DBG_UNSPEC, 1000, ret);
out:
	/* mark the termination of our program so that the go program stops
	 * blocking on the ring buffer
	 */
	cilium_dbg(ctx, DBG_UNSPEC, 0xe3d, 0xe3d);
	return ret;
}

BPF_LICENSE("GPL");
