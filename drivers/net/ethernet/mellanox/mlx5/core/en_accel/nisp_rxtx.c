// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/ip6_checksum.h>
#include <net/psp/types.h>

#include "en.h"
#include "../nisp.h"
#include "en_accel/nisp_rxtx.h"
#include "en_accel/nisp.h"
#include "lib/psp_defs.h"

static void mlx5e_nisp_set_swp(struct sk_buff *skb,
			       struct mlx5e_accel_tx_nisp_state *nisp_st,
			       struct mlx5_wqe_eth_seg *eseg)
{
	/* Tunnel Mode:
	 * SWP:      OutL3       InL3  InL4
	 * Pkt: MAC  IP     ESP  IP    L4
	 *
	 * Transport Mode:
	 * SWP:      OutL3       OutL4
	 * Pkt: MAC  IP     ESP  L4
	 *
	 * Tunnel(VXLAN TCP/UDP) over Transport Mode
	 * SWP:      OutL3                   InL3  InL4
	 * Pkt: MAC  IP     ESP  UDP  VXLAN  IP    L4
	 */
	u8 inner_ipproto = 0;
	struct ethhdr *eth;

	/* Shared settings */
	eseg->swp_outer_l3_offset = skb_network_offset(skb) / 2;
	if (skb->protocol == htons(ETH_P_IPV6))
		eseg->swp_flags |= MLX5_ETH_WQE_SWP_OUTER_L3_IPV6;

	if (skb->inner_protocol_type == ENCAP_TYPE_IPPROTO) {
		inner_ipproto = skb->inner_ipproto;
		/* Set SWP additional flags for packet of type IP|UDP|PSP|[ TCP | UDP ] */
		switch (inner_ipproto) {
		case IPPROTO_UDP:
			eseg->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L4_UDP;
			fallthrough;
		case IPPROTO_TCP:
			eseg->swp_inner_l4_offset = skb_inner_transport_offset(skb) / 2;
			break;
		default:
			break;
		}
	} else {
		/* IP in IP tunneling like vxlan*/
		if (skb->inner_protocol_type != ENCAP_TYPE_ETHER)
			return;

		eth = (struct ethhdr *)skb_inner_mac_header(skb);
		switch (ntohs(eth->h_proto)) {
		case ETH_P_IP:
			inner_ipproto = ((struct iphdr *)((char *)skb->data +
					 skb_inner_network_offset(skb)))->protocol;
			break;
		case ETH_P_IPV6:
			inner_ipproto = ((struct ipv6hdr *)((char *)skb->data +
					 skb_inner_network_offset(skb)))->nexthdr;
			break;
		default:
			break;
		}

		/* Tunnel(VXLAN TCP/UDP) over Transport Mode PSP i.e. PSP payload is vxlan tunnel */
		switch (inner_ipproto) {
		case IPPROTO_UDP:
			eseg->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L4_UDP;
			fallthrough;
		case IPPROTO_TCP:
			eseg->swp_inner_l3_offset = skb_inner_network_offset(skb) / 2;
			eseg->swp_inner_l4_offset =
				(skb->csum_start + skb->head - skb->data) / 2;
			if (skb->protocol == htons(ETH_P_IPV6))
				eseg->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L3_IPV6;
			break;
		default:
			break;
		}

		nisp_st->inner_ipproto = inner_ipproto;
	}
}

static bool mlx5e_nisp_set_state(struct mlx5e_priv *priv,
				struct sk_buff *skb,
				struct mlx5e_accel_tx_nisp_state *nisp_st)
{
	struct psp_assoc *pas;
	bool ret = false;

	rcu_read_lock();
	pas = psp_skb_get_assoc_rcu(skb);
	if (!pas)
		goto out;

	ret = true;
	nisp_st->tailen = PSP_ICV_LENGTH;
	nisp_st->spi = pas->tx.spi;
	memcpy(&nisp_st->keyid, pas->drv_data, sizeof(nisp_st->keyid));

out:
	rcu_read_unlock();
	return ret;
}

void mlx5e_nisp_tx_build_eseg(struct mlx5e_priv *priv, struct sk_buff *skb,
			      struct mlx5e_accel_tx_nisp_state *nisp_st,
			      struct mlx5_wqe_eth_seg *eseg)
{
	if (!mlx5_is_nisp_device(priv->mdev))
		return;

	if (unlikely(skb->protocol != htons(ETH_P_IP) &&
		     skb->protocol != htons(ETH_P_IPV6)))
		return;

	mlx5e_nisp_set_swp(skb, nisp_st, eseg);
	/* Special WA for PSP LSO in ConnectX7 */
	eseg->swp_outer_l3_offset = 0;
	eseg->swp_inner_l3_offset = 0;

	eseg->flow_table_metadata |= cpu_to_be32(nisp_st->keyid);
	eseg->trailer |= cpu_to_be32(MLX5_ETH_WQE_INSERT_TRAILER) |
			 cpu_to_be32(MLX5_ETH_WQE_TRAILER_HDR_OUTER_L4_ASSOC);
}

void mlx5e_nisp_handle_tx_wqe(struct mlx5e_tx_wqe *wqe,
			      struct mlx5e_accel_tx_nisp_state *nisp_st,
			      struct mlx5_wqe_inline_seg *inlseg)
{
	inlseg->byte_count = cpu_to_be32(nisp_st->tailen | MLX5_INLINE_SEG);
}

static void psp_write_headers(struct net *net, struct sk_buff *skb,
			      __be32 spi, unsigned int udp_len,
			      bool has_sport, __be16 sport)
{
	struct udphdr *uh = udp_hdr(skb);
	struct psphdr *psph = (struct psphdr *)(uh + 1);

	uh->dest = htons(PSP_UDP_DPORT);
	uh->source = has_sport ? sport : udp_flow_src_port(net, skb, 0, 0, false);
	uh->check = 0;
	uh->len = htons(udp_len);

	psph->nexthdr = IPPROTO_TCP;
	psph->hdrlen = (sizeof(struct psphdr) - 8) >> 3;
	psph->crypt_offset = 0;
	psph->verfl = 1;         /* reserved 0, version 0, V = 1 */
	psph->spi = spi;
	memset(&psph->iv, 0, sizeof(psph->iv));
}

/* Encapsulate a TCP packet with PSP by adding the UDP+PSP headers and filling
 * them in.
 */
static void psp_encapsulate(struct net *net, struct sk_buff *skb,
__be32 spi, bool has_sport, __be16 sport)
{
	u32 network_len = skb_network_header_len(skb);
	u32 ethr_len = skb_mac_header_len(skb);
	u32 bufflen = ethr_len + network_len;
	struct ipv6hdr *ip6;
	u8 *buff;

	buff = kzalloc(bufflen, GFP_ATOMIC);
	if (!buff)
		return;

	skb_copy_from_linear_data(skb, buff, bufflen);
	if (skb_cow_head(skb, PSP_ENCAP_HLEN))
		return;

	skb_push(skb, PSP_ENCAP_HLEN);
	skb_copy_to_linear_data(skb, buff, bufflen);
	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, ethr_len);
	skb_set_transport_header(skb, skb_network_offset(skb) + network_len);
	ip6 = ipv6_hdr(skb);
	skb_set_inner_ipproto(skb, IPPROTO_TCP);
	ip6->nexthdr = IPPROTO_UDP;
	ip6->payload_len = htons(ntohs(ip6->payload_len) + PSP_ENCAP_HLEN);
	skb_set_inner_transport_header(skb, skb_transport_offset(skb) + PSP_ENCAP_HLEN);
	skb->encapsulation = 1;
	psp_write_headers(net, skb, spi, skb->len - skb_transport_offset(skb),
			  has_sport, sport);
	kfree(buff);
}

bool mlx5e_nisp_handle_tx_skb(struct net_device *netdev,
			      struct sk_buff *skb,
			      struct mlx5e_accel_tx_nisp_state *nisp_st)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct net *net = sock_net(skb->sk);
	const struct ipv6hdr *ip6;
	struct tcphdr *th;

	if (!mlx5e_nisp_set_state(priv, skb, nisp_st))
		return true;

	/* psp_encap of the packet */
	psp_encapsulate(net, skb, nisp_st->spi, false, 0);
	if (skb_is_gso(skb)) {
		ip6 = ipv6_hdr(skb);
		th = inner_tcp_hdr(skb);

		th->check = ~tcp_v6_check(skb_shinfo(skb)->gso_size + inner_tcp_hdrlen(skb), &ip6->saddr,
				&ip6->daddr, 0);
	}

	return true;
}
