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

enum {
	MLX5E_NISP_OFFLOAD_RX_SYNDROME_DECRYPTED,
	MLX5E_NISP_OFFLOAD_RX_SYNDROME_AUTH_FAILED,
	MLX5E_NISP_OFFLOAD_RX_SYNDROME_BAD_TRAILER,
};

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

void mlx5e_nisp_csum_complete(struct net_device *netdev, struct sk_buff* skb)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_nisp *nisp = priv->nisp;
	__wsum csumdiff;

	goto trim_skb;
	skb->csum = csum_block_sub(skb->csum, nisp->psphdrsum, PSP_ENCAP_HLEN);
	csumdiff = csum_partial(skb->data + skb->len - PSP_ICV_LENGTH, PSP_ENCAP_HLEN, 0);
	skb->csum = csum_block_sub(skb->csum, csumdiff, skb->len - PSP_ICV_LENGTH);
trim_skb:
	pskb_trim(skb, skb->len - PSP_ICV_LENGTH);
}

/* Receive handler for PSP packets.
 *
 * Presently it accepts only already-authenticated packets and does not
 * support optional fields, such as virtualization cookies.
 */
static int psp_rcv(struct net_device *netdev, struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_nisp *mnisp = priv->mdev->nisp;
	struct mlx5e_nisp *nisp = priv->nisp;
	const struct psphdr *psph;
	struct psp_skb_ext *pse;
	struct ipv6hdr *ipv6h;
	int depth = 0;
	__be32 spi;
	u8 *buff;
	u16 gen;
	u8 ver;

	__vlan_get_protocol(skb, eth->h_proto, &depth);
	ipv6h = (struct ipv6hdr *)(skb->data + depth);
	depth += sizeof(*ipv6h);
	buff = kzalloc(depth, GFP_KERNEL);
	if(!buff)
		return -ENOMEM;
	nisp->psphdrsum = csum_partial(skb->data + depth, PSP_ENCAP_HLEN, 0);
	psph = (const struct psphdr *) (skb->data + depth + sizeof(struct udphdr));
	spi = psph->spi;
	gen = mnisp->key_gen_arr[(ntohl(psph->spi) >> 31) & 0x1];
	ver = (psph->verfl >> 2) & 0xF;
	if (unlikely(!pskb_may_pull(skb, PSP_ENCAP_HLEN)))
		goto drop;

	/* pull UDP+PSP headers and make adjustments (we actually supports only ipv6 at this point) */
	ipv6h->nexthdr = psph->nexthdr;
	ipv6h->payload_len =
		htons(ntohs(ipv6h->payload_len) - PSP_ENCAP_HLEN - PSP_ICV_LENGTH);
	skb_copy_from_linear_data(skb, buff, depth);
	skb_pull(skb, PSP_ENCAP_HLEN);
	skb_copy_to_linear_data(skb, buff, depth);
	pse = skb_ext_add_inplace(skb, SKB_EXT_PSP);
	if (!pse)
		goto drop;

	pse->generation = gen;
	pse->spi = spi;
	pse->version = ver;

	kfree(buff);
	return 0;
drop:
	kfree_skb_reason(skb, SKB_DROP_REASON_PSP_OUTPUT);
	kfree(buff);
	return 0;
}

void mlx5e_nisp_offload_handle_rx_skb(struct net_device *netdev, struct sk_buff *skb,
				      struct mlx5_cqe64 *cqe)
{
	u32 nisp_meta_data = be32_to_cpu(cqe->ft_metadata);

	/* TBD: report errors as SW counters to ethtool, any further handling ? */
	switch (MLX5_NISP_METADATA_SYNDROM(nisp_meta_data)) {
	case MLX5E_NISP_OFFLOAD_RX_SYNDROME_DECRYPTED:
		psp_rcv(netdev, skb);
		skb->decrypted = 1;
		break;
	case MLX5E_NISP_OFFLOAD_RX_SYNDROME_AUTH_FAILED:
		break;
	case MLX5E_NISP_OFFLOAD_RX_SYNDROME_BAD_TRAILER:
		break;
	default:
		break;
	}
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
