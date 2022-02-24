/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5E_NISP_RXTX_H__
#define __MLX5E_NISP_RXTX_H__

#include <linux/skbuff.h>
#include <net/xfrm.h>
#include <net/psp.h>
#include "en.h"
#include "en/txrx.h"

struct mlx5e_accel_tx_nisp_state {
	u32 tailen;
	u32 keyid;
	__be32 spi;
	u8 inner_ipproto;
};

#ifdef CONFIG_MLX5_EN_PSP
static inline bool mlx5e_psp_is_offload_state(struct mlx5e_accel_tx_nisp_state* nisp_state)
{
	return (nisp_state->tailen != 0);
}

static inline bool mlx5e_psp_is_offload(struct sk_buff *skb, struct net_device *netdev)
{
	bool ret;

	rcu_read_lock();
	ret = !!psp_skb_get_assoc_rcu(skb);
	rcu_read_unlock();
	return ret;
}

bool mlx5e_nisp_handle_tx_skb(struct net_device *netdev,
			      struct sk_buff *skb,
			      struct mlx5e_accel_tx_nisp_state *nisp_st);

void mlx5e_nisp_tx_build_eseg(struct mlx5e_priv *priv, struct sk_buff *skb,
			      struct mlx5e_accel_tx_nisp_state *nisp_st,
			      struct mlx5_wqe_eth_seg *eseg);

void mlx5e_nisp_handle_tx_wqe(struct mlx5e_tx_wqe *wqe,
			      struct mlx5e_accel_tx_nisp_state *nisp_st,
			      struct mlx5_wqe_inline_seg *inlseg);

static inline bool mlx5e_nisp_txwqe_build_eseg_csum(struct mlx5e_txqsq *sq, struct sk_buff *skb,
						    struct mlx5e_accel_tx_nisp_state *nisp_st,
						    struct mlx5_wqe_eth_seg *eseg)
{
	u8 inner_ipproto;

	if (!mlx5e_psp_is_offload_state(nisp_st))
		return false;

	inner_ipproto = nisp_st->inner_ipproto;
	eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM;
	if (inner_ipproto) {
		eseg->cs_flags |= MLX5_ETH_WQE_L3_INNER_CSUM;
		if (inner_ipproto == IPPROTO_TCP || inner_ipproto == IPPROTO_UDP)
			eseg->cs_flags |= MLX5_ETH_WQE_L4_INNER_CSUM;
		if (likely(skb->ip_summed == CHECKSUM_PARTIAL))
			sq->stats->csum_partial_inner++;
	} else if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		eseg->cs_flags |= MLX5_ETH_WQE_L4_INNER_CSUM;
		sq->stats->csum_partial_inner++;
	}

	return true;
}

static inline unsigned int mlx5e_nisp_tx_ids_len(struct mlx5e_accel_tx_nisp_state *nisp_st)
{
	return nisp_st->tailen;
}
#else
static inline bool mlx5e_psp_is_offload_state(struct mlx5e_accel_tx_nisp_state* nisp_state)
{
	return false;
}

static inline bool mlx5e_psp_is_offload(struct sk_buff *skb, struct net_device *netdev)
{
	return false;
}

static inline bool mlx5e_nisp_txwqe_build_eseg_csum(struct mlx5e_txqsq *sq, struct sk_buff *skb,
						    struct mlx5e_accel_tx_nisp_state *nisp_st,
						    struct mlx5_wqe_eth_seg *eseg)
{
	return false;
}
#endif
#endif
