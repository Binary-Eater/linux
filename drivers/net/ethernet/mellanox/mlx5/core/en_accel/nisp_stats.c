// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <linux/ethtool.h>
#include <net/sock.h>

#include "en.h"
#include "en_accel/nisp.h"

static const struct counter_desc mlx5e_nisp_hw_stats_desc[] = {
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_pkts) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_bytes) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_pkts_auth_fail) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_bytes_auth_fail) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_pkts_frame_err) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_bytes_frame_err) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_pkts_drop) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_rx_bytes_drop) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_tx_pkts) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_tx_bytes) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_tx_pkts_drop) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nisp_stats, psp_tx_bytes_drop) },
};

#define MLX5E_READ_CTR_ATOMIC64(ptr, dsc, i) \
	atomic64_read((atomic64_t *)((char *)(ptr) + (dsc)[i].offset))

#define NUM_NISP_HW_COUNTERS ARRAY_SIZE(mlx5e_nisp_hw_stats_desc)

static MLX5E_DECLARE_STATS_GRP_OP_NUM_STATS(nisp_hw)
{
	if (!priv->nisp)
		return 0;

	if (mlx5_is_nisp_device(priv->mdev))
		return NUM_NISP_HW_COUNTERS;

	return 0;
}

static MLX5E_DECLARE_STATS_GRP_OP_UPDATE_STATS(nisp_hw)
{
	if (!priv->nisp || !mlx5_is_nisp_device(priv->mdev))
		return;

	mlx5e_accel_nisp_get_stats_fill(priv, mlx5e_accel_nisp_get_stats(priv));
}

static MLX5E_DECLARE_STATS_GRP_OP_FILL_STRS(nisp_hw)
{
	unsigned int i;

	if (!priv->nisp || !mlx5_is_nisp_device(priv->mdev))
		return;

	for (i = 0; i < NUM_NISP_HW_COUNTERS; i++)
		ethtool_puts(data, mlx5e_nisp_hw_stats_desc[i].format);
}

static MLX5E_DECLARE_STATS_GRP_OP_FILL_STATS(nisp_hw)
{
	unsigned int i;

	if (!priv->nisp || !mlx5_is_nisp_device(priv->mdev))
		return;

	mlx5e_accel_nisp_get_stats_fill(priv, mlx5e_accel_nisp_get_stats(priv));
	for (i = 0; i < NUM_NISP_HW_COUNTERS; i++)
		mlx5e_ethtool_put_stat(
			data,
			MLX5E_READ_CTR64_CPU(mlx5e_accel_nisp_get_stats(priv),
					     mlx5e_nisp_hw_stats_desc,
					     i));
}

MLX5E_DEFINE_STATS_GRP(nisp_hw, 0);
