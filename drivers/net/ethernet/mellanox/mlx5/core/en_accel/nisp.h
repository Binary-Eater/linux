/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5E_ACCEL_NISP_H__
#define __MLX5E_ACCEL_NISP_H__
#if IS_ENABLED(CONFIG_MLX5_EN_PSP)
#include <net/psp/types.h>
#include "en.h"

struct mlx5e_nisp_stats {
	u64 psp_rx_pkts;
	u64 psp_rx_bytes;
	u64 psp_rx_pkts_auth_fail;
	u64 psp_rx_bytes_auth_fail;
	u64 psp_rx_pkts_frame_err;
	u64 psp_rx_bytes_frame_err;
	u64 psp_rx_pkts_drop;
	u64 psp_rx_bytes_drop;
	u64 psp_tx_pkts;
	u64 psp_tx_bytes;
	u64 psp_tx_pkts_drop;
	u64 psp_tx_bytes_drop;
};

struct mlx5e_nisp {
	struct psp_dev *psp;
	struct mlx5e_nisp_fs *fs;
	atomic_t tx_key_cnt;
	__wsum psphdrsum;
	/* Stats manage */
	struct mlx5e_nisp_stats stats;
};

struct nisp_key_spi {
	u32 spi;
	union {
		__be32 key[PSP_V0_KEY / sizeof(u32)];
		u8 keyv0[PSP_V0_KEY];
	};
	u16 keysz;
};

static inline bool mlx5_is_nisp_device(struct mlx5_core_dev *mdev)
{
	if (!MLX5_CAP_GEN(mdev, nisp))
		return false;

	if (!MLX5_CAP_NISP(mdev, nisp_crypto_esp_aes_gcm_128_encrypt) ||
	    !MLX5_CAP_NISP(mdev, nisp_crypto_esp_aes_gcm_128_decrypt))
		return false;

	return true;
}

void mlx5e_nisp_register(struct mlx5e_priv *priv);
void mlx5e_nisp_unregister(struct mlx5e_priv *priv);
int mlx5e_nisp_init(struct mlx5e_priv *priv);
void mlx5e_nisp_cleanup(struct mlx5e_priv *priv);
int mlx5e_nisp_rotate_key(struct mlx5_core_dev *mdev);
int mlx5e_nisp_generate_key_spi(struct mlx5_core_dev *mdev,
				enum mlx5_nisp_gen_spi_in_key_size keysz,
				struct nisp_key_spi *keys);
struct mlx5e_nisp_stats *mlx5e_accel_nisp_get_stats(struct mlx5e_priv *priv);
void mlx5e_accel_nisp_get_stats_fill(struct mlx5e_priv *priv, void *nisp_stats);
#else
static inline bool mlx5_is_nisp_device(struct mlx5_core_dev *mdev)
{
	return false;
}

static inline void mlx5e_nisp_register(struct mlx5e_priv *priv) { }
static inline void mlx5e_nisp_unregister(struct mlx5e_priv *priv) { }
static inline int mlx5e_nisp_init(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_nisp_cleanup(struct mlx5e_priv *priv) { }
static inline struct mlx5e_nisp_stats *mlx5e_accel_nisp_get_stats(struct mlx5e_priv *priv)
{
	return NULL;
}
#endif /* CONFIG_MLX5_EN_PSP */
#endif /* __MLX5E_ACCEL_NISP_H__ */
