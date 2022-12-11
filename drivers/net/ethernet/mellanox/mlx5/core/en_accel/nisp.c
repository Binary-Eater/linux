// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
#include <linux/mlx5/device.h>
#include <net/psp.h>
#include <linux/psp.h>
#include "mlx5_core.h"
#include "../nisp.h"
#include "lib/crypto.h"
#include "en_accel/nisp.h"
#include "en_accel/nisp_fs.h"

MODULE_IMPORT_NS(NETDEV_PRIVATE);

struct mlx5e_nisp_sa_entry {
	struct mlx5e_accel_nisp_rule *nisp_rule;
	u32 enc_key_id;
};

static int
mlx5e_psp_set_config(struct psp_dev *psd, struct psp_dev_config *conf,
		    struct netlink_ext_ack *extack)
{
	return 0;
}

static int
mlx5e_psp_rx_spi_alloc(struct psp_dev *psd, u32 version,
		      struct psp_key_parsed *assoc,
		      struct netlink_ext_ack *extack)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5_nisp *mnisp = priv->mdev->nisp;
	enum mlx5_nisp_gen_spi_in_key_size keysz;
	struct nisp_key_spi key_spi = {};
	u8 keysz_bytes;
	int err, i;

	switch (version) {
	case PSP_VERSION_HDR0_AES_GCM_128:
		keysz = MLX5_NISP_GEN_SPI_IN_KEY_SIZE_128;
		keysz_bytes = 16;
		break;
	case PSP_VERSION_HDR0_AES_GCM_256:
		keysz = MLX5_NISP_GEN_SPI_IN_KEY_SIZE_256;
		keysz_bytes = 32;
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack,
				   "Invalid key version, Supported Versions AES_GCM_128 and AES_GCM_256");
		return -EINVAL;
	}

	err = mlx5e_nisp_generate_key_spi(priv->mdev, keysz, &key_spi);
	if (err)
		return err;

	assoc->spi = cpu_to_be32(key_spi.spi);
	if (!mnisp->key_index_inited) {
		mnisp->key_index = (key_spi.spi >> 31) & 0x1;
		mnisp->key_gen_arr[mnisp->key_index] = psd->generation;
		mnisp->key_index_inited = true;
	}

	for (i = 0; i < keysz_bytes; i++)
		assoc->key[i] = key_spi.keyv0[i];

	return err;
}

struct nisp_key {
	u32 id;
};

static int mlx5e_psp_assoc_add(struct psp_dev *psd, struct psp_assoc *pas,
			       struct netlink_ext_ack *extack)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_nisp *nisp = priv->nisp;
	struct psp_key_parsed *tx = &pas->tx;
	struct nisp_key *nkey;
	int err;

	mdev = priv->mdev;
	nkey = (struct nisp_key *)pas->drv_data;

	err = mlx5_create_encryption_key(mdev, tx->key,
					 PSP_V0_KEY,
					 MLX5_ACCEL_OBJ_NISP_KEY,
					 &nkey->id);
	if (err) {
		mlx5_core_err(mdev, "Failed to create encryption key (err = %d)\n", err);
		return err;
	}

	atomic_inc(&nisp->tx_key_cnt);
	return 0;
}

static void mlx5e_psp_assoc_del(struct psp_dev *psd, struct psp_assoc *pas)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5e_nisp *nisp = priv->nisp;
	struct nisp_key *nkey;

	nkey = (struct nisp_key *)pas->drv_data;
	mlx5_destroy_encryption_key(priv->mdev, nkey->id);
	atomic_dec(&nisp->tx_key_cnt);
}

static void mlx5e_psp_get_stats(struct psp_dev *psd, struct psp_dev_stats *stats)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5e_nisp_stats nstats;

	mlx5e_accel_nisp_fs_get_stats_fill(priv, &nstats);
	stats->rx_packets = nstats.psp_rx_pkts;
	stats->rx_bytes = nstats.psp_rx_bytes;
	stats->rx_auth_fail = nstats.psp_rx_pkts_auth_fail;
	stats->rx_error = nstats.psp_rx_pkts_frame_err;
	stats->rx_bad = nstats.psp_rx_pkts_drop;
	stats->tx_packets = nstats.psp_tx_pkts;
	stats->tx_bytes = nstats.psp_tx_bytes;
	stats->tx_error = 0; // TODO implement
}

static struct psp_dev_ops mlx5_psp_ops = {
	.set_config   = mlx5e_psp_set_config,
	.rx_spi_alloc = mlx5e_psp_rx_spi_alloc,
	.tx_key_add   = mlx5e_psp_assoc_add,
	.tx_key_del   = mlx5e_psp_assoc_del,
	.get_stats    = mlx5e_psp_get_stats,
};

static struct psp_dev_caps mlx5_psp_caps = {
	.versions = 1 << PSP_VERSION_HDR0_AES_GCM_128 |
		    1 << PSP_VERSION_HDR0_AES_GCM_256,
	.assoc_drv_spc = sizeof(u32),
};

void mlx5e_accel_nisp_get_stats_fill(struct mlx5e_priv *priv, void *nisp_stats)
{
	mlx5e_accel_nisp_fs_get_stats_fill(priv, nisp_stats);
}

struct mlx5e_nisp_stats *mlx5e_accel_nisp_get_stats(struct mlx5e_priv *priv)
{
	return &priv->nisp->stats;
}

void mlx5e_nisp_unregister(struct mlx5e_priv *priv)
{
	if (!priv->nisp || !priv->nisp->psp)
		return;

	psp_dev_unregister(priv->nisp->psp);
}

void mlx5e_nisp_register(struct mlx5e_priv *priv)
{
	/* FW Caps missing */
	if (!priv->nisp)
		return;

	priv->nisp->psp = psp_dev_create(priv->netdev, &mlx5_psp_ops, &mlx5_psp_caps, NULL);
	if (IS_ERR(priv->nisp->psp))
		mlx5_core_err(priv->mdev, "PSP failed to register due to %pe\n",
			      priv->nisp->psp);
}

int mlx5e_nisp_init(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_nisp_fs *fs;
	struct mlx5e_nisp *nisp;
	int err;

	if (!mlx5_is_nisp_device(mdev)) {
		mlx5_core_dbg(mdev, "NISP offload not supported\n");
		return -ENOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp)) {
		mlx5_core_dbg(mdev, "SWP not supported\n");
		return -ENOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp_csum)) {
		mlx5_core_dbg(mdev, "SWP checksum not supported\n");
		return -ENOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp_lso)) {
		mlx5_core_dbg(mdev, "NISP LSO not supported\n");
		return -ENOTSUPP;
	}

	nisp = kzalloc(sizeof(*nisp), GFP_KERNEL);
	if (!nisp)
		return -ENOMEM;

	priv->nisp = nisp;
	fs = mlx5e_accel_nisp_fs_init(priv);
	if (IS_ERR(fs)) {
		err = PTR_ERR(fs);
		goto out_err;
	}

	nisp->fs = fs;

	mlx5_core_dbg(priv->mdev, "NISP attached to netdevice\n");
	return 0;

out_err:
	priv->nisp = NULL;
	kfree(nisp);
	return err;
}

void mlx5e_nisp_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_nisp *nisp = priv->nisp;

	if (!nisp)
		return;

	WARN_ON(atomic_read(&nisp->tx_key_cnt));
	mlx5e_accel_nisp_fs_cleanup(nisp->fs);
	priv->nisp = NULL;
	kfree(nisp);
}
