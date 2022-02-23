/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_NISP_H__
#define __MLX5_NISP_H__
#include <linux/mlx5/driver.h>

#define MLX5_NISP_MASTER_KEY_NUM 2

struct mlx5_nisp {
	struct mlx5_core_dev *mdev;
	/* Rx manage */
	u16 key_gen_arr[MLX5_NISP_MASTER_KEY_NUM];
	u16 key_index;
	bool key_index_inited : 1;
};

struct mlx5_nisp  *mlx5_nisp_create(struct mlx5_core_dev *mdev);
void mlx5_nisp_destroy(struct mlx5_nisp *nisp);

#endif /* __MLX5_NISP_H__ */
