// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "nisp.h"

struct mlx5_nisp *mlx5_nisp_create(struct mlx5_core_dev *mdev)
{
	struct mlx5_nisp *nisp = kzalloc(sizeof(*nisp), GFP_KERNEL);

	if (!nisp)
		return ERR_PTR(-ENOMEM);

	nisp->mdev = mdev;

	return nisp;
}

void mlx5_nisp_destroy(struct mlx5_nisp *nisp)
{
	if (IS_ERR_OR_NULL(nisp))
		return;

	kfree(nisp);
}
