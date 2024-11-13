// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024, Rahul Rameshbabu <sergeantsagara@protonmail.com>
 *
 * TODO details
 */
use crate::prelude::*;

#[macro_export]
macro_rules! module_i2c_driver {
    (@replace_expr $_t:tt $sub:expr) => {$sub};

    (open_firmware_table: [$($firmware:expr),+ $(,)?], id_table: [$($id:expr),+ $(,)?], $($core_module:tt)*) => {
        struct RustI2C;

        $crate::prelude::module! {
            type: RustI2C,
            $($core_module)*
        }

        impl $crate::Module for RustI2C {
            fn init(module: &'static $crate::ThisModule) -> Result<Self, $crate::error::Error> {
                $(
                    $crate::prelude::pr_err!("Firmware {} from open_firmware_table.\n", ($firmware));
                )*
                $(
                    $crate::prelude::pr_err!("Id {} from id_table.\n", ($id));
                )*

                Ok(RustI2C)
            }
        }
    }
}

