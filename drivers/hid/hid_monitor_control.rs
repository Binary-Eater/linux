// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2025 Rahul Rameshbabu <sergeantsagara@protonmail.com>

use kernel::prelude::*;
use kernel::hid::{
    self,
    Driver,
};

struct HidMonitorControl;

#[vtable]
impl Driver for HidMonitorControl {
    fn probe(dev: &mut hid::Device, id: &hid::DeviceId) -> Result<()> {
        /* TODO implement */
        Ok(())
    }

    fn remove(dev: &mut hid::Device) {
        /* TODO implement */
    }
}

kernel::module_hid_driver! {
    driver: HidMonitorControl,
    id_table: [
        kernel::usb_device! {
            vendor: /* TODO fill in */,
            product: /* TODO fill in */,
        },
    ],
    name: "monitor_control",
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Driver for the USB Monitor Control Class",
    license: "GPL",
}
