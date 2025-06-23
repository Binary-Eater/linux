// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2025 Rahul Rameshbabu <sergeantsagara@protonmail.com>

use kernel::prelude::*;
use kernel::hid;

const USB_VENDOR_ID_NVIDIA: u32 = 0x0955;
const USB_DEVICE_ID_NVIDIA_THUNDERSTRIKE_CONTROLLER: u32 = 0x7214;

struct HidMonitorControl;

kernel::hid_device_table!(
    HID_TABLE,
    MODULE_HID_TABLE,
    <HidMonitorControl as hid::Driver>::IdInfo,
    [(
        hid::DeviceId::new_usb(
            hid::Group::Generic,
            USB_VENDOR_ID_NVIDIA,
            USB_DEVICE_ID_NVIDIA_THUNDERSTRIKE_CONTROLLER,
        ),
        (),
    )]
);

#[vtable]
impl hid::Driver for HidMonitorControl {
    type IdInfo = ();
    const ID_TABLE: hid::IdTable<Self::IdInfo> = &HID_TABLE;
}

kernel::module_hid_driver! {
    type: HidMonitorControl,
    name: "HidMonitorControl",
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Driver for the USB Monitor Control Class",
    license: "GPL",
}
