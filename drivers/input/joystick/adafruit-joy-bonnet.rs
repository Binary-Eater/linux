// SPDX-License-Identifier: GPL-2.0

struct JoyBonnet;

#[vtable]
impl Driver for JoyBonnet {}

fn joy_bonnet_probe -> Result {

}

kernel::module_i2c_driver! {
    name: "joy_bonnet_i2c",
    open_firmware_table: [
        "adafruit,joy-bonnet"
    ],
    id_table: [
        "joy-bonnet-rpi-hat"
    ],
    probe: joy_bonnet_probe,
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Adafruit Joy Bonnet for Rapberry Pi driver",
    license: "GPL",
}
