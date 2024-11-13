// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024, Rahul Rameshbabu <sergeantsagara@protonmail.com>
 *
 * TODO details
 */
// CANNOT HAVE HYPHENS IN CRATE NAME SO adafruit-joy-bonnet DEFAULT DOES NOT WORK...

/*
struct JoyBonnet;

#[vtable]
impl Driver for JoyBonnet {}

fn joy_bonnet_probe(client: &I2CClient) -> Result {

}
*/

kernel::module_i2c_driver! {
    open_firmware_table: [
        "adafruit,joy-bonnet"
    ],
    id_table: [
        "joy-bonnet-rpi-hat"
    ],
    name: "joy_bonnet_i2c",
    //probe: joy_bonnet_probe,
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Adafruit Joy Bonnet for Rapberry Pi driver",
    license: "GPL",
}
