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

    fn remove(dev: &mut hid::Device) -> Result<()> {
        /* TODO implement */
        Ok(())
    }
}

kernel::module_hid_driver! {
    driver: HidMonitorControl,
    id_table: [
        hid::usb_device! {
            vendor: /* TODO fill in */,
            product: /* TODO fill in */,
        },
    ],
    name: "monitor-control",
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Driver for the USB Monitor Control Class",
    license: "GPL",
}
