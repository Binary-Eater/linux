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

    /*
     * TODO figure out type. If type is too flexible, might make sense to make
     * the id table a part of the driver macro
     */
    const IdTable: &'static Vec<hid::DeviceId> = vec![
        hid::usb_device! {
            vendor_id: /* TODO fill in */,
            device_id: /* TODO fill in */,
        },
    ];
}

kernel::module_hid_driver! {
    driver: HidMonitorControl,
    name: "monitor-control",
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Driver for the USB Monitor Control Class",
    license: "GPL",
}
