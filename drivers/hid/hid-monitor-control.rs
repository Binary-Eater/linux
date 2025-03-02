use kernel::prelude::*;
use kernel::hid::{
    self,
    Driver,
};

const USB_VENDOR_ID_NVIDIA: u32 = 0x0955;
const USB_DEVICE_ID_NVIDIA_THUNDERSTRIKE_CONTROLLER: u32 = 0x7214;

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
            vendor: USB_VENDOR_ID_NVIDIA,
            product: USB_DEVICE_ID_NVIDIA_THUNDERSTRIKE_CONTROLLER,
        },
    ],
    name: "monitor-control",
    author: "Rahul Rameshbabu <sergeantsagara@protonmail.com>",
    description: "Driver for the USB Monitor Control Class",
    license: "GPL",
}
