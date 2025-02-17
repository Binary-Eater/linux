/* TODO use bindings interface for defining Device and DeviceId from C HID core */

#[vtable]
pub trait Driver {
    fn probe(_dev: &mut Device, _id: &DeviceId) -> Result {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    fn remove(_dev: &mut Device) -> Result {

    }

    const IdTable: &'static Vec<DeviceId>;
}
