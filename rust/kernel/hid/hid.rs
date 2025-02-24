/* TODO use bindings interface for defining Device and DeviceId from C HID core */

#[repr(transparent)]
pub struct Device(Opaque<bindings::hid_device>);

impl Device {
    unsafe fn from_ptr<'a>(ptr: *mut bindings::hid_device) -> &'a mut Self {
        let ptr = ptr.cast::<Self>();

        unsafe { &mut *ptr };
    }

    pub fn vendor(&self) -> u32 {
        let hdev = self.0.get();

        unsafe { (*hdev).vendor }
    }

    pub fn product(&self) -> u32 {
        let hdev = self.0.get();

        unsafe { (*hdev).product }
    }
}

#[repr(transparent)]
pub struct DeviceId(Opaque<bindings::hid_device_id>);

impl DeviceId {
    unsafe fn from_ptr<'a>(ptr: *mut bindings::hid_device_id) -> &'a mut Self {
        let ptr = ptr.cast::<Self>();

        unsafe { &mut *ptr };
    }

    pub fn vendor(&self) -> u32 {
        let hdev_id = self.0.get();

        unsafe { (*hdev_id).vendor }
    }

    pub fn product(&self) -> u32 {
        let hdev_id = self.0.get();

        unsafe { (*hdev_id).product }
    }
}

/*
#[repr(transparent)]
pub struct Field(Opaque<bindings::hid_field>);

#[repr(transparent)]
pub struct ReportEnum(Opaque<bindings::hid_report_enum>);

#[repr(transparent)]
pub struct Report(Opaque<bindings::hid_report>);
*/

#[vtable]
pub trait Driver {
    fn probe(_dev: &mut Device, _id: &DeviceId) -> Result {
        build_error!(VTABLE_DEFAULT_ERROR)
    }

    fn remove(_dev: &mut Device) -> Result {
        Ok(0)
    }

    const IdTable: &'static Vec<DeviceId>;
}

struct Adapter<T: Driver> {
    _p: PhantomData<T>,
}

impl<T: Driver> Adapter<T> {
    unsafe extern "C" fn probe_callback(
        hdev: *mut bindings::hid_device,
        hdev_id: *mut bindings::hid_device_id,
    ) -> crate::ffi::c_int {
        from_result(|| {
            let dev = unsafe { Device::from_ptr(hdev) };
            let dev_id = unsafe { DeviceId::from_ptr(hdev_id) };
            T::probe(dev, dev_id)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn remove_callback(hdev: *mut bindings::hid_device,) -> crate::ffi::c_int {
        from_result(|| {
            let dev = unsafe { Device::from_ptr(hdev) };
            T::remove(dev)?;
            Ok(0)
        })
    }
}

#[repr(transparent)]
pub struct DriverVTable(Opaque<bindings::hid_driver>);

// SAFETY: `DriverVTable` doesn't expose any &self method to access internal data, so it's safe to
// share `&DriverVTable` across execution context boundaries.
unsafe impl Sync for DriverVTable {}

pub const fn create_hid_driver<T: Driver>(name: &'static CStr) -> DriverVTable {
    DriverVTable(Opaque::new(bindings::hid_driver {
        name: name.as_char_ptr(),
        id_table: /* TODO */,
        probe: if T::HAS_PROBE {
            Some(Adapter::<T>::probe_callback)
        } else {
            None
        },
        remove: if T::HAS_REMOVE {
            Some(Adapter::<T>::remove_callback)
        } else {
            None
        },
        // SAFETY: The rest is zeroed out to initialize `struct hid_driver`,
        // sets `Option<&F>` to be `None`.
        ..unsafe { core::mem::MaybeUninit::<bindings::hid_driver>::zeroed().assume_init() }
    }))
}

pub struct Registration {
    driver: Pin<&'static mut DriverVTable>,
}

unsafe impl Send for Registration {}

impl Registration {
    pub fn register(
        module: &'static crate::ThisModule,
        driver: Pin<&'static mut DriverVTable>,
        name: &'static CStr,
    ) -> Result<Self> {
        to_result(unsafe {
            bindings::__hid_register_driver(driver.0.get(), module.0, name.as_char_ptr())
        })?;

        Ok(Registration { driver })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        unsafe {
            bindings::hid_unregister_driver(self.driver.0.get())
        };
    }
}

#[macro_export]
macro_rules! module_hid_driver {
    (driver: $($driver:ident), name: $($name:expr), $(f:tt)*) => {
        struct Module {
            _reg: $crate::hid::Registration,
        }

        $crate::prelude::module! {
            type: Module,
            name: $($name),
            $($f)*
        }

        const _: () = {
            static mut DRIVER: $crate::hid::DriverVTable = $($crate::hid::create_hid_driver::<$driver>(NAME, /* TODO pass ID_TABLE */));
        };
    }
}
