/* TODO use bindings interface for defining Device and DeviceId from C HID core */

#[repr(transparent)]
pub struct Device(Opaque<bindings::hid_device>);

impl Device {
    unsafe fn from_ptr<'a>(ptr: *mut bindings::hid_device) -> &'a mut Self {
        let ptr = ptr.cast::<Self>();

        unsafe { &mut *ptr }
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

        unsafe { &mut *ptr }
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

pub const fn create_hid_driver<T: Driver>(
    name: &'static CStr,
    id_table: Pin<&'static [DeviceId]>,
) -> DriverVTable {
    DriverVTable(Opaque::new(bindings::hid_driver {
        name: name.as_char_ptr(),
        id_table: id_table[0].0.get(),
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
macro_rules! usb_device {
    (vendor: $($vendor:expr), product: $($product:expr)) => {
        DeviceId(Opaque::new(bindings::hid_device_id {
            bus: 0x3, /* BUS_USB */
            vendor: $($vendor),
            product: $($product),
            // SAFETY: The rest is zeroed out to initialize `struct hid_device_id`,
            // sets `Option<&F>` to be `None`.
            ..unsafe { $crate::core::mem::MaybeUninit::<bindings::hid_device_id>::zeroed().assume_init() }
        }))
    }
}

#[macro_export]
macro_rules! module_hid_driver {
    (@replace_expr $_t:tt $sub:expr) => {$sub};

    (@count_devices $($x:expr),*) => {
        0usize $(+ $crate::module_hid_driver!(@replace_expr $x 1usize))*
    };

    (driver: $($driver:ident), id_table: [$($dev_id:expr),+ $(,)?], name: $($name:expr), $(f:tt)*) => {
        struct Module {
            _reg: $crate::hid::Registration,
        }

        $crate::prelude::module! {
            type: Module,
            name: $($name),
            $($f)*
        }

        const _: () = {
            const NAME: &'static Cstr = $crate::c_str!($($name));

            static ID_TABLE: [$crate::hid::DeviceId;
                $crate::module_hid_driver!(@count_devices $($dev_id),+) + 1] = [
                $($dev_id),+,
                DeviceId(Opaque::new($crate::bindings::hid_device_id {
                    // SAFETY: All is zeroed out to initialize `struct hid_device_id`,
                    // sets `Option<&F>` to be `None`.
                    ..unsafe { $crate::core::mem::MaybeUninit::<$crate::bindings::hid_device_id>::zeroed().assume_init() }
                })),
            ];

            static mut DRIVER: $crate::hid::DriverVTable =
                $($crate::hid::create_hid_driver::<$driver>(NAME, ::core::pin::Pin::static(ID_TABLE)));

            impl $crate::Module for Module {
                fn init(module: &'static $crate::ThisModule) -> Result<Self> {
                    let driver = unsafe { &mut DRIVER };
                    let mut reg = $crate::hid::Registration::register(
                        module,
                        ::core::pin::Pin::static_mut(driver),
                    )?;
                    Ok(Module { _reg: reg })
                }
            }
        };
    }
}
