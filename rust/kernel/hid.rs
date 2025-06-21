// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2025 Rahul Rameshbabu <sergeantsagara@protonmail.com>

use crate::{error::*, prelude::*, types::Opaque};
use core::marker::PhantomData;

#[repr(transparent)]
pub struct Device<Ctx: DeviceContext = Normal>(Opaque<bindings::hid_device>, PhantomData<Ctx>);

impl<Ctx: device::DeviceContext> Device<Ctx> {
    fn as_raw(&self) -> *mut bindings::pci_dev {
        self.0.get()
    }
}

impl Device {
    unsafe fn from_ptr<'a>(ptr: *mut bindings::hid_device) -> &'a mut Self {
        let ptr = ptr.cast::<Self>();

        unsafe { &mut *ptr }
    }

    pub fn vendor(&self) -> u32 {
        unsafe { (*self.as_raw()).vendor }
    }

    pub fn product(&self) -> u32 {
        unsafe { (*self.as_raw()).product }
    }
}

// TODO see if this is needed
// SAFETY: `Device` is a transparent wrapper of a type that doesn't depend on `Device`'s generic
// argument.
//kernel::impl_device_context_deref!(unsafe { Device });
//kernel::impl_device_context_into_aref!(Device);

/// Abstraction for bindings::hid_device_id.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::hid_device_id);

impl DeviceId {
    pub const fn new_usb(vendor: u32, product: u32) -> Self {
        Self(bindings::hid_device_id {
            bus: 0x3, /* BUS_USB */
            group: HID_GROUP_ANY, /* TODO fix/use */
            vendor: vendor,
            product: product,
            driver_data: 0, /* TODO fix/use */
        })
    }

    unsafe fn from_ptr<'a>(ptr: *mut bindings::hid_device_id) -> &'a mut Self {
        let ptr = ptr.cast::<Self>();

        unsafe { &mut *ptr }
    }

    unsafe fn from_const_ptr<'a>(ptr: *const bindings::hid_device_id) -> &'a Self {
        let ptr = ptr.cast::<Self>();

        unsafe { &(*ptr) }
    }

    /* TODO simplify with a non-exported macro rule? */
    pub fn bus(&self) -> u16 {
        let hdev_id = self.0;

        unsafe { (*hdev_id).bus }
    }

    pub fn group(&self) -> u16 {
        let hdev_id = self.0;

        unsafe { (*hdev_id).group }
    }

    pub fn vendor(&self) -> u32 {
        let hdev_id = self.0;

        unsafe { (*hdev_id).vendor }
    }

    pub fn product(&self) -> u32 {
        let hdev_id = self.0;

        unsafe { (*hdev_id).product }
    }
}

// SAFETY:
// * `DeviceId` is a `#[repr(transparent)` wrapper of `hid_device_id` and does not add
//   additional invariants, so it's safe to transmute to `RawType`.
// * `DRIVER_DATA_OFFSET` is the offset to the `driver_data` field.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::hid_device_id;

    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::hid_device_id, driver_data);

    fn index(&self) -> usize {
        self.0.driver_data as _
    }
}

/// IdTable type for HID
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// Create a HID `IdTable` with its alias for modpost.
#[macro_export]
macro_rules! hid_device_table {
    // TODO fill in
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::hid::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new($table_data);

        $crate::module_device_table!("hid", $module_table_name, $table_name);
    };
}

/// An adapter for the registration of HID drivers.
pub struct Adapter<T: Driver>(T);

unsafe impl<T: Driver + 'static> driver::RegistrationOps for Adapter<T> {
    type RegType = bindings::hid_driver;

    unsafe fn register(
        hdrv: &Opaque<Self::RegType>,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        unsafe {
            let raw_hdrv = *hdrv.get();

            raw_hdrv.name = name.as_char_ptr();
            raw_hdrv.id_table = T::ID_TABLE::as_ptr();
            raw_hdrv.report_fixup = if T::HAS_REPORT_FIXUP {
                Some(Self::report_fixup_callback)
            } else {
                None
            }
        }

        to_result(unsafe {
            bindings::__hid_register_driver(hdrv.get(), module.0, name.as_char_ptr())
        })
    }

    unsafe fn unregister(hdrv: &Opaque<Self::RegType>) {
        unsafe { bindings::hid_unregister_driver(hdrv.get()) }
    }
}

impl<T: Driver + 'static> Adapter<T> {
    extern "C" fn report_fixup_callback(
        hdev: *mut bindings::hid_dev,
        buf: *mut u8,
        size: *mut kernel::ffi::c_uint,
    ) -> *u8 {
        let hdev = unsafe { &*hdev.cast::<Device> };

        /* FIXME If KVec frees the underlying buffer, we get a double free in
         * the hid-core stack... */
        /* TODO build a vector from buf and size in Rust */
        let mut report_desc_vec = unsafe { KVec::from_raw_parts(bug, *size, *size) };

        /* TODO figure out typing */
        T::report_fixup(hdev, &mut report_desc_vec);

        /* FIXME This causes a memory leak since hid-core does not attempt to
         * free the buffer in case its static read-only memory*/
        let (ptr, len, capacity) = report_desc_vec.into_raw_parts();
        *size = len;
        ptr
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
pub trait Driver: Send {
    type IdInfo: 'static;

    const ID_TABLE: IdTable<Self::IdInfo>;

    fn report_fixup(hdev: &Device, );
}

struct Adapter<T: Driver> {
    _p: PhantomData<T>,
}

impl<T: Driver> Adapter<T> {
    unsafe extern "C" fn probe_callback(
        hdev: *mut bindings::hid_device,
        hdev_id: *const bindings::hid_device_id,
    ) -> crate::ffi::c_int {
        from_result(|| {
            let dev = unsafe { Device::from_ptr(hdev) };
            let dev_id = unsafe { DeviceId::from_const_ptr(hdev_id) };
            T::probe(dev, dev_id)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn remove_callback(hdev: *mut bindings::hid_device) {
        let dev = unsafe { Device::from_ptr(hdev) };
        T::remove(dev);
    }
}

#[repr(transparent)]
pub struct DriverVTable(Opaque<bindings::hid_driver>);

// SAFETY: `DriverVTable` doesn't expose any &self method to access internal data, so it's safe to
// share `&DriverVTable` across execution context boundaries.
unsafe impl Sync for DriverVTable {}

pub const fn create_hid_driver<T: Driver>(
    name: &'static CStr,
    id_table: &'static DeviceIdShallow,
) -> DriverVTable {
    DriverVTable(Opaque::new(bindings::hid_driver {
        name: name.as_char_ptr().cast_mut(),
        id_table: unsafe { id_table.as_ptr() },
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
    (vendor: $vendor:expr, product: $product:expr $(,)?) => {
        $crate::hid::DeviceIdShallow::new_usb($vendor, $product)
    }
}

#[macro_export]
macro_rules! module_hid_driver {
    (@replace_expr $_t:tt $sub:expr) => {$sub};

    (@count_devices $($x:expr),*) => {
        0usize $(+ $crate::module_hid_driver!(@replace_expr $x 1usize))*
    };

    (driver: $driver:ident, id_table: [$($dev_id:expr),+ $(,)?], name: $name:tt, $($f:tt)*) => {
        struct Module {
            _reg: $crate::hid::Registration,
        }

        $crate::prelude::module! {
            type: Module,
            name: $name,
            $($f)*
        }

        const _: () = {
            static NAME: &$crate::str::CStr = $crate::c_str!($name);

            static ID_TABLE: [$crate::hid::DeviceIdShallow;
                $crate::module_hid_driver!(@count_devices $($dev_id),+) + 1] = [
                $($dev_id),+,
                $crate::hid::DeviceIdShallow::new(),
            ];

            static mut DRIVER: $crate::hid::DriverVTable =
                $crate::hid::create_hid_driver::<$driver>(NAME, unsafe { &ID_TABLE[0] });

            impl $crate::Module for Module {
                fn init(module: &'static $crate::ThisModule) -> Result<Self> {
                    let driver = unsafe { &mut DRIVER };
                    let mut reg = $crate::hid::Registration::register(
                        module,
                        ::core::pin::Pin::static_mut(driver),
                        NAME,
                    )?;
                    Ok(Module { _reg: reg })
                }
            }
        };
    }
}
