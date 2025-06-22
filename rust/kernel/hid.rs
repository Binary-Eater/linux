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

#[vtable]
pub trait Driver: Send {
    type IdInfo: 'static;

    const ID_TABLE: IdTable<Self::IdInfo>;

    fn report_fixup(hdev: &Device, rdesc: &mut [u8]) -> &[u8];
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

        /* Build a mutable Rust slice from buf and size */
        let mut rdesc_slice = unsafe { core::slice::from_raw_parts_mut(buf, *size) };
        let rdesc_slice = T::report_fixup(hdev, &mut rdesc_slice);

        *size = rdesc_slice.len()

        rdesc_slice.as_ptr()
    }
}

#[macro_export]
macro_rules! module_hid_driver {
($($f:tt)*) => {
    $crate::module_driver!(<T>, $crate::hid::Adapter<T>, { $($f)* });
};
}
