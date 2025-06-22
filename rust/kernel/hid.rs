// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2025 Rahul Rameshbabu <sergeantsagara@protonmail.com>

use crate::{
    device,
    device_id::RawDeviceId,
    driver,
    error::*,
    prelude::*,
    types::Opaque,
};
use core::marker::PhantomData;

/*
 * HID report descriptor main item contents
 */
pub const MAIN_ITEM_CONSTANT: u8      = bindings::HID_MAIN_ITEM_CONSTANT as u8;
pub const MAIN_ITEM_VARIABLE: u8      = bindings::HID_MAIN_ITEM_VARIABLE as u8;
pub const MAIN_ITEM_RELATIVE: u8      = bindings::HID_MAIN_ITEM_RELATIVE as u8;
pub const MAIN_ITEM_WRAP: u8          = bindings::HID_MAIN_ITEM_WRAP as u8;
pub const MAIN_ITEM_NONLINEAR: u8     = bindings::HID_MAIN_ITEM_NONLINEAR as u8;
pub const MAIN_ITEM_NO_PREFERRED: u8  = bindings::HID_MAIN_ITEM_NO_PREFERRED as u8;
pub const MAIN_ITEM_NULL_STATE: u8    = bindings::HID_MAIN_ITEM_NULL_STATE as u8;
pub const MAIN_ITEM_VOLATILE: u8      = bindings::HID_MAIN_ITEM_VOLATILE as u8;
pub const MAIN_ITEM_BUFFERED_BYTE: u8 = bindings::HID_MAIN_ITEM_BUFFERED_BYTE as u8;

#[repr(transparent)]
pub struct Device<Ctx: device::DeviceContext = device::Normal>(
    Opaque<bindings::hid_device>,
    PhantomData<Ctx>,
);

impl<Ctx: device::DeviceContext> Device<Ctx> {
    fn as_raw(&self) -> *mut bindings::hid_device {
        self.0.get()
    }
}

impl Device {
    pub fn vendor(&self) -> u32 {
        unsafe { *self.as_raw() }.vendor
    }

    pub fn product(&self) -> u32 {
        unsafe { *self.as_raw() }.product
    }
}

/// Abstraction for bindings::hid_device_id.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::hid_device_id);

impl DeviceId {
    pub const fn new_usb(vendor: u32, product: u32) -> Self {
        Self(bindings::hid_device_id {
            bus: 0x3, /* BUS_USB */
            group: bindings::HID_GROUP_ANY as u16, /* TODO fix/use */
            vendor: vendor,
            product: product,
            driver_data: 0, /* TODO fix/use */
        })
    }

    /* TODO simplify with a non-exported macro rule? */
    pub fn bus(&self) -> u16 {
        self.0.bus
    }

    pub fn group(&self) -> u16 {
        self.0.group
    }

    pub fn vendor(&self) -> u32 {
        self.0.vendor
    }

    pub fn product(&self) -> u32 {
        self.0.product
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

    fn report_fixup<'a, 'b: 'a>(_hdev: &Device, _rdesc: &'b mut [u8]) -> &'a [u8] {
        build_error!(VTABLE_DEFAULT_ERROR)
    }
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
        let hdrv_ref = &mut unsafe { *hdrv.get() };

        hdrv_ref.name = name.as_char_ptr();
        hdrv_ref.id_table = T::ID_TABLE.as_ptr();
        hdrv_ref.report_fixup = if T::HAS_REPORT_FIXUP {
            Some(Self::report_fixup_callback)
        } else {
            None
        };

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
        hdev: *mut bindings::hid_device,
        buf: *mut u8,
        size: *mut kernel::ffi::c_uint,
    ) -> *const u8 {
        let hdev = unsafe { &*hdev.cast::<Device>() };

        let buf_len: usize = match unsafe { *size }.try_into() {
            Ok(len) => len,
            Err(e) => {
                pr_err!("Cannot fix report description due to length conversion failure: {}!\n",
                        e);

                return buf;
            },
        };

        /* Build a mutable Rust slice from buf and size */
        let mut rdesc_slice = unsafe { core::slice::from_raw_parts_mut(buf, buf_len) };
        let rdesc_slice = T::report_fixup(hdev, &mut rdesc_slice);

        match rdesc_slice.len().try_into() {
            Ok(len) => unsafe { *size = len },
            Err(e) => {
                pr_err!("Fixed report description will not be used due to {}!\n", e);

                return buf;
            },
        }

        rdesc_slice.as_ptr()
    }
}

#[macro_export]
macro_rules! module_hid_driver {
    ($($f:tt)*) => {
        $crate::module_driver!(<T>, $crate::hid::Adapter<T>, { $($f)* });
    };
}
