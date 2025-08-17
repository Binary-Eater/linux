// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM connector.
//!
//! C header: [`include/drm/drm_connector.h`](srctree/include/drm/drm_connector.h)

use kernel::prelude::*;
use kernel::types::Opaque;

#[pin_data]
pub struct Connector {
    raw_connector: Opaque<*mut bindings::drm_connector>,
    #[pin]
    rust_only_attribute: bool,
}

#[export]
pub unsafe extern "C" fn drm_connector_init_rust(raw_connector: *mut bindings::drm_connector) -> kernel::ffi::c_int {
    let connector = match KBox::pin_init(
        try_pin_init!(Connector{
            raw_connector <- Opaque::new(raw_connector),
            rust_only_attribute: true,
        }),
        GFP_KERNEL,
    ) {
        Ok(kbox) => kbox,
        Err(_) => return -ENOMEM.to_errno(),
    };

    unsafe {
        (*raw_connector).rust = KBox::into_raw(unsafe { Pin::into_inner_unchecked(connector) }).cast::<kernel::ffi::c_void>();
    }

    return 0;
}

#[export]
pub unsafe extern "C" fn drm_connector_cleanup_rust(raw_connector: *mut bindings::drm_connector) {
    let connector_ptr = unsafe { (*raw_connector).rust.cast::<*mut Connector>() };

    drop(unsafe{ KBox::from_raw(connector_ptr) });
}
