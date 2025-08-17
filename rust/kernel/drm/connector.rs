// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM connector.
//!
//! C header: [`include/drm/drm_connector.h`](srctree/include/drm/drm_connector.h)

use core::marker::PhantomPinned;
use kernel::prelude::*;
use kernel::types::{ForeignOwnable, Opaque};

#[pin_data]
pub struct Connector {
    #[pin]
    raw_connector: Opaque<*mut bindings::drm_connector>,
    rust_only_attribute: bool,

    /// A connector needs to be pinned since it is referred to using a raw
    /// pointer field `rust` in the C DRM `struct drm_connector` implementation.
    ///
    /// [`struct drm_connector`]: srctree/include/drm/drm_connector.h
    #[pin]
    _pin: PhantomPinned,
}

#[export]
pub unsafe extern "C" fn drm_connector_init_rust(raw_connector: *mut bindings::drm_connector) -> kernel::ffi::c_int {
    let connector = match KBox::pin_init(
        try_pin_init!(Connector{
            raw_connector <- Opaque::new(raw_connector),
            rust_only_attribute: true,
            _pin: PhantomPinned,
        }),
        GFP_KERNEL,
    ) {
        Ok(kbox) => kbox,
        Err(_) => return -ENOMEM.to_errno(),
    };

    unsafe {
        (*raw_connector).rust = unsafe { connector.into_foreign() };
    }

    return 0;
}

#[export]
pub unsafe extern "C" fn drm_connector_cleanup_rust(raw_connector: *mut bindings::drm_connector) {
    drop(unsafe{ <Pin<KBox<Connector>>>::from_foreign((*raw_connector).rust) });
}
