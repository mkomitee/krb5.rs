extern crate libc;

use libc::{c_char, c_int};
use std::ffi::{CStr};

pub fn c_to_string(raw: *const c_char) -> Option<String> {
    ::std::str::from_utf8(unsafe{CStr::from_ptr(raw)}.to_bytes())
        .ok()
        .map(|o| o.to_string())
}

// From krb5.h:
//  struct _krb5_context;
//  typedef struct _krb5_context * krb5_context;
//  This is opaque in the c header file.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct krb5_context;

// TODO: Is there any reason to actually expose the internals of
// krb5_principal? If so we'll have to fill in the internals.
// From krb5.h:
//  typedef struct krb5_principal_data {
//      krb5_magic magic;
//      krb5_data realm;
//      krb5_data *data;            /**< An array of strings */
//      krb5_int32 length;
//      krb5_int32 type;
//  } krb5_principal_data;
//  typedef krb5_principal_data * krb5_principal;
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct krb5_principal;

#[link(name = "krb5")]
extern "C" {
    // From krb5.h:
    //  krb5_error_code KRB5_CALLCONV
    //  krb5_init_context(krb5_context *context);
    pub fn krb5_init_context(context: *mut *mut krb5_context) -> c_int;

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_free_context(krb5_context context);
    pub fn krb5_free_context(context: *mut krb5_context);

    // From krb5.h:
    //  krb5_error_code KRB5_CALLCONV
    //  krb5_parse_name(krb5_context context,
    //                  const char *name,
    //                  krb5_principal *nprincipal);
    pub fn krb5_parse_name(context: *mut krb5_context,
                           name: *const c_char,
                           principal: *mut *mut krb5_principal) -> c_int;

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_free_principal(krb5_context context,
    //                      krb5_principal val);
    pub fn krb5_free_principal(context: *mut krb5_context,
                               val: *mut krb5_principal);

    // From krb5.h:
    //  krb5_error_code KRB5_CALLCONV
    //  krb5_aname_to_localname(krb5_context context,
    //                          krb5_const_principal aname,
    //                          int lnsize_in,
    //                          char *lname);
    pub fn krb5_aname_to_localname(context: *mut krb5_context,
                                   aname: *mut krb5_principal,
                                   size: c_int,
                                   lname: *mut [u8]) -> c_int;

    // From krb5.h:
    //  const char * KRB5_CALLCONV
    //  krb5_get_error_message(krb5_context ctx,
    //                         krb5_error_code code);
    pub fn krb5_get_error_message(context: *mut krb5_context,
                                  code: c_int) -> *const c_char;

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_clear_error_message(krb5_context ctx);
    pub fn krb5_clear_error_message(context: *mut krb5_context);

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_free_error_message(krb5_context ctx,
    //                          const char *msg);
    pub fn krb5_free_error_message(context: *mut krb5_context,
                                   message: *const c_char);
}
