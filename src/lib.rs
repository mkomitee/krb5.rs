extern crate libc;

use libc::{c_char, c_int};
use std::ffi::{NulError, CString};

const MAX_USERNAME: c_int = 256;

// TODO: We can do better here. The man pages indicate the specific
// errors we may receive. For example, krb5_aname_to_localname returns
// either KRB5_LNAME_NOTRANS or KRB5_CONFIG_NOTENUFSPACE. Also we
// should create our own struct which implements the Error trait which
// wraps the raw Error so that it may later be retrieved and
// inspected.
#[derive(Debug)]
pub enum Error {
    Krb5(c_int),
    Nul(NulError),
}

impl From<NulError> for Error {
    fn from(e: NulError) -> Error {
        Error::Nul(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// From krb5.h:
//  struct _krb5_context;
//  typedef struct _krb5_context * krb5_context;
//  This is opaque in the c header file.
#[allow(non_camel_case_types)]
#[repr(C)]
struct krb5_context;

#[allow(raw_pointer_derive)]
#[derive(Debug)]
pub struct Context {
    ctx: *mut krb5_context,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe{
            krb5_free_context(self.ctx)
        }
    }
}

impl Context {
    pub fn new() -> Result<Context> {
        let mut kcontext: *mut krb5_context = std::ptr::null_mut();
        let err = unsafe {krb5_init_context(&mut kcontext)};
        if err == 0 {
            Ok(Context{ctx: kcontext})
        } else {
            Err(Error::Krb5(err))
        }
    }
    pub fn localname(&self, name: &str) -> Result<String> {
        println!("name: {:?}", name);
        let mut kprinc: *mut krb5_principal = std::ptr::null_mut();
        println!("kprinc: {:?}", kprinc);
        let cname = try!(CString::new(name.as_bytes()));
        println!("cname: {:?}", cname);
        let err = unsafe {krb5_parse_name(self.ctx, cname.as_ptr(), &mut kprinc)};
        println!("err: {:?}", err);
        if err != 0 {
            return Err(Error::Krb5(err));
        }

        unsafe {krb5_free_principal(self.ctx, kprinc)}

        let mut lname: Vec<u8> = Vec::with_capacity(MAX_USERNAME as usize);
        println!("initial lname: {:?}", lname);
        // TODO: Verify that this works somewhere that has localname
        // translation rules :) It doesn't segfault, but it returns a
        // KRB5_LNAME_NOTRANS every time.
        let err = unsafe {krb5_aname_to_localname(self.ctx,
                                                  kprinc,
                                                  MAX_USERNAME - 1,
                                                  &mut lname[..])};
        println!("err: {:?}", err);
        if err != 0 {
            return Err(Error::Krb5(err));
        }
        // TODO: Fix this error. Having issues w/ the From Trait on
        // this error type, it's not Utf8Error, it's something in
        // collections.
        match String::from_utf8(lname) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::Krb5(-1)),
        }
    }
}

// TODO: Do we want to make a Principal struct which wraps
// krb5_principal so that it can become a first class citizen with
// it's own Drop? If we do, we'll be able to actually use them to do
// other things at some time. Unfortunately, the mechanism by which
// it's freed would require us to capture a reference to the Context
// within the Principal struct so it's available.
// From krb5.h:
//  typedef struct krb5_principal_data {
//      krb5_magic magic;
//      krb5_data realm;
//      krb5_data *data;            /**< An array of strings */
//      krb5_int32 length;
//      krb5_int32 type;
//  } krb5_principal_data;
//  typedef krb5_principal_data * krb5_principal;
// Note: I'm leaving this as opaque because we don't actually use its
// contents at all.
#[allow(non_camel_case_types)]
#[repr(C)]
struct krb5_principal;


#[link(name = "krb5")]
extern "C" {
    // From krb5.h:
    //  krb5_error_code KRB5_CALLCONV
    //  krb5_init_context(krb5_context *context);
    fn krb5_init_context(context: *mut *mut krb5_context) -> c_int;

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_free_context(krb5_context context);
    fn krb5_free_context(context: *mut krb5_context);

    // From krb5.h:
    //  krb5_error_code KRB5_CALLCONV
    //  krb5_parse_name(krb5_context context,
    //                  const char *name,
    //                  krb5_principal *nprincipal);
    fn krb5_parse_name(context: *mut krb5_context,
                       name: *const c_char,
                       principal: *mut *mut krb5_principal) -> c_int;

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_free_principal(krb5_context context,
    //                      krb5_principal val);
    fn krb5_free_principal(context: *mut krb5_context,
                           val: *mut krb5_principal);

    // From krb5.h:
    //  krb5_error_code KRB5_CALLCONV
    //  krb5_aname_to_localname(krb5_context context,
    //                          krb5_const_principal aname,
    //                          int lnsize_in,
    //                          char *lname);
    fn krb5_aname_to_localname(context: *mut krb5_context,
                               aname: *mut krb5_principal,
                               size: c_int,
                               lname: *mut [u8]) -> c_int;
}
