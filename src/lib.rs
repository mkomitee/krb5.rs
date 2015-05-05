extern crate libc;

use libc::{c_char, c_int, strlen};
use std::ffi::{NulError, CString, CStr};
use std::string::FromUtf8Error;

const MAX_USERNAME: c_int = 256;

fn c_to_string(raw: *const c_char) -> Option<String> {
    std::str::from_utf8(unsafe{CStr::from_ptr(raw)}.to_bytes())
        .ok()
        .map(|o| o.to_string())
}

#[derive(Debug)]
pub enum Error {
    Krb5(Krb5Error),
    FromUtf8(FromUtf8Error),
    Nul(NulError),
}

#[derive(Debug)]
pub struct Krb5Error {
    major: c_int,
    message: String,
}

impl Krb5Error {
    fn new(major: c_int) -> Krb5Error {
        let message = format!("Kerberos Error: {}", major).to_string();
        Krb5Error{major: major, message: message}
    }
    fn from_context(context: &Context, major: c_int) -> Krb5Error {
        let message = context.error_message(major);
        match message {
            Some(msg) => Krb5Error{major: major, message: msg},
            None => Krb5Error::new(major),
        }
    }
    fn description(&self) -> &str {
        self.message.as_ref()
    }
}

impl std::fmt::Display for Krb5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::FromUtf8(ref e) => e.fmt(f),
            Error::Nul(ref e) => e.fmt(f),
            Error::Krb5(ref e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::FromUtf8(ref e) => e.description(),
            Error::Nul(ref e) => e.description(),
            Error::Krb5(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::FromUtf8(ref e) => Some(e as &std::error::Error),
            Error::Nul(ref e) => Some(e as &std::error::Error),
            Error::Krb5(_) => None,
        }
    }
}

impl From<NulError> for Error {
    fn from(e: NulError) -> Error {
        Error::Nul(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Error {
        Error::FromUtf8(e)
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
            Err(Error::Krb5(Krb5Error::new(err)))
        }
    }

    fn error_message(&self, code: c_int) -> Option<String> {
        let raw = unsafe{krb5_get_error_message(self.ctx, code)};
        unsafe{krb5_clear_error_message(self.ctx)};
        let res = c_to_string(raw);
        unsafe{krb5_free_error_message(self.ctx, raw)};
        res
    }

    // TODO: evaluate if it's appropriate to return a CString, an
    // OsString, or something else. It probably doesn't make sense to
    // require Utf8 encoding in this library.
    pub fn localname(&self, name: &str) -> Result<String> {
        let mut princ = Principal::new(self);
        let cname = try!(CString::new(name.as_bytes()));
        let err = unsafe {krb5_parse_name(self.ctx, cname.as_ptr(), &mut princ.princ)};
        if err != 0 {
            return Err(Error::Krb5(Krb5Error::from_context(self, err)))
        }


        let mut lname: Vec<u8> = Vec::with_capacity(MAX_USERNAME as usize);
        unsafe {lname.set_len((MAX_USERNAME - 1) as usize)};
        lname.push('\0' as u8);
        let err = unsafe {krb5_aname_to_localname(self.ctx,
                                                  princ.princ,
                                                  MAX_USERNAME - 1,
                                                  &mut lname[..])};
        if err != 0 {
            return Err(Error::Krb5(Krb5Error::from_context(self, err)));
        }

        // Need to find the length (position of the NUL put in place by
        // krb5_aname_to_lname to indicate the end of the string and
        // truncate the Vec<u8> to that size so that we can convert it
        // it to a String
        let len = unsafe {strlen(lname.as_ptr() as *const i8)};
        lname.truncate(len as usize);

        Ok(try!(String::from_utf8(lname)))
    }
}

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
struct krb5_principal;
pub struct Principal<'a> {
    princ: *mut krb5_principal,
    ctx: &'a Context,
}

impl<'a> Principal<'a> {
    // TODO: Should the constructor take a principal name and handle
    // calling krb5_parse_name for it? Should it not require a Context
    // to be passed in, and initialize one?
    fn new(ctx: &Context) -> Principal {
        Principal{princ: std::ptr::null_mut(), ctx: ctx}
    }
}

impl<'a> Drop for Principal<'a> {
    fn drop(&mut self) {
        unsafe {krb5_free_principal(self.ctx.ctx, self.princ)}
    }
}



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

    // From krb5.h:
    //  const char * KRB5_CALLCONV
    //  krb5_get_error_message(krb5_context ctx,
    //                         krb5_error_code code);
    fn krb5_get_error_message(context: *mut krb5_context,
                              code: c_int) -> *const c_char;

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_clear_error_message(krb5_context ctx);
    fn krb5_clear_error_message(context: *mut krb5_context);

    // From krb5.h:
    //  void KRB5_CALLCONV
    //  krb5_free_error_message(krb5_context ctx,
    //                          const char *msg);
    fn krb5_free_error_message(context: *mut krb5_context,
                               message: *const c_char);
}
