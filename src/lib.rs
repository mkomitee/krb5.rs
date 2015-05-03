extern crate libc;

use libc::{c_char, c_int, strlen};
use std::ffi::{NulError, CString};
use std::string::FromUtf8Error;

const MAX_USERNAME: c_int = 256;

// TODO: We can do better here. The man pages indicate the specific
// errors we may receive. For example, krb5_aname_to_localname returns
// either KRB5_LNAME_NOTRANS or KRB5_CONFIG_NOTENUFSPACE.
#[derive(Debug)]
pub enum Error {
    Krb5(Krb5Error),
    FromUtf8(FromUtf8Error),
    Nul(NulError),
}

#[derive(Debug)]
pub struct Krb5Error {
    major: c_int,
    minor: Option<c_int>,
}

impl Krb5Error {
    fn as_str(&self) -> String {
        match self.minor {
            Some(m) => format!("Kerberos Major: {}, Minor: {}", self.major, m),
            None => format!("Kerberos Major: {}", self.major),
        }
    }
}

impl std::fmt::Display for Krb5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
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
            // TODO: Find a way to get this to return e.as_str(). The
            // problem is that it must be an &str, and if we take a
            // ref to e.as_str(), the borrow doesn't last long enough.
            // Error::Krb5(ref e) => e.as_str().as_ref(),
            Error::Krb5(_) => "",
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
            Err(Error::Krb5(Krb5Error{major: err, minor: None}))
        }
    }

    // TODO: evaluate if it's appropriate to return a CString, an
    // OsString, or something else. It probably doesn't make sense to
    // require Utf8 encoding in this library.
    pub fn localname(&self, name: &str) -> Result<String> {
        let mut kprinc: *mut krb5_principal = std::ptr::null_mut();
        let cname = try!(CString::new(name.as_bytes()));
        let err = unsafe {krb5_parse_name(self.ctx, cname.as_ptr(), &mut kprinc)};
        if err != 0 {
            return Err(Error::Krb5(Krb5Error{major: err, minor: None}));
        }


        let mut lname: Vec<u8> = Vec::with_capacity(MAX_USERNAME as usize);
        unsafe {lname.set_len((MAX_USERNAME - 1) as usize)};
        lname.push('\0' as u8);
        let err = unsafe {krb5_aname_to_localname(self.ctx,
                                                  kprinc,
                                                  MAX_USERNAME - 1,
                                                  &mut lname[..])};
        unsafe {krb5_free_principal(self.ctx, kprinc)}
        if err != 0 {
            return Err(Error::Krb5(Krb5Error{major: err, minor: None}));
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
