extern crate libc;

use libc::{c_int, strlen};
use std::ffi::{CString};

use ffi::*;
use error::Error;
use error::Krb5Error;
use error::Result;
use principal::Principal;

const MAX_USERNAME: c_int = 256;

#[allow(raw_pointer_derive)]
#[derive(Debug)]
pub struct Context {
    // TODO: Find a way to refactor this so it can be private.
    pub ctx: *mut krb5_context,
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
        let mut kcontext: *mut krb5_context = ::std::ptr::null_mut();
        let err = unsafe {krb5_init_context(&mut kcontext)};
        if err == 0 {
            Ok(Context{ctx: kcontext})
        } else {
            Err(Error::Krb5(Krb5Error::new(err)))
        }
    }

    // TODO: Find a way to refactor this so it can be private.
    pub fn error_message(&self, code: c_int) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::Context;

    #[test]
    fn create_context() {
        assert!(Context::new().is_ok());
    }
    #[test]
    fn translate_localname_ok() {
        // FIXME: This has a side effect which we don't reset.
        ::std::env::set_var("KRB5_CONFIG", "example/krb5.conf");
        let ctx = Context::new();
        let localname = ctx.unwrap().localname("user@EXAMPLE.COM");
        assert_eq!(localname.unwrap(), "user");
    }
    #[test]
    #[should_panic(expected="No translation")]
    fn translate_localname_err() {
        // FIXME: This has a side effect which we don't reset.
        ::std::env::set_var("KRB5_CONFIG", "example/krb5.conf.missing");
        let ctx = Context::new();
        let localname = ctx.unwrap().localname("user@EXAMPLE.COM");
        localname.unwrap();
    }
}
