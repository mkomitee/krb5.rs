extern crate libc;

use ffi::*;
use context::Context;

#[allow(raw_pointer_derive)]
#[derive(Debug)]
pub struct Principal<'a> {
    // TODO: Find a way to refactor this so it can be private.
    pub princ: *mut krb5_principal,
    ctx: &'a Context,
}

impl<'a> Principal<'a> {
    // TODO: Should the constructor take a principal name and handle
    // calling krb5_parse_name for it? Should it not require a Context
    // to be passed in, and initialize one?
    pub fn new(ctx: &Context) -> Principal {
        Principal{princ: ::std::ptr::null_mut(), ctx: ctx}
    }
}

impl<'a> Drop for Principal<'a> {
    fn drop(&mut self) {
        unsafe {krb5_free_principal(self.ctx.ctx, self.princ)}
    }
}


