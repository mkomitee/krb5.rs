extern crate libc;

#[allow(non_camel_case_types)]
#[repr(C)]
type krb5_error_code = libc::c_int;

#[allow(non_camel_case_types)]
#[repr(C)]
struct krb5_context;

#[allow(raw_pointer_derive)]
#[derive(Debug)]
pub struct Context {
    ctx: *mut krb5_context,
}

pub type Error = krb5_error_code;

pub type Result<T> = std::result::Result<T, Error>;

impl Context {
    pub fn new() -> Result<Context> {
        let mut kcontext: *mut krb5_context = std::ptr::null_mut();
        let err = unsafe {krb5_init_context(&mut kcontext)};
        if err == 0 {
            Ok(Context{ctx: kcontext})
        } else {
            Err(err)
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe{
            krb5_free_context(self.ctx)
        }
    }
}

#[link(name = "krb5")]
extern "C" {
    fn krb5_init_context(context: *mut *mut krb5_context) -> krb5_error_code;
    fn krb5_free_context(context: *mut krb5_context);
}
