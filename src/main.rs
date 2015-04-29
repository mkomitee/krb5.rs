extern crate libc;

#[allow(non_camel_case_types)]
#[repr(C)]
type krb5_error_code = libc::c_int;

#[allow(non_camel_case_types)]
#[repr(C)]
struct krb5_context;

#[allow(raw_pointer_derive)]
#[derive(Debug)]
struct Krb5Context {
    ctx: *mut krb5_context,
}

type Krb5Error = krb5_error_code;

type Krb5Result<T> = Result<T, Krb5Error>;

impl Krb5Context {
    fn new() -> Krb5Result<Krb5Context> {
        let mut kcontext: *mut krb5_context = std::ptr::null_mut();
        let err = unsafe {krb5_init_context(&mut kcontext)};
        if err == 0 {
            Ok(Krb5Context{ctx: kcontext})
        } else {
            Err(err)
        }
    }
}

impl Drop for Krb5Context {
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

fn main() {
    let kctx = Krb5Context::new();
    match kctx {
        Ok(ctx) => println!("Success, got context: {:?}", ctx),
        Err(e) => println!("Failure, cannot initialize conterxt: {:?}", e)
    }
}
