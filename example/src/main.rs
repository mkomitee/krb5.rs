extern crate krb5;

// use krb5;

fn main() {
    let kctx = krb5::Krb5Context::new();
    match kctx {
        Ok(ctx) => println!("Success, got context: {:?}", ctx),
        Err(e) => println!("Failure, cannot initialize conterxt: {:?}", e)
    }
}
