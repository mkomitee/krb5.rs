extern crate krb5;

fn main() {
    let ctx = match krb5::Context::new() {
        Ok(ctx) => ctx,
        Err(e) => panic!("Failure, cannot initialize conterxt: {:?}", e)
    };

    println!("Success, got context: {:?}", ctx);

    let local = ctx.localname("user@EXAMPLE.ORG");
    println!("WAT?: {:?}", local);
}
