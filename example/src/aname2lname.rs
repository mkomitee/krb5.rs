extern crate krb5;

fn main() {
    let ctx = match krb5::Context::new() {
        Ok(ctx) => ctx,
        Err(e) => panic!("Failure: {}", e)
    };
    println!("Success, got context: {:?}", ctx);

    let lname = match ctx.localname("user@EXAMPLE.COM") {
        Ok(lname) => lname,
        Err(e) => panic!("Failure: {}", e),
    };
    println!("Success, translated name: {}", lname);
}
