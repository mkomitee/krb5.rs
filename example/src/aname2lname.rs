extern crate krb5;

fn main() {
    let ctx = match krb5::Context::new() {
        Ok(ctx) => ctx,
        Err(e) => panic!("Failure, cannot initialize conterxt: {:?}", e)
    };
    println!("Success, got context: {:?}", ctx);

    let lname = match ctx.localname("user@EXAMPLE.COM") {
        Ok(lname) => lname,
        Err(e) => panic!("Failure, cannot translate authenticated name: {:?}", e),
    };
    println!("Success, translated name: {}", lname);
}
