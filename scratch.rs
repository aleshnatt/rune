use rand::Rng;
fn main() {
    let mut rng = rand::rng();
    let x: u32 = rng.random();
    println!("{}", x);
}
