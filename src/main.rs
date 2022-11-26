mod schnorr;
// This is an implementation of Schnorr signature scheme.
fn main() {
    println!("Welcome to simple Schnorr sig library!");

    // declaring the global variables
    let p: u64 = 7;
    let q: u64 = 3;
    let a: u64 = 2; // a^q = 1 mod p

    let global = schnorr::Global::new(p, q, a);

    // gop is the sender and boyd is the receiver
    // Ideally this should be taken as a terminal input from the sender
    // and never stored.
    // Create a sender.
    let gop_secret_key: u64 = 1;
    let gop_r: u64 = 2;
    let message: u64 = 101010;
    let gop = schnorr::Sender::new(gop_secret_key, gop_r, message, global);

    println!("Message: {}", message);

    let gop_message = gop.get_message();
    let gop_signatures = gop.calculate_signature();

    // Create a receiver.
    let boyd = schnorr::Recipeint::new(gop.get_public_key(), gop_message, gop_signatures, global);

    let sender_sig = gop_signatures.get_signature();
    let receiver_sig = boyd.get_signature();

    // In a zero knowledge way verify that the sender and receiver signatures match.
    assert_eq!(sender_sig, receiver_sig);

    println!("Sender Sig: {}", sender_sig);
    println!("Receiver calculated Sig: {}", receiver_sig);

    println!("Message hash been verified!")
}
