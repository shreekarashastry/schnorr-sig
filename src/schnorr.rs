use num_modular::ModularPow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy)]
pub struct Global {
    pub p: u64, // prime number
    pub q: u64, // factor of p-1
    pub a: u64, // a s.t a^q = 1 mod p
}

impl Global {
    pub fn new(p: u64, q: u64, a: u64) -> Global {
        Global { p, q, a }
    }
}

#[derive(Clone, Copy)]
pub struct Signatures {
    e: u64,
    y: u64,
}

impl Signatures {
    pub fn get_signature(&self) -> u64 {
        self.e
    }
}

#[allow(dead_code)]
pub struct Sender {
    public_key: u64,  // public key = a^(-s) mod q
    private_key: u64, // secret key (0<s<q)
    r: u64,
    x: u64,
    message: u64,
    c_message: u64,
    pub global: Global,
}

impl Hash for Sender {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.c_message.hash(state);
    }
}

impl Sender {
    pub fn new(s: u64, r: u64, message: u64, global: Global) -> Sender {
        let x = ModularPow::powm(global.a, r, &global.p);
        let c_mesg = message + x;
        let pub_key = ModularPow::powm(global.a, 1 / s, &global.q);

        let valid_range = 0..global.q;
        // Assert that private key is between 0 and q.
        assert!(valid_range.contains(&s));

        // Assert that the chosen r value is between 0 and q as well.
        assert!(valid_range.contains(&r));

        Sender {
            public_key: pub_key,
            private_key: s,
            r,
            x,
            message,
            c_message: c_mesg,
            global,
        }
    }

    pub fn calculate_signature(&self) -> Signatures {
        let e = hash_message(&self);
        let y = (self.r + self.private_key * e) % (self.global.q);
        Signatures { e, y }
    }

    pub fn get_public_key(&self) -> u64 {
        self.public_key
    }

    pub fn get_message(&self) -> u64 {
        self.message
    }
}

fn hash_message<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish() as u64
}

#[allow(dead_code)]
pub struct Recipeint {
    sender_pub_key: u64,
    x_prime: u64,
    sender_message: u64,
    sender_sig: Signatures,
    c_message: u64,
    global: Global,
}

impl Hash for Recipeint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.c_message.hash(state);
    }
}

impl Recipeint {
    pub fn new(
        sender_pub_key: u64,
        sender_message: u64,
        sender_sig: Signatures,
        global: Global,
    ) -> Recipeint {
        let x_prime = ModularPow::powm(global.a, sender_sig.y, &global.p)
            * ModularPow::powm(sender_pub_key, sender_sig.e, &global.p)
            % (global.p);
        let c_message = sender_message + x_prime;
        Recipeint {
            sender_pub_key,
            sender_message,
            x_prime,
            sender_sig,
            c_message,
            global,
        }
    }

    pub fn get_signature(&self) -> u64 {
        hash_message(&self)
    }
}
