use curve25519_dalek::scalar;
use curve25519_dalek::Scalar;
use ed25519_dalek::ed25519::signature::Keypair;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::VerifyingKey;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SECRET_KEY_LENGTH;
use zk_callbacks::crypto::rr::{RRSigner, RRVerifier};
use rand::CryptoRng;
use rand::RngCore;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use rand::rngs::OsRng;


struct PrivateKey {
    signing_key: SigningKey,
}

struct PublicKey {
    verifying_key: VerifyingKey,
}

impl<S, M, R, V> RRSigner<S, M, R, V> for PrivateKey where
V: RRVerifier<S, M, R>, {
    type Vk = V;

    fn sign_message(&self, message: &M) -> S {
        // let signature: Signature = self.signing_key.sign(message);
        todo!()
    }

    fn sk_to_pk(&self) -> V {
        self.signing_key.verifying_key();
        todo!()
    }

    fn gen() -> Self {
        todo!()
    }

    fn rerand(&self, randomness: R) -> Self {
        todo!()
    }
}

impl<S, M, R> RRVerifier<S, M, R> for PublicKey {
    fn verify(&self, message: M, signature: S) -> bool {
        todo!()
    }

    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (R, Self) {
        let _ = rng;
        todo!()
    }
}

fn main() {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let message: &[u8] = b"All I want is to pet all of the dogs.";
    let a = VerifyingKey::from_bytes(&CompressedEdwardsY::from_slice(&verifying_key.to_bytes()).unwrap().decompress().unwrap().compress().to_bytes()).unwrap();
    // verifying key -> bytes -> compressed edwards Y -> edwards point [RERAND OCCURS HERE] -> compressed edwards Y -> bytes -> verifying key
    // println!("{:?}", a == verifying_key);

    // let b: signing_key.to_bytes();
    // println!("{:?}", signing_key.to_scalar_bytes());
    // println!("{:?}", SigningKey::from_bytes(&signing_key.to_scalar_bytes()) == signing_key);

    println!("{:?}", Scalar::from_canonical_bytes(signing_key.to_scalar_bytes()).unwrap().to_bytes());
    println!("{:?}", signing_key.to_bytes());

    println!("{:?}", Scalar::from_canonical_bytes(signing_key.to_scalar_bytes()).unwrap().to_bytes() == signing_key.to_bytes());
    // let b: signing_key.to_bytes();
    // println!("{:?}", b == signing_key);

}