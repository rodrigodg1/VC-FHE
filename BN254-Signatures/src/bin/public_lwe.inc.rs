// Versioned evaluation profile. Legacy secret-key fixtures retain their parameters.
// The (dimension, Gaussian deviation) pair is the small LWE pair in TFHE-rs
// 0.7.4 PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64; no PBS parameters are used.
const PUBLIC_LWE_K: usize = 1289;
const PUBLIC_LWE_STD_DEV: f64 = 1.3847362925087773e-9;
const PUBLIC_ZERO_COUNT: usize = (PUBLIC_LWE_K + 1) * 64 + 256;
const PUBLIC_LWE_PROFILE: &str = "seeded-regev-lwe-v2";

fn public_regime_ok(n: usize, abs_result: u128) -> bool {
    // For fixed signed weights, |w_i|=1, the reused zero-encryption errors have
    // coefficients z_j=sum_i w_i r_ij, |z_j|<=N. Thus ||z||_2<=N sqrt(M),
    // without assuming independently distributed owner ciphertext errors.
    let sigma = PUBLIC_LWE_STD_DEV * 2f64.powi(64);
    let bound = 16.0 * sigma * n as f64 * (PUBLIC_ZERO_COUNT as f64).sqrt()
        + n as f64 * PUBLIC_ZERO_COUNT as f64 / 2.0;
    (1..=33).contains(&n) && abs_result < (1u128 << (MSG_BITS-1)) && bound < (DELTA/2) as f64
}

// This type has no secret key. Every owner uses fresh private subset coins.
struct PublicLweEncryptor {
    pk: SeededLwePublicKeyOwned<u64>,
    coins: SecretRandomGenerator<ActivatedRandomGenerator>,
}
impl PublicLweEncryptor {
    fn from_public_key(pk: SeededLwePublicKeyOwned<u64>) -> Self {
        let mut seeder = new_seeder();
        Self { pk, coins: SecretRandomGenerator::new(seeder.seed()) }
    }
    fn encrypt(&mut self, message: u64) -> LweCiphertextOwned<u64> {
        assert!(message < 1u64 << (MSG_BITS-1), "public input outside message domain");
        let mut ct = LweCiphertextOwned::new(0, LweDimension(PUBLIC_LWE_K).to_lwe_size(), CiphertextModulus::new_native());
        encrypt_lwe_ciphertext_with_seeded_public_key(&self.pk, &mut ct,
            Plaintext(message * DELTA), &mut self.coins);
        ct
    }
}
struct PublicLweCtx {
    sk: LweSecretKey<Vec<u64>>,
    owner: PublicLweEncryptor,
}
impl PublicLweCtx {
    fn new() -> Self {
        let mut seeder = new_seeder();
        let mut secret = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let sk = allocate_and_generate_new_binary_lwe_secret_key(LweDimension(PUBLIC_LWE_K), &mut secret);
        let noise = Gaussian::from_dispersion_parameter(StandardDev(PUBLIC_LWE_STD_DEV), 0.0);
        let pk = allocate_and_generate_new_seeded_lwe_public_key(&sk,
            LwePublicKeyZeroEncryptionCount(PUBLIC_ZERO_COUNT), noise,
            CiphertextModulus::new_native(), seeder.as_mut());
        Self { sk, owner: PublicLweEncryptor::from_public_key(pk) }
    }
    fn encrypt(&mut self, message: u64) -> LweCiphertextOwned<u64> { self.owner.encrypt(message) }
    fn decrypt_coords(&self, coords: &[u64]) -> u64 {
        assert_eq!(coords.len(), PUBLIC_LWE_K+1);
        let ct = LweCiphertextOwned::from_container(coords.to_vec(), CiphertextModulus::new_native());
        let raw = decrypt_lwe_ciphertext(&self.sk, &ct).0;
        (raw.wrapping_add(DELTA/2)/DELTA) % (1u64 << MSG_BITS)
    }
}

enum FixtureEncryption { Legacy(TfheCtx), Public(PublicLweCtx) }
impl FixtureEncryption {
    fn dimension(&self) -> usize { match self { Self::Legacy(_) => LWE_K, Self::Public(_) => PUBLIC_LWE_K } }
    fn secret(&self) -> &[u64] { match self { Self::Legacy(c) => c.sk.as_ref(), Self::Public(c) => c.sk.as_ref() } }
    fn encrypt(&mut self, message:u64) -> LweCiphertextOwned<u64> {
        match self { Self::Legacy(c) => c.encrypt(message), Self::Public(c) => c.encrypt(message) }
    }
    fn decrypt_coords(&self, coords:&[u64]) -> u64 {
        match self { Self::Legacy(c) => c.decrypt_coords(coords), Self::Public(c) => c.decrypt_coords(coords) }
    }
    fn regime(&self, n:usize, value:u128) -> bool {
        match self { Self::Legacy(_) => leveled_regime_ok(n,value), Self::Public(_) => public_regime_ok(n,value) }
    }
}

#[cfg(test)]
mod public_encryption_tests {
    use super::*;
    #[test]
    fn public_only_encryption_sum_sub_and_delivery_binding() {
        let ctx=PublicLweCtx::new();
        // Serialize/deserialize PUBLIC material into an independently randomized
        // encryptor. Decryption is invoked only by this laboratory reference.
        let bytes=bincode::serialize(&ctx.owner.pk).unwrap();
        let pk=bincode::deserialize(&bytes).unwrap();
        let mut owner=PublicLweEncryptor::from_public_key(pk);
        let mut ciphertexts=Vec::new();
        for i in 0..33 { ciphertexts.push(owner.encrypt((i%5+1) as u64)); }
        assert_ne!(owner.encrypt(3).as_ref(),owner.encrypt(3).as_ref());
        for n in [2,10,20,33] {
            let mut sum=vec![0u64;PUBLIC_LWE_K+1];
            for ct in &ciphertexts[..n] { for (a,b) in sum.iter_mut().zip(ct.as_ref()) { *a=a.wrapping_add(*b); } }
            assert_eq!(ctx.decrypt_coords(&sum),(0..n).map(|i|(i%5+1) as u64).sum::<u64>());
            assert!(public_regime_ok(n,165));
        }
        let a=owner.encrypt(500); let b=owner.encrypt(11);
        let diff:Vec<u64>=a.as_ref().iter().zip(b.as_ref()).map(|(a,b)|a.wrapping_sub(*b)).collect();
        assert_eq!(ctx.decrypt_coords(&diff),489);
        let gens=commit_generators(PUBLIC_LWE_K+1);
        let av=coords_to_fr(&a); let bv=coords_to_fr(&b);
        let mut lifted:Vec<Fr>=av.iter().zip(&bv).map(|(a,b)|*a-*b).collect();
        assert_eq!(derive_canonical_ct(&lifted),diff);
        assert_eq!(commit(&lifted,&gens),commit(&av,&gens)-commit(&bv,&gens));
        lifted[0]+=Fr::from(1u64);
        assert_ne!(commit(&lifted,&gens),commit(&av,&gens)-commit(&bv,&gens));
        assert!(!public_regime_ok(34,165)); assert!(!public_regime_ok(2,512));
    }
}
