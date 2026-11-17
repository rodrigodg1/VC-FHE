// Matched OFF-CHAIN baseline: ordinary owner signatures on exact ciphertexts,
// followed by independent full reaggregation. Same keys, messages, weights,
// input ciphertexts, output vector, consumer and valid noise/message regime.
fn release_lwe_simulation(args: &[String]) {
    assert_eq!(args.len(),5,"release-lwe KEY.json LIFTED.json AUTHORIZED_DIGEST");
    let strings: Vec<String> = serde_json::from_slice(&std::fs::read(&args[3]).unwrap()).unwrap();
    let key:serde_json::Value=serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    let public=key["profile"].as_str()==Some(PUBLIC_LWE_PROFILE);
    assert!(key.is_array() || public,"unsupported encryption profile");
    let dimension=if public { PUBLIC_LWE_K } else { LWE_K };
    assert_eq!(strings.len(),dimension+1,"wrong ciphertext dimension");
    let coordinates: Vec<Fr> = strings.iter().map(|s| {
        let value:Fr=s.parse().expect("non-field coordinate");
        assert_eq!(value.into_bigint().to_string(),*s,"noncanonical coordinate"); value
    }).collect();
    assert_eq!(coords_digest_hex(&coordinates),args[4],"unauthorized delivered vector");
    let secret:Vec<u64>=serde_json::from_value(if public {key["secret"].clone()} else {key}).unwrap();
    assert!(secret.len()==dimension && secret.iter().all(|v|*v<=1),"invalid simulation key");
    let sk=LweSecretKey::from_container(secret);
    let ct=LweCiphertextOwned::from_container(derive_canonical_ct(&coordinates),CiphertextModulus::new_native());
    let raw=decrypt_lwe_ciphertext(&sk,&ct).0;
    let value=(raw.wrapping_add(DELTA/2)/DELTA)%(1u64<<MSG_BITS);
    println!("{}",serde_json::json!({"value":value.to_string(),"backend":"local-full-key-kms-simulation"}));
}

fn run_matched_baseline(args: &[String]) {
    use std::time::Instant;
    let out = args.get(2).expect("bench-matched OUT.csv [REPEATS]");
    let repeats: usize = args.get(3).map(|s| s.parse().expect("repeats")).unwrap_or(3);
    assert!(repeats >= 3, "comparison requires at least three fresh encryptions");
    let mut rows = String::from("variant,phase,n,repeat,elapsed_ms,input_bytes,output_bytes,input_encryption,public_key_bytes\n");
    let d = PUBLIC_LWE_K + 1;
    let t = Instant::now(); let gens = commit_generators(d);
    rows.push_str(&format!("commitment,public_basis,0,0,{:.6},0,0,{PUBLIC_LWE_PROFILE},0\n", t.elapsed().as_secs_f64()*1000.0));
    for n in [2usize, 10, 20, 33] { for repeat in 0..repeats {
        let ratings: Vec<u64> = (0..n).map(|i| (i as u64 % 5)+1).collect();
        let expected = ratings.iter().sum::<u64>();
        assert!(public_regime_ok(n, expected as u128));
        let t = Instant::now(); let mut ctx = PublicLweCtx::new();
        let mut rng = StdRng::from_entropy();
        let owners: Vec<Lhs> = (0..n).map(|_| Lhs::keygen(&mut rng,0)).collect();
        let public_key_bytes=bincode::serialize(&ctx.owner.pk).unwrap().len();
        let mut push = |variant: &str, phase: &str, started: Instant| {
            rows.push_str(&format!("{variant},{phase},{n},{repeat},{:.6},{},{},{PUBLIC_LWE_PROFILE},{public_key_bytes}\n",
                started.elapsed().as_secs_f64()*1000.0,n*d*8,d*32));
        };
        push("shared","key_setup",t);
        let t = Instant::now();
        let cts: Vec<LweCiphertextOwned<u64>> = ratings.iter().map(|m| ctx.encrypt(*m)).collect();
        let coords: Vec<Vec<Fr>> = cts.iter().map(coords_to_fr).collect();
        push("shared","encrypt_and_encode",t);
        let mut context = Keccak256::new(); context.update(b"VCFHE-MATCHED-LINEAR-V2");
        context.update((n as u64).to_be_bytes()); context.update((repeat as u64).to_be_bytes());
        // Unique benchmark domain. This is an off-chain computation comparison;
        // deployment-bound gas and replay checks are measured separately.
        let tag: [u8;32] = context.finalize().into();
        let t = Instant::now();
        let mut lifted = vec![Fr::zero();d];
        for c in &coords { for j in 0..d { lifted[j] += c[j]; } }
        let delivered_digest = coords_digest_hex(&lifted);
        push("shared","operator_aggregate_and_digest",t);
        // Reverse variant order on alternating trials to expose neither to a
        // systematic first/second timing advantage. Both cache admitted inputs.
        for variant in if repeat % 2 == 0 { [0,1] } else { [1,0] } {
            if variant == 0 {
                let t = Instant::now();
                let commitments: Vec<G1Projective> = coords.iter().map(|c| commit(c,&gens)).collect();
                let messages: Vec<G1Projective> = commitments.iter().enumerate().map(|(i,p)|
                    context_point(&owners[i].pk,&tag,i as u64,0,n as u64,p)).collect();
                let sigs: Vec<G1Projective> = messages.iter().enumerate().map(|(i,m)| *m*owners[i].sk).collect();
                push("commitment","owner_prepare",t);
                let t = Instant::now();
                for i in 0..n {
                    let m = context_point(&owners[i].pk,&tag,i as u64,0,n as u64,&commitments[i]);
                    assert_eq!(Bn254::pairing(sigs[i].into_affine(),G2Projective::generator().into_affine()),
                        Bn254::pairing(m.into_affine(),owners[i].pk.into_affine()));
                }
                let p_agg: G1Projective = commitments.iter().copied().sum();
                push("commitment","cached_admission",t);
                let t = Instant::now(); let p_out = commit(&lifted,&gens);
                push("commitment","operator_output_commitment",t);
                let t = Instant::now(); assert_eq!(p_out,p_agg);
                push("commitment","verifier_result",t);
                let t = Instant::now();
                assert_eq!(coords_digest_hex(&lifted),delivered_digest);
                assert_eq!(commit(&lifted,&gens),p_out);
                assert_eq!(ctx.decrypt_coords(&derive_canonical_ct(&lifted)),expected);
                push("commitment","consumer_validate_and_decrypt",t);
                let mut altered = lifted.clone(); altered[0] += Fr::from(1u64);
                assert_ne!(commit(&altered,&gens),p_agg);
            } else {
                let message = |i: usize, coordinates: &[Fr], domain: &[u8;32]| {
                    let mut bytes = b"VCFHE-ORDINARY-CIPHERTEXT-BLS-V1".to_vec();
                    bytes.extend_from_slice(domain); bytes.extend_from_slice(&(i as u64).to_be_bytes());
                    bytes.extend_from_slice(&(n as u64).to_be_bytes());
                    // A digest of every canonical input coordinate, not merely
                    // a claimed commitment. Honest input owners are assumed in
                    // both constructions; no range/PoK admission is implied.
                    bytes.extend_from_slice(coords_digest_hex(coordinates).as_bytes());
                    hash_to_g1(&bytes)
                };
                let t = Instant::now();
                let sigs: Vec<G1Projective> = coords.iter().enumerate().map(|(i,c)|message(i,c,&tag)*owners[i].sk).collect();
                push("ordinary","owner_prepare",t);
                let t = Instant::now();
                for i in 0..n { assert_eq!(Bn254::pairing(sigs[i].into_affine(),G2Projective::generator().into_affine()),
                    Bn254::pairing(message(i,&coords[i],&tag).into_affine(),owners[i].pk.into_affine())); }
                push("ordinary","cached_admission",t);
                let t = Instant::now();
                let mut reaggregated = vec![Fr::zero();d];
                for c in &coords { for j in 0..d { reaggregated[j] += c[j]; } }
                assert_eq!(lifted,reaggregated);
                push("ordinary","verifier_result",t);
                let t = Instant::now();
                assert_eq!(coords_digest_hex(&lifted),delivered_digest);
                assert_eq!(lifted,reaggregated);
                assert_eq!(ctx.decrypt_coords(&derive_canonical_ct(&lifted)),expected);
                push("ordinary","consumer_validate_and_decrypt",t);
                let mut altered = lifted.clone(); altered[0] += Fr::from(1u64);
                assert_ne!(altered,reaggregated);
                let mut different = coords[0].clone(); different[0] += Fr::from(1u64);
                assert_ne!(Bn254::pairing(sigs[0].into_affine(),G2Projective::generator().into_affine()),
                    Bn254::pairing(message(0,&different,&tag).into_affine(),owners[0].pk.into_affine()));
                let mut other_tag = tag; other_tag[0] ^= 1;
                assert_ne!(message(0,&coords[0],&tag),message(0,&coords[0],&other_tag));
            }
        }
    } }
    std::fs::write(out,rows).expect("write matched baseline CSV");
}
