use halo2_proofs::{
    halo2curves::bn256::{Fr as Fp, Bn256, G1Affine}, 
    poly::{
        commitment::ParamsProver,
        kzg::{
        commitment::{
            ParamsKZG,
            KZGCommitmentScheme,
        },
        strategy::SingleStrategy,
        multiopen::{ProverSHPLONK, VerifierSHPLONK}
        },
    },
    plonk::{
        create_proof, verify_proof, keygen_pk, keygen_vk, Circuit
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use std::time::Instant;
use rand::rngs::OsRng;

pub fn full_prover <C: Circuit<Fp>> (
    circuit: C,
    k: u32,
    public_input: &[Fp]
) {

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    let vk_time_start = Instant::now();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let vk_time = vk_time_start.elapsed();

    let pk_time_start = Instant::now();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let pk_time = pk_time_start.elapsed();

    let proof_time_start = Instant::now();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[public_input]], OsRng, &mut transcript)
    .expect("prover should not fail");
    let proof = transcript.finalize();
    let proof_time = proof_time_start.elapsed();

    let verifier_params = params.verifier_params();
    let verify_time_start = Instant::now();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[public_input]], &mut transcript)
    .is_ok());
    let verify_time = verify_time_start.elapsed();

    println!("Time to generate vk {:?}", vk_time);
    println!("Time to generate pk {:?}", pk_time);
    println!("Prover Time {:?}", proof_time);
    println!("Verifier Time {:?}", verify_time);
}