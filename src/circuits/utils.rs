use crate::circuits::hash_v1::Hash1Circuit;
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::VerificationStrategy;
use halo2_proofs::{
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey, VerifyingKey,
    },
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::AccumulatorStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    SerdeFormat,
};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr as Fp, G1Affine},
    poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader};
use snark_verifier::{
    pcs::kzg::{Gwc19, KzgAs, KzgDecidingKey},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::fs::File;
use std::rc::Rc;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

pub fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fp>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    evm::compile_yul(&loader.yul_code())
}

pub fn gen_proof<C: Circuit<Fp>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fp>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

pub fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fp>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}
