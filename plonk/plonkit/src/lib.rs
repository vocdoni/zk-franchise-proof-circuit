#[macro_use]
extern crate serde;
#[macro_use]
extern crate hex_literal;
extern crate bellman_ce;
extern crate bellman_vk_codegen;
extern crate byteorder;
extern crate itertools;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate wasm_bindgen;
extern crate base64;

pub mod circom_circuit;
pub mod plonk;
pub mod r1cs_file;
pub mod reader;
pub mod transpile;
pub mod utils;

use wasm_bindgen::prelude::*;
use bellman_ce::pairing::bn256::Bn256;
use base64::read::DecoderReader;

use circom_circuit::CircomCircuit;
use bellman_ce::
    kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm}; 

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}


fn console_log(s : &str ) {
    unsafe { log(s); }
}

#[wasm_bindgen]
pub fn prove(r1cs_b64: &str, witness_b64: &str, key_b64: &str) -> String {
        
    console_log("load_r1cs");   
    let r1cs = reader::load_r1cs_from_bin(DecoderReader::new(&mut r1cs_b64.as_bytes(),base64::STANDARD)).0;
    
    console_log("load_witness");    
    let witness = reader::load_witness_from_bin_reader::<Bn256,_>(DecoderReader::new(&mut witness_b64.as_bytes(), base64::STANDARD)).expect("cannot read witness");
    
    console_log("load_key");    
    let key = Crs::<Bn256, CrsForMonomialForm>::read(DecoderReader::new(&mut key_b64.as_bytes(), base64::STANDARD));
    let key = match key {
        Ok(r) => r,
        Err(err) => {
            let err_print = format!("{}",err);
            console_log(&err_print);
            panic!("failed");
        }
    };

    //let key = key.expect("read key_monomial_form err");

    console_log("build_circuit");
    let circuit = CircomCircuit {
        r1cs, 
        witness: Some(witness),
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    console_log("prepare_setup");
    let setup = plonk::SetupForProver::prepare_setup_for_prover(
        circuit.clone(),
        key,
        None,
    )
    .expect("prepare err");

    console_log("proving");
    let proof = setup.prove(circuit).unwrap();
    let mut encoded_proof : Vec<u8> = Vec::new();
    proof.write(&mut encoded_proof).unwrap();

    console_log("returning proof");
    base64::encode(encoded_proof)
}   


