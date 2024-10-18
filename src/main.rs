use ark_bn254::{Bn254, Fr};
// Use BN254 as the curve
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
// Uniform random for field elements
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::rngs::OsRng;
// Secure RNG
use clap::Parser;

/// A simple constraint system for the equation a * b = c
#[derive(Clone)]
struct SimpleCircuit {
    pub a: Option<Fr>,
    pub b: Option<Fr>,
    pub c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SimpleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs (a and b)
        let a_var = FpVar::new_witness(cs.clone(), || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = FpVar::new_witness(cs.clone(), || self.b.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate public output (c)
        let c_var = FpVar::new_input(cs.clone(), || self.c.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce a * b = c
        let result_var = &a_var * &b_var;
        result_var.enforce_equal(&c_var)?;

        Ok(())
    }
}

/// CLI Arguments parser
#[derive(Parser, Debug)]
struct Args {
    /// Private input: a
    #[arg(short, long)]
    a: u32,

    /// Private input: b
    #[arg(short, long)]
    b: u32,

    /// Public output: c (a * b = c)
    #[arg(short, long)]
    c: u32,
}

fn main() {
    // Parse CLI arguments
    let args = Args::parse();

    // Step 1: Create the R1CS circuit
    let circuit = SimpleCircuit {
        a: Some(Fr::from(args.a)),
        b: Some(Fr::from(args.b)),
        c: Some(Fr::from(args.c)),
    };

    // Step 2: Generate the Groth16 parameters
    let mut rng = OsRng;  // Use OsRng for CryptoRng compatibility
    let params = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

    // Step 3: Create a random proof for the circuit
    let proof = Groth16::<Bn254>::prove(&params.0, circuit.clone(), &mut rng).unwrap();

    // Step 4: Prepare the verifying key (public information)
    let pvk = prepare_verifying_key(&params.1);

    // Step 5: Convert public inputs into field elements
    let public_inputs = vec![Fr::from(args.c)];

    // Step 6: Verify the proof using the correct argument order
    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs[..]).unwrap();


    // Output the result
    if is_valid {
        println!("Proof is valid!");
    } else {
        println!("Proof is invalid!");
    }
}
