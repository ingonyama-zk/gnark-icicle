package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"

	"github.com/consensys/gnark/test/unsafekzg"
)

func runBenchmark(plonky2Circuit string, proofSystem string, profileCircuit bool, dummy bool, saveArtifacts bool) {
	commonCircuitData := types.ReadCommonCircuitData("testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	if profileCircuit {
		p = profile.Start()
	}

	var builder frontend.NewBuilder
	if proofSystem == "plonk" {
		builder = scs.NewBuilder
	} else {
		fmt.Println("Please provide a valid proof system to benchmark, we only support plonk and groth16")
		os.Exit(1)
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if profileCircuit {
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	if proofSystem == "plonk" {
		plonkProof(r1cs, plonky2Circuit, dummy, saveArtifacts)
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}
}

func plonkProof(r1cs constraint.ConstraintSystem, circuitName string, dummy bool, saveArtifacts bool) {
	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey
	var srs kzg.SRS = kzg.NewSRS(ecc.BN254)
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	// Don't serialize the circuit for now, since it takes up too much memory
	// if saveArtifacts {
	// 	fR1CS, _ := os.Create("circuit")
	// 	r1cs.WriteTo(fR1CS)
	// 	fR1CS.Close()
	// }

	fmt.Println("Running circuit setup", time.Now())

	//srs, err = test.NewKZGSRS(r1cs)
	srs, srsLagrange, err := unsafekzg.NewSRS(r1cs)

	if err != nil {
		panic(err)
	}

	pk, vk, err = plonk.Setup(r1cs, srs, srsLagrange)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if saveArtifacts {
		fPK, _ := os.Create("proving.key")
		pk.WriteTo(fPK)
		fPK.Close()

		if vk != nil {
			fVK, _ := os.Create("verifying.key")
			vk.WriteTo(fVK)
			fVK.Close()
		}

		fSolidity, _ := os.Create("proof.sol")
		err = vk.ExportSolidity(fSolidity)
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	if saveArtifacts {
		fWitness, _ := os.Create("witness")
		witness.WriteTo(fWitness)
		fWitness.Close()
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := plonk.Prove(r1cs, pk, witness, backend.WithIcicleAcceleration())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if saveArtifacts {
		fProof, _ := os.Create("proof.proof")
		proof.WriteTo(fProof)
		fProof.Close()
	}

	if vk == nil {
		fmt.Println("vk is nil, means you're using dummy setup and we skip verification of proof")
		return
	}

	fmt.Println("Verifying proof", time.Now())
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	fmt.Printf("proofBytes: %v\n", proofBytes)
}

func main() {
	plonky2Circuit := flag.String("plonky2-circuit", "step", "plonky2 circuit to benchmark")
	proofSystem := flag.String("proof-system", "plonk", "proof system to benchmark")
	profileCircuit := flag.Bool("profile", true, "profile the circuit")
	dummySetup := flag.Bool("dummy", true, "use dummy setup")
	saveArtifacts := flag.Bool("save", false, "save circuit artifacts")

	flag.Parse()

	if plonky2Circuit == nil || *plonky2Circuit == "" {
		fmt.Println("Please provide a plonky2 circuit to benchmark")
		os.Exit(1)
	}

	fmt.Printf("Running benchmark for %s circuit with proof system %s\n", *plonky2Circuit, *proofSystem)
	fmt.Printf("Profiling: %t, DummySetup: %t, SaveArtifacts: %t\n", *profileCircuit, *dummySetup, *saveArtifacts)

	runBenchmark(*plonky2Circuit, *proofSystem, *profileCircuit, *dummySetup, *saveArtifacts)
}
