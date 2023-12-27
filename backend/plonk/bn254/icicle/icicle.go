//go:build !icicle

package icicle_bn254

import (
	
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"


)

type Proof struct {

	// Commitments to the solution vectors
	LRO [3]kzg.Digest

	// Commitment to Z, the permutation polynomial
	Z kzg.Digest

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Digest

	Bsb22Commitments []kzg.Digest

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2, qCPrime
	BatchedProof kzg.BatchOpeningProof

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof
}


const HasIcicle = true


func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (Proof, error) {
	return nil
}
