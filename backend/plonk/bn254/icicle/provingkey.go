package icicle_bn254

import (
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z unsafe.Pointer
	}
	DomainDevice struct {
		Twiddles, TwiddlesInv     unsafe.Pointer
		CosetTable, CosetTableInv unsafe.Pointer
	}
	G2Device struct {
		B unsafe.Pointer
	}
	DenDevice             unsafe.Pointer
	InfinityPointIndicesK []int
}

// VerifyingKey stores the data needed to verify a proof:
// * The commitment scheme
// * Commitments of ql prepended with as many ones as there are public inputs
// * Commitments of qr, qm, qo, qk prepended with as many zeroes as there are public inputs
// * Commitments to S1, S2, S3
type VerifyingKey struct {
	// Size circuit
	Size              uint64
	SizeInv           fr.Element
	Generator         fr.Element
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	Kzg kzg.VerifyingKey

	// cosetShift generator of the coset on the small domain
	CosetShift fr.Element

	// S commitments to S1, S2, S3
	S [3]kzg.Digest

	// Commitments to ql, qr, qm, qo, qcp prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Digest
	Qcp                []kzg.Digest

	CommitmentConstraintIndexes []uint64
}

// Trace stores a plonk trace as columns
type Trace struct {
	// Constants describing a plonk circuit. The first entries
	// of LQk (whose index correspond to the public inputs) are set to 0, and are to be
	// completed by the prover. At those indices i (so from 0 to nb_public_variables), LQl[i]=-1
	// so the first nb_public_variables constraints look like this:
	// -1*Wire[i] + 0* + 0 . It is zero when the constant coefficient is replaced by Wire[i].
	Ql, Qr, Qm, Qo, Qk *iop.Polynomial
	Qcp                []*iop.Polynomial

	// Polynomials representing the splitted permutation. The full permutation's support is 3*N where N=nb wires.
	// The set of interpolation is <g> of size N, so to represent the permutation S we let S acts on the
	// set A=(<g>, u*<g>, u^{2}*<g>) of size 3*N, where u is outside <g> (its use is to shift the set <g>).
	// We obtain a permutation of A, A'. We split A' in 3 (A'_{1}, A'_{2}, A'_{3}), and S1, S2, S3 are
	// respectively the interpolation of A'_{1}, A'_{2}, A'_{3} on <g>.
	S1, S2, S3 *iop.Polynomial

	// S full permutation, i -> S[i]
	S []int64
}

type ProvingKey struct {
	*plonk_bn254.ProvingKey
	*deviceInfo
}

func Setup(spr *cs.SparseR1CS, kzgSrs kzg.SRS) (*ProvingKey, *plonk_bn254.VerifyingKey, error) {
	pk, vk, err := plonk_bn254.Setup(spr, kzgSrs)
	if err != nil {
		return nil, nil, err
	}
	newPk := &ProvingKey{pk, nil}
	return newPk, vk, nil
}
