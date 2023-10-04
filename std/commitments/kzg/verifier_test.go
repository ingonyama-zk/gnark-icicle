package kzg

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/test"
)

const (
	kzgSize        = 128
	polynomialSize = 100
)

type KZGVerificationCircuit[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GTEl algebra.GtElementT] struct {
	SRS[G2El]
	Commitment[G1El]
	OpeningProof[S, G1El]
}

func (c *KZGVerificationCircuit[S, G1El, G2El, GTEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(c.SRS, curve, pairing)
	if err := verifier.AssertProof(c.Commitment, c.OpeningProof); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGVerification(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bn254.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bn254.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bn254.Element
	point.SetRandom()
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bn254.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bn254.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bn254.Scalar, sw_bn254.G1Affine](point, proof)
	assert.NoError(err)
	wSrs, err := ValueOfSRS[sw_bn254.G2Affine](srs)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bn254.Scalar, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		SRS:          wSrs,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[sw_bn254.Scalar, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}, test.WithValidAssignment(&assignment))
}

func TestKZGBLS12377(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12377.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12377.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12377.Element
	point.SetRandom()
	proof, err := kzg_bls12377.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12377.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12377.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12377.Scalar, sw_bls12377.G1Affine](point, proof)
	assert.NoError(err)
	wSrs, err := ValueOfSRS[sw_bls12377.G2Affine](srs)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		SRS:          wSrs,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}

	assert.CheckCircuit(&KZGVerificationCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_761))
}
