//go:build g2

package plonk_icicle

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func GnarkG2AffineToIcicleG2Affine(as []bn254.G2Affine) []icicle_bn254.G2Affine {
	fields := make([]fp.Element, 4*len(as))
	for i := 0; i < len(as); i++ {
		a := as[i]
		fields[i*4].Set(&a.X.A0)
		fields[i*4+1].Set(&a.X.A1)
		fields[i*4+2].Set(&a.Y.A0)
		fields[i*4+3].Set(&a.Y.A1)
	}
	affinesG2 := ConvertFpG2ToAffinesBytes(fields)
	return affinesG2
}

func GnarkG2AffineToProjective(as []bn254.G2Affine) []icicle_bn254.G2Projective {
	fields := make([]fp.Element, 4*len(as))
	for i := 0; i < len(as); i++ {
		a := as[i]
		fields[i*4].Set(&a.X.A0)
		fields[i*4+1].Set(&a.X.A1)
		fields[i*4+2].Set(&a.Y.A0)
		fields[i*4+3].Set(&a.Y.A1)
	}
	affines := ConvertFpG2ToAffinesBytes(fields)
	projectives := make([]icicle_bn254.G2Projective, len(affines))
	for i := 0; i < len(projectives); i++ {
		projectives[i] = affines[i].ToProjective()
	}

	return projectives
}

func ConvertFpG2ToAffinesBytes(fpElements []fp.Element) []icicle_bn254.G2Affine {
	baseFields := make([]icicle_bn254.G2BaseField, len(fpElements))

	affines := make([]icicle_bn254.G2Affine, len(baseFields)/4)
	for i := 0; i < len(affines); i++ {
		var littleEndBytesXA0, littleEndBytesXA1, littleEndBytesYA0, littleEndBytesYA1 [32]byte
		fp.LittleEndian.PutElement(&littleEndBytesXA0, fpElements[i*4])
		fp.LittleEndian.PutElement(&littleEndBytesXA1, fpElements[i*4+1])
		fp.LittleEndian.PutElement(&littleEndBytesYA0, fpElements[i*4+2])
		fp.LittleEndian.PutElement(&littleEndBytesYA1, fpElements[i*4+3])

		x := append(littleEndBytesXA0[:], littleEndBytesXA1[:]...)
		y := append(littleEndBytesYA0[:], littleEndBytesYA1[:]...)

		affines[i].X = baseFields[4*i].FromBytesLittleEndian(x)
		//affines[i].X.A1 = baseFields[4*i+1].FromBytesLittleEndian(littleEndBytesXA1[:])
		affines[i].Y = baseFields[4*i+2].FromBytesLittleEndian(y)
		//affines[i].Y.A1 = baseFields[4*i+3].FromBytesLittleEndian(littleEndBytesYA1[:])
	}

	return affines
}

func ProjectiveToGnarkG2Affine(p icicle_bn254.G2Projective) bn254.G2Affine {
	pxBytes := p.X.ToBytesLittleEndian()
	pxA0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pxBytes[:fp.Bytes]))
	pxA1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pxBytes[fp.Bytes:]))
	x := bn254.E2{
		A0: pxA0,
		A1: pxA1,
	}

	pyBytes := p.Y.ToBytesLittleEndian()
	pyA0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pyBytes[:fp.Bytes]))
	pyA1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pyBytes[fp.Bytes:]))
	y := bn254.E2{
		A0: pyA0,
		A1: pyA1,
	}

	pzBytes := p.Z.ToBytesLittleEndian()
	pzA0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pzBytes[:fp.Bytes]))
	pzA1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pzBytes[fp.Bytes:]))
	z := bn254.E2{
		A0: pzA0,
		A1: pzA1,
	}

	var zSquared bn254.E2
	zSquared.Mul(&z, &z)

	var X bn254.E2
	X.Mul(&x, &z)

	var Y bn254.E2
	Y.Mul(&y, &zSquared)

	g2Jac := bn254.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	var g2Affine bn254.G2Affine
	return *g2Affine.FromJacobian(&g2Jac)
}
