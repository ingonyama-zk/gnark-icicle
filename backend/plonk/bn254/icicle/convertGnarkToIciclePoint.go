package plonk_icicle

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func ProjectiveToGnarkAffine(p icicle_bn254.Projective) bn254.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.X).ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.Y).ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.Z).ToBytesLittleEndian()))

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(&pz)

	x.Mul(&px, zInv)
	y.Mul(&py, zInv)

	return bn254.G1Affine{X: *x, Y: *y}
}

func GnarkAffineToIcicleAffine(as []bn254.G1Affine) []icicle_bn254.Affine {
	fields := make([]fp.Element, 2*len(as))
	for i := 0; i < len(as); i++ {
		a := as[i]
		fields[i*2].Set(&a.X)
		fields[i*2+1].Set(&a.Y)
	}
	affines := ConvertFpToAffinesBytes(fields)
	return affines
}

func GnarkAffineToProjective(as []bn254.G1Affine) []icicle_bn254.Projective {
	fields := make([]fp.Element, 2*len(as))
	for i := 0; i < len(as); i++ {
		a := as[i]
		fields[i*2].Set(&a.X)
		fields[i*2+1].Set(&a.Y)
	}
	affines := ConvertFpToAffinesBytes(fields)
	projectives := make([]icicle_bn254.Projective, len(affines))
	for i := 0; i < len(projectives); i++ {
		projectives[i] = affines[i].ToProjective()
	}

	return projectives
}
