package icicle_bn254

import (
	"unsafe"

	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"

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

