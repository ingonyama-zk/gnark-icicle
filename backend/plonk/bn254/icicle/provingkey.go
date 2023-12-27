package icicle_bn254

import (
	"unsafe"

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

type ProvingKey struct {
	plonk_bn254.ProvingKey
	*deviceInfo
}

// TODO add plonk setup
func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *plonk_bn254.VerifyingKey) error {
	return plonk_bn254.Setup(r1cs, &pk.ProvingKey, vk)
}

