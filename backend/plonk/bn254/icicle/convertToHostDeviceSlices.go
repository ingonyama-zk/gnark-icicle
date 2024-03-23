package plonk_icicle

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ingonyama-zk/icicle/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func ConvertFromFrToHostDeviceSlice(data []fr.Element) core.HostOrDeviceSlice {

	scalars := ConvertFrToScalarFieldsBytes(data)

	hostDeviceScalarSlice := core.HostSliceFromElements[bn254.ScalarField](scalars)

	return hostDeviceScalarSlice
}

func ConvertFrToScalarFields(data []fr.Element) []bn254.ScalarField {
	scalars := make([]bn254.ScalarField, len(data))

	for i := 0; i < len(data); i++ {
		src := data[i] // 4 uint64

		limbs := make([]uint32, 8)
		for k := 0; k < 4; k++ {
			//fmt.Println("input", k, src[k])
			num64 := src[k]
			limbs[2*k] = uint32(num64 & 0xffffffff)
			limbs[2*k+1] = uint32(num64 >> 32)
		}
		scalars[i].FromLimbs(limbs)
	}
	return scalars
}

func ConvertFrToScalarFieldsBytes(data []fr.Element) []bn254.ScalarField {
	scalars := make([]bn254.ScalarField, len(data))

	for i := 0; i < len(data); i++ {
		src := data[i] // 4 uint64
		var littleEndian [32]byte

		fr.LittleEndian.PutElement(&littleEndian, src)
		scalars[i].FromBytesLittleEndian(littleEndian[:])
	}
	return scalars
}

func ConvertScalarFieldsToFrBytes(scalars []bn254.ScalarField) []fr.Element {
	frElements := make([]fr.Element, len(scalars))

	for i := 0; i < len(frElements); i++ {
		v := scalars[i]
		slice64, _ := fr.LittleEndian.Element((*[fr.Bytes]byte)(v.ToBytesLittleEndian()))
		frElements[i] = slice64
	}
	return frElements
}

func ConvertFpToBaseFields(data []fr.Element) []bn254.BaseField {
	scalars := make([]bn254.BaseField, len(data))
	for i := 0; i < len(data); i++ {
		src := data[i] // 4 uint64

		limbs := make([]uint32, 8)
		for k := 0; k < 4; k++ {
			num64 := src[k]
			limbs[2*k] = uint32(num64 & 0xffffffff)
			limbs[2*k+1] = uint32(num64 >> 32)
		}
		scalars[i].FromLimbs(limbs)
	}
	return scalars
}

func ConvertFpToAffines(data []fp.Element) []bn254.Affine {
	scalars := make([]bn254.BaseField, len(data))
	for i := 0; i < len(data); i++ {
		src := data[i] // 4 uint64

		limbs := make([]uint32, 8)
		for k := 0; k < 4; k++ {
			num64 := src[k]
			limbs[2*k] = uint32(num64 & 0xffffffff)
			limbs[2*k+1] = uint32(num64 >> 32)
		}
		scalars[i].FromLimbs(limbs)
	}

	affines := make([]bn254.Affine, len(data)/2)
	for i := 0; i < len(affines); i++ {
		affines[i].X = scalars[2*i]
		affines[i].Y = scalars[2*i+1]
	}
	return affines
}

func ConvertFpToAffinesBytes(fpElements []fp.Element) []bn254.Affine {

	baseFields := make([]bn254.BaseField, len(fpElements))

	affines := make([]bn254.Affine, len(baseFields)/2)
	for i := 0; i < len(affines); i++ {
		var littleEndBytesX, littleEndBytesY [32]byte
		fp.LittleEndian.PutElement(&littleEndBytesX, fpElements[i*2])
		fp.LittleEndian.PutElement(&littleEndBytesY, fpElements[i*2+1])

		affines[i].X = baseFields[2*i].FromBytesLittleEndian(littleEndBytesX[:])
		affines[i].Y = baseFields[2*i+1].FromBytesLittleEndian(littleEndBytesY[:])
	}
	return affines
}

func ConvertScalarFieldsToFr(data []bn254.ScalarField) []fr.Element {
	scalars := make([]fr.Element, len(data))
	for i := 0; i < len(data); i++ {
		limbs := data[i].GetLimbs() // 4 uint64
		for k := 0; k < 4; k++ {
			var num uint64
			num = uint64(limbs[2*k+1]) << 32
			num = num | uint64(limbs[2*k])
			scalars[i][k] = num
		}

	}
	return scalars
}
