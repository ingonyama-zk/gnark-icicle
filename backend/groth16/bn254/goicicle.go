package groth16

import (
	"fmt"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
)

func INttOnDevice(scalars []fr.Element, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) (unsafe.Pointer, unsafe.Pointer) {
	scalars_d, _ := cudawrapper.CudaMalloc(sizeBytes)
	cudawrapper.CudaMemCpyHtoD(scalars_d, scalars, sizeBytes)

	icicle.FromMontgomery(scalars_d, len(scalars))

	icicle.ReverseScalars(scalars_d, size)
	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)

	return scalarsInterp, scalars_d
}

func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) []fr.Element {
	defer icicle.TimeTrack(time.Now())

	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)

	if res != 0 {
		fmt.Print("Issue evaluating")
	}

	icicle.ReverseScalars(scalars_out, size)
	icicle.ToMontgomery(scalars_out, size)

	a_host := make([]fr.Element, size)
	cudawrapper.CudaMemCpyDtoH[fr.Element](a_host, scalars_out, size_bytes)

	return a_host
}

func MsmOnDevice(points_d unsafe.Pointer, scalars []fr.Element, count int, convert bool) (curve.G1Jac, unsafe.Pointer, error) {
	defer icicle.TimeTrack(time.Now())

	scalars_d, _ := cudawrapper.CudaMalloc(len(scalars) * fr.Bytes)
	cudawrapper.CudaMemCpyHtoD(scalars_d, scalars, len(scalars)*fr.Bytes)

	out_d, _ := cudawrapper.CudaMalloc(96)
	icicle.Commit(out_d, scalars_d, points_d, count, 10)

	if convert {
		outHost := make([]icicle.PointBN254, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.PointBN254](outHost, out_d, 96)
		return *outHost[0].ToGnarkJac(), nil, nil
	}

	return curve.G1Jac{}, out_d, nil

}

func MsmG2OnDevice(points_d unsafe.Pointer, scalars []fr.Element, count int, convert bool) (curve.G2Jac, unsafe.Pointer, error) {
	defer icicle.TimeTrack(time.Now())

	scalars_d, _ := cudawrapper.CudaMalloc(len(scalars) * fr.Bytes)
	cudawrapper.CudaMemCpyHtoD(scalars_d, scalars, len(scalars)*fr.Bytes)

	out_d, _ := cudawrapper.CudaMalloc(192)

	icicle.CommitG2(out_d, scalars_d, points_d, count, 10)

	if convert {
		outHost := make([]icicle.G2Point, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, 192)
		return *outHost[0].ToGnarkJac(), nil, nil
	}

	return curve.G2Jac{}, out_d, nil
}

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) {
	defer icicle.TimeTrack(time.Now())

	if is_into {
		icicle.ToMontgomery(scalars_d, size)
	} else {
		icicle.FromMontgomery(scalars_d, size)
	}
}

func CopyScalarsToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	defer icicle.TimeTrack(time.Now())

	devicePtr, _ := cudawrapper.CudaMalloc(bytes)
	cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	MontConvOnDevice(devicePtr, len(scalars), false)

	copyDone <- devicePtr
}

func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) {
	defer icicle.TimeTrack(time.Now())

	ret := icicle.VecScalarMulMod(a_d, b_d, size)

	if ret != 0 {
		fmt.Print("Vector mult a*b issue")
	}
	ret = icicle.VecScalarSub(a_d, c_d, size)

	if ret != 0 {
		fmt.Print("Vector sub issue")
	}
	ret = icicle.VecScalarMulMod(a_d, den_d, size)

	if ret != 0 {
		fmt.Print("Vector mult a*den issue")
	}
}
