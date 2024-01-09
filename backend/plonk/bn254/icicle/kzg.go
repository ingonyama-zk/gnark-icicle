package icicle_bn254

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	iciclegnark "github.com/ingonyama-zk/iciclegnark/curves/bn254"
)

// Digest commitment of a polynomial.
type Digest = bn254.G1Affine

var (
	ErrInvalidPolynomialSize = errors.New("invalid polynomial size (larger than SRS or == 0)")
)

// Commit commits to a polynomial using a multi exponentiation with the SRS.
// It is assumed that the polynomial is in canonical form, in Montgomery form.
func Commit(p []fr.Element, pk kzg.ProvingKey, nbTasks ...int) (Digest, error) {
	if len(p) == 0 || len(p) > len(pk.G1) {
		return Digest{}, ErrInvalidPolynomialSize
	}
	// Size of the polynomial
	np := len(p)

	// Size of the polynomial in bytes
	sizeBytesScalars := len(p) * fr.Bytes

	// Copy points to device
	copyTmpDone := make(chan unsafe.Pointer, 1)
	tmpDeviceData := make(chan iciclegnark.OnDeviceData, 1)
	go func() {
		// size of the commitment key
		sizeBytes := len(pk.G1[:np]) * fp.Bytes * 2

		// Perform copy operation
		iciclegnark.CopyPointsToDevice(pk.G1[:np], sizeBytes, copyTmpDone)

		// Receive result once copy operation is done
		keyDevice := <-copyTmpDone

		// Create OnDeviceData
		tmpDeviceValue := iciclegnark.OnDeviceData{
			P:    keyDevice,
			Size: sizeBytes,
		}

		// Send OnDeviceData to respective channel
		tmpDeviceData <- tmpDeviceValue

		// Close channels
		close(copyTmpDone)
		close(tmpDeviceData)
	}()

	//  Copy device data to respective channels
	tmpDeviceValue := <-tmpDeviceData

	// Initialize Scalar channels
	copyCpDone := make(chan unsafe.Pointer, 1)
	cpDeviceData := make(chan iciclegnark.OnDeviceData, 1)

	// Copy Scalar to device
	go func() {
		// Perform copy operation
		iciclegnark.CopyToDevice(p, sizeBytesScalars, copyCpDone)

		// Receive result once copy operation is done
		cpDevice := <-copyCpDone

		// Create OnDeviceData
		cpDeviceValue := iciclegnark.OnDeviceData{
			P:    cpDevice,
			Size: sizeBytesScalars,
		}

		// Send OnDeviceData to respective channel
		cpDeviceData <- cpDeviceValue

		// Close channels
		close(copyCpDone)
		close(cpDeviceData)
	}()

	// Wait for copy operation to finish
	cpDeviceValue := <-cpDeviceData

	// KZG Committment on device
	var wg sync.WaitGroup

	// Perform multi exponentiation on device
	wg.Add(1)
	tmpChan := make(chan bn254.G1Affine, 1)
	go func() {
		defer wg.Done()
		tmp, _, err := iciclegnark.MsmOnDevice(cpDeviceValue.P, tmpDeviceValue.P, cpDeviceValue.Size, true)
		fmt.Println("tmp", tmp)
		if err != nil {
			fmt.Print("error", err)
		}
		var res bn254.G1Affine
		res.FromJacobian(&tmp)
		tmpChan <- res
	}()
	wg.Wait()

	// Receive result once copy operation is done
	res := <-tmpChan

	// Free device memory
	go func() {
		iciclegnark.FreeDevicePointer(unsafe.Pointer(&cpDeviceValue))
		iciclegnark.FreeDevicePointer(unsafe.Pointer(&tmpDeviceValue))
	}()

	return res, nil
}
