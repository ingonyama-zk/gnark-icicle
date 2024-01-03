package icicle_bn254

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/logger"
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
	log := logger.Logger()
	log.Info().Msg("Running KZG Commit on Device")

	if len(p) == 0 || len(p) > len(pk.G1) {
		return Digest{}, ErrInvalidPolynomialSize
	}

	var res bn254.G1Affine

	config := ecc.MultiExpConfig{}
	if len(nbTasks) > 0 {
		config.NbTasks = nbTasks[0]
	}

	startTime := time.Now()

	sizeBytes := len(pk.G1[:len(p)]) * fp.Bytes * 2
	copyKeyDone := make(chan unsafe.Pointer, 1)

	go iciclegnark.CopyPointsToDevice(pk.G1[:len(p)], sizeBytes, copyKeyDone)

	keyDevice := <-copyKeyDone
	keyDeviceValue := iciclegnark.OnDeviceData{
		P:    keyDevice,
		Size: sizeBytes,
	}

	log.Debug().Int("sizeBytes", sizeBytes).Dur("elapsed", time.Since(startTime)).Msg("Copied Scalars to device.")

	startTime = time.Now()

	copyCpDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyToDevice(p, sizeBytes, copyCpDone)
	cpDevice := <-copyCpDone

	log.Debug().Dur("elapsed", time.Since(startTime)).Msg("Copied Points to device.")

	var tmp bn254.G1Jac
	tmp, _, err := iciclegnark.MsmOnDevice(keyDeviceValue.P, cpDevice, keyDeviceValue.Size, true)
	if err != nil {
		fmt.Print("error")
	}
	res.FromJacobian(&tmp)

	startTime = time.Now()
	log.Debug().Dur("elapsed", time.Since(startTime)).Msg("MSM on device.")

	return res, nil
}
