package plonk_icicle

import (
	"fmt"
	"math/rand"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
)

func deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...*curve.G1Affine) (fr.Element, error) {

	var buf [curve.SizeOfG1AffineUncompressed]byte
	var r fr.Element

	for _, p := range points {
		buf = p.RawBytes()
		if err := fs.Bind(challenge, buf[:]); err != nil {
			return r, err
		}
	}

	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil
}

func bindPublicData(fs *fiatshamir.Transcript, challenge string, vk *plonk_bn254.VerifyingKey, publicInputs []fr.Element) error {

	// permutation
	if err := fs.Bind(challenge, vk.S[0].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[1].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[2].Marshal()); err != nil {
		return err
	}

	// coefficients
	if err := fs.Bind(challenge, vk.Ql.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qr.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qm.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qo.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qk.Marshal()); err != nil {
		return err
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, vk.Qcp[i].Marshal()); err != nil {
			return err
		}
	}

	// public inputs
	for i := 0; i < len(publicInputs); i++ {
		if err := fs.Bind(challenge, publicInputs[i].Marshal()); err != nil {
			return err
		}
	}

	return nil

}

func CheckEquality(a, b []*iop.Polynomial) {

	// check random coefficient
	rc := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(4097)

	for i := 0; i < len(a); i++ {
		if a[i].Coefficients()[rc] != b[i].Coefficients()[rc] {
			panic("equality check failed")
		}
		if a[i].Layout != b[i].Layout {
			panic("layout check failed")
		}
		if a[i].Basis != b[i].Basis {
			panic("basis check failed")
		}
	}
}

func CheckBasis(a []*iop.Polynomial) {

	for i := 0; i < len(a); i++ {
		if a[i].Basis != iop.Canonical {
			fmt.Println("basis check failed", i)
			panic("basis check failed")
		}
	}
}
