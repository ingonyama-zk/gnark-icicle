//go:build !icicle

package icicle_bn254

import (
	"time"
	"fmt"
	"unsafe"
	"math/big"
	"math/bits"
	"context"
	"hash"

	"golang.org/x/sync/errgroup"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	//"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"

	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	iciclegnark "github.com/ingonyama-zk/iciclegnark/curves/bn254"
	"github.com/consensys/gnark/logger"
)

const HasIcicle = true

const (
	id_L int = iota
	id_R
	id_O
	id_Z
	id_ZS
	id_Ql
	id_Qr
	id_Qm
	id_Qo
	id_Qk
	id_S1
	id_S2
	id_S3
	id_ID
	id_LOne
	id_Qci // [ .. , Qc_i, Pi_i, ...]
)

// blinding factors
const (
	id_Bl int = iota
	id_Br
	id_Bo
	id_Bz
	nb_blinding_polynomials
)

// blinding orders (-1 to deactivate)
const (
	order_blinding_L = 1
	order_blinding_R = 1
	order_blinding_O = 1
	order_blinding_Z = 2
)

type Proof struct {

	// Commitments to the solution vectors
	LRO [3]kzg.Digest

	// Commitment to Z, the permutation polynomial
	Z kzg.Digest

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Digest

	Bsb22Commitments []kzg.Digest

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2, qCPrime
	BatchedProof kzg.BatchOpeningProof

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof
}

func (pk *ProvingKey) setupDevicePointers() error {
	log := logger.Logger().With().Str("position", "start").Logger()
	log.Info().Msg("setupDevicePointers")

	if pk.deviceInfo != nil {
		return nil
	}

	// TODO is [0] the correct part of the array
	pk.deviceInfo = &deviceInfo{}
	n := int(pk.Domain[0].Cardinality)
	sizeBytes := n * fr.Bytes
	fmt.Print(sizeBytes)
	
	/*************************  Start Domain Device Setup  ***************************/
	copyCosetInvDone := make(chan unsafe.Pointer, 1)
	copyCosetDone := make(chan unsafe.Pointer, 1)
	copyDenDone := make(chan unsafe.Pointer, 1)

	/*************************     CosetTableInv      ***************************/
	go iciclegnark.CopyToDevice(pk.Domain[0].CosetTableInv, sizeBytes, copyCosetInvDone)

	/*************************     CosetTable      ***************************/
	go iciclegnark.CopyToDevice(pk.Domain[0].CosetTable, sizeBytes, copyCosetDone)

	/*************************     Den      ***************************/
	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(pk.Domain[0].FrMultiplicativeGen, big.NewInt(int64(pk.Domain[0].Cardinality)))
	denI.Sub(&denI, &oneI).Inverse(&denI)

	log2SizeFloor := bits.Len(uint(n)) - 1
	denIcicleArr := []fr.Element{denI}
	for i := 0; i < log2SizeFloor; i++ {
		denIcicleArr = append(denIcicleArr, denIcicleArr...)
	}
	pow2Remainder := n - 1<<log2SizeFloor
	for i := 0; i < pow2Remainder; i++ {
		denIcicleArr = append(denIcicleArr, denI)
	}

	go iciclegnark.CopyToDevice(denIcicleArr, sizeBytes, copyDenDone)

	/*************************     Twiddles and Twiddles Inv    ***************************/
	log = logger.Logger().With().Str("position", "start").Logger()
	log.Info().Msg("Generating Twiddle Factors")

	twiddlesInv_d_gen, twddles_err := iciclegnark.GenerateTwiddleFactors(n, true)
	if twddles_err != nil {
		return twddles_err
	}

	twiddles_d_gen, twddles_err := iciclegnark.GenerateTwiddleFactors(n, false)
	if twddles_err != nil {
		return twddles_err
	}

	/*************************  End Domain Device Setup  ***************************/
	pk.DomainDevice.Twiddles = twiddles_d_gen
	pk.DomainDevice.TwiddlesInv = twiddlesInv_d_gen

	pk.DomainDevice.CosetTableInv = <-copyCosetInvDone
	pk.DomainDevice.CosetTable = <-copyCosetDone
	pk.DenDevice = <-copyDenDone

	return nil
}


func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*plonk_bn254.Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("get prover options: %w", err)
	}

	log := logger.Logger().With().Str("curve", spr.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", spr.GetNbConstraints()).Str("backend", "plonk").Logger()
	if pk.deviceInfo == nil {
		log.Debug().Msg("precomputing proving key in GPU")
		if err := pk.setupDevicePointers(); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
	}

	start := time.Now()

	// init instance
	g, ctx := errgroup.WithContext(context.Background())
	instance, err := newInstance(ctx, spr, pk, fullWitness, &opt)
	if err != nil {
		return nil, fmt.Errorf("new instance: %w", err)
	}

	// solve constraints
	g.Go(instance.solveConstraints)

    // compute numerator data
	g.Go(instance.initComputeNumerator)

	// complete qk
	g.Go(instance.completeQk)

	// init blinding polynomials
	g.Go(instance.initBlindingPolynomials)

	// derive gamma, beta (copy constraint)
	g.Go(instance.deriveGammaAndBeta)

	// compute accumulating ratio for the copy constraint
	g.Go(instance.buildRatioCopyConstraint)

	// compute h
	g.Go(instance.evaluateConstraints)

	// open Z (blinded) at ωζ (proof.ZShiftedOpening)
	g.Go(instance.openZ)

	// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
	g.Go(instance.foldH)

	// linearized polynomial
	g.Go(instance.computeLinearizedPolynomial)

	// Batch opening
	g.Go(instance.batchOpening)

	if err := g.Wait(); err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return instance.proof, nil

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return &plonk_bn254.Proof{}, nil 
}

// represents a Prover instance
type instance struct {
	ctx context.Context

	pk    *ProvingKey
	proof *plonk_bn254.Proof
	spr   *cs.SparseR1CS
	opt   *backend.ProverConfig

	fs             fiatshamir.Transcript
	kzgFoldingHash hash.Hash // for KZG folding
	htfFunc        hash.Hash // hash to field function

	// polynomials
	x        []*iop.Polynomial // x stores tracks the polynomial we need
	bp       []*iop.Polynomial // blinding polynomials
	h        *iop.Polynomial   // h is the quotient polynomial
	blindedZ []fr.Element      // blindedZ is the blinded version of Z

	foldedH       []fr.Element // foldedH is the folded version of H
	foldedHDigest kzg.Digest   // foldedHDigest is the kzg commitment of foldedH

	linearizedPolynomial       []fr.Element
	linearizedPolynomialDigest kzg.Digest

	fullWitness witness.Witness

	// bsb22 commitment stuff
	commitmentInfo constraint.PlonkCommitments
	commitmentVal  []fr.Element
	cCommitments   []*iop.Polynomial

	// challenges
	gamma, beta, alpha, zeta fr.Element

	// compute numerator data
	cres, twiddles0, cosetTableRev, twiddlesRev []fr.Element

	// channel to wait for the steps
	chLRO,
	chQk,
	chbp,
	chZ,
	chH,
	chRestoreLRO,
	chZOpening,
	chLinearizedPolynomial,
	chFoldedH,
	chNumeratorInit,
	chGammaBeta chan struct{}
}

func newInstance(ctx context.Context, spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts *backend.ProverConfig) (*instance, error) {
	if opts.HashToFieldFn == nil {
		opts.HashToFieldFn = hash_to_field.New([]byte("BSB22-Plonk"))
	}
	s := instance{
		ctx:                    ctx,
		pk:                     pk,
		proof:                  &plonk_bn254.Proof{},
		spr:                    spr,
		opt:                    opts,
		fullWitness:            fullWitness,
		bp:                     make([]*iop.Polynomial, nb_blinding_polynomials),
		fs:                     fiatshamir.NewTranscript(opts.ChallengeHash, "gamma", "beta", "alpha", "zeta"),
		kzgFoldingHash:         opts.KZGFoldingHash,
		htfFunc:                opts.HashToFieldFn,
		chLRO:                  make(chan struct{}, 1),
		chQk:                   make(chan struct{}, 1),
		chbp:                   make(chan struct{}, 1),
		chGammaBeta:            make(chan struct{}, 1),
		chZ:                    make(chan struct{}, 1),
		chH:                    make(chan struct{}, 1),
		chZOpening:             make(chan struct{}, 1),
		chLinearizedPolynomial: make(chan struct{}, 1),
		chFoldedH:              make(chan struct{}, 1),
		chRestoreLRO:           make(chan struct{}, 1),
		chNumeratorInit:        make(chan struct{}, 1),
	}
	s.initBSB22Commitments()
	s.setupGKRHints()
	s.x = make([]*iop.Polynomial, id_Qci+2*len(s.commitmentInfo))

	return &s, nil
}

func (s *instance) initBSB22Commitments() {
	s.commitmentInfo = s.spr.CommitmentInfo.(constraint.PlonkCommitments)
	s.commitmentVal = make([]fr.Element, len(s.commitmentInfo)) // TODO @Tabaie get rid of this
	s.cCommitments = make([]*iop.Polynomial, len(s.commitmentInfo))
	s.proof.Bsb22Commitments = make([]kzg.Digest, len(s.commitmentInfo))

	// override the hint for the commitment constraints
	for i := range s.commitmentInfo {
		s.opt.SolverOpts = append(s.opt.SolverOpts,
			solver.OverrideHint(s.commitmentInfo[i].HintID, s.bsb22Hint(i)))
	}
}

func (s *instance) setupGKRHints() {
	if s.spr.GkrInfo.Is() {
		var gkrData cs.GkrSolvingData
		s.opt.SolverOpts = append(s.opt.SolverOpts,
			solver.OverrideHint(s.spr.GkrInfo.SolveHintID, cs.GkrSolveHint(s.spr.GkrInfo, &gkrData)),
			solver.OverrideHint(s.spr.GkrInfo.ProveHintID, cs.GkrProveHint(s.spr.GkrInfo.HashName, &gkrData)))
	}
}

// Computing and verifying Bsb22 multi-commits explained in https://hackmd.io/x8KsadW3RRyX7YTCFJIkHg
func (s *instance) bsb22Hint(commDepth int) solver.Hint {
	return func(_ *big.Int, ins, outs []*big.Int) error {
		var err error

		res := &s.commitmentVal[commDepth]

		commitmentInfo := s.spr.CommitmentInfo.(constraint.PlonkCommitments)[commDepth]
		committedValues := make([]fr.Element, s.pk.Domain[0].Cardinality)
		offset := s.spr.GetNbPublicVariables()
		for i := range ins {
			committedValues[offset+commitmentInfo.Committed[i]].SetBigInt(ins[i])
		}
		if _, err = committedValues[offset+commitmentInfo.CommitmentIndex].SetRandom(); err != nil { // Commitment injection constraint has qcp = 0. Safe to use for blinding.
			return err
		}
		if _, err = committedValues[offset+s.spr.GetNbConstraints()-1].SetRandom(); err != nil { // Last constraint has qcp = 0. Safe to use for blinding
			return err
		}
		s.cCommitments[commDepth] = iop.NewPolynomial(&committedValues, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		if s.proof.Bsb22Commitments[commDepth], err = kzg.Commit(s.cCommitments[commDepth].Coefficients(), s.pk.KzgLagrange); err != nil {
			return err
		}
		s.cCommitments[commDepth].ToCanonical(&s.pk.Domain[0]).ToRegular()

		s.htfFunc.Write(s.proof.Bsb22Commitments[commDepth].Marshal())
		hashBts := s.htfFunc.Sum(nil)
		s.htfFunc.Reset()
		nbBuf := fr.Bytes
		if s.htfFunc.Size() < fr.Bytes {
			nbBuf = s.htfFunc.Size()
		}
		res.SetBytes(hashBts[:nbBuf]) 
		res.BigInt(outs[0])

		return nil
	}
}

// solveConstraints computes the evaluation of the polynomials L, R, O
// and sets x[id_L], x[id_R], x[id_O] in canonical form
func (s *instance) solveConstraints() error {
	fmt.Print("solver constraints")
	return nil
} 

func (s *instance) initComputeNumerator() error {
	fmt.Print("init Compute Numerator")
	return nil
} 

func (s *instance) completeQk() error {
	fmt.Print("completeQk")
	return nil
}

func (s *instance) initBlindingPolynomials() error {
	fmt.Print("initBlindingPolynomials")
	return nil
}

func (s *instance) deriveGammaAndBeta() error {
	fmt.Print("deriveGammaAndBeta")
	return nil
}

func (s *instance) buildRatioCopyConstraint() error {
	fmt.Print("buildRatioCopyConstraint")
	return nil
}

func (s *instance) evaluateConstraints() error {
	fmt.Print("evaluateConstraints")
	return nil
}

func (s *instance) openZ() error {
	fmt.Print("openZ")
	return nil
}

func (s *instance) foldH() error {
	fmt.Print("foldH")
	return nil
}

func (s *instance) computeLinearizedPolynomial() error {
	fmt.Print("computeLinearizedPolynomial")
	return nil
}

func (s *instance) batchOpening() error {
	fmt.Print("batchOpening")
	return nil
}
