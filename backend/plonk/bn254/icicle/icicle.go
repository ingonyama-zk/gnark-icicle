//go:build !icicle

package icicle_bn254

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sync/errgroup"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"

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

func (pk *ProvingKey) setupDevicePointers() error {
	log := logger.Logger().With().Str("position", "start").Logger()
	log.Info().Msg("setupDevicePointers")

	start := time.Now()

	if pk.deviceInfo != nil {
		return nil
	}

	// TODO is [0] the correct part of the array
	pk.deviceInfo = &deviceInfo{}
	n := int(pk.Domain[0].Cardinality)
	sizeBytes := n * fr.Bytes

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

	/*************************  G1 Device Setup ***************************/
	log.Info().Msg("G1 Device Setup")
	pointsBytesG1 := len(pk.Kzg.G1) * fp.Bytes * 2
	copyG1Done := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.Kzg.G1, pointsBytesG1, copyG1Done) // Make a function for points

	pointsBytesLagrangeG1 := len(pk.KzgLagrange.G1) * fp.Bytes * 2
	copyLagrangeG1Done := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.KzgLagrange.G1, pointsBytesLagrangeG1, copyLagrangeG1Done) // Make a function for points

	pk.G1Device.G1 = <-copyG1Done
	pk.G1Device.G1Lagrange = <-copyLagrangeG1Done

	log.Debug().Dur("took", time.Since(start)).Msg("Device Setup Complete")
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

func (s *instance) initComputeNumerator() error {
	n := s.pk.Domain[0].Cardinality
	s.cres = make([]fr.Element, s.pk.Domain[1].Cardinality)
	s.twiddles0 = make([]fr.Element, n)
	if n == 1 {
		// edge case
		s.twiddles0[0].SetOne()
	} else {
		copy(s.twiddles0, s.pk.Domain[0].Twiddles[0])
		for i := len(s.pk.Domain[0].Twiddles[0]); i < len(s.twiddles0); i++ {
			s.twiddles0[i].Mul(&s.twiddles0[i-1], &s.twiddles0[1])
		}
	}

	// TODO ICICLE accelerate fft
	cosetTable := s.pk.Domain[0].CosetTable
	twiddles := s.pk.Domain[1].Twiddles[0][:n]

	s.cosetTableRev = make([]fr.Element, len(cosetTable))
	copy(s.cosetTableRev, cosetTable)
	// TODO ICICLE reverseScalars
	fft.BitReverse(s.cosetTableRev)

	s.twiddlesRev = make([]fr.Element, len(twiddles))
	copy(s.twiddlesRev, twiddles)
	// TODO ICICLE reverseScalars
	fft.BitReverse(s.twiddlesRev)

	close(s.chNumeratorInit)

	return nil
}

func (s *instance) initBlindingPolynomials() error {
	s.bp[id_Bl] = getRandomPolynomial(order_blinding_L)
	s.bp[id_Br] = getRandomPolynomial(order_blinding_R)
	s.bp[id_Bo] = getRandomPolynomial(order_blinding_O)
	s.bp[id_Bz] = getRandomPolynomial(order_blinding_Z)
	close(s.chbp)
	return nil
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
		if s.proof.Bsb22Commitments[commDepth], err = kzgDeviceCommit(s.cCommitments[commDepth].Coefficients(), unsafe.Pointer(&s.pk.G1Device.G1Lagrange)); err != nil {
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
		res.SetBytes(hashBts[:nbBuf]) // TODO @Tabaie use CommitmentIndex for this; create a new variable CommitmentConstraintIndex for other uses
		res.BigInt(outs[0])

		return nil
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

// solveConstraints computes the evaluation of the polynomials L, R, O
// and sets x[id_L], x[id_R], x[id_O] in canonical form
func (s *instance) solveConstraints() error {
	_solution, err := s.spr.Solve(s.fullWitness, s.opt.SolverOpts...)
	if err != nil {
		return err
	}
	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		s.x[id_L] = iop.NewPolynomial(&evaluationLDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		wg.Done()
	}()
	go func() {
		s.x[id_R] = iop.NewPolynomial(&evaluationRDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		wg.Done()
	}()

	s.x[id_O] = iop.NewPolynomial(&evaluationODomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})

	wg.Wait()

	// commit to l, r, o and add blinding factors
	if err := s.commitToLRO(); err != nil {
		return err
	}
	close(s.chLRO)
	return nil
}

func (s *instance) completeQk() error {
	qk := s.pk.GetTrace().Qk.Clone().ToLagrange(&s.pk.Domain[0]).ToRegular()
	qkCoeffs := qk.Coefficients()

	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	copy(qkCoeffs, wWitness[:len(s.spr.Public)])

	// wait for solver to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	for i := range s.commitmentInfo {
		qkCoeffs[s.spr.GetNbPublicVariables()+s.commitmentInfo[i].CommitmentIndex] = s.commitmentVal[i]
	}

	s.x[id_Qk] = qk
	close(s.chQk)

	return nil
}

func (s *instance) commitToLRO() error {
	// wait for blinding polynomials to be initialized or context to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chbp:
	}

	g := new(errgroup.Group)

	g.Go(func() (err error) {
		s.proof.LRO[0], err = s.commitToPolyAndBlinding(s.x[id_L], s.bp[id_Bl])
		return
	})

	g.Go(func() (err error) {
		s.proof.LRO[1], err = s.commitToPolyAndBlinding(s.x[id_R], s.bp[id_Br])
		return
	})

	g.Go(func() (err error) {
		s.proof.LRO[2], err = s.commitToPolyAndBlinding(s.x[id_O], s.bp[id_Bo])
		return
	})

	return g.Wait()
}

// deriveGammaAndBeta (copy constraint)
func (s *instance) deriveGammaAndBeta() error {
	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	if err := bindPublicData(&s.fs, "gamma", s.pk.Vk, wWitness[:len(s.spr.Public)]); err != nil {
		return err
	}

	// wait for LRO to be committed
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	gamma, err := deriveRandomness(&s.fs, "gamma", &s.proof.LRO[0], &s.proof.LRO[1], &s.proof.LRO[2])
	if err != nil {
		return err
	}

	bbeta, err := s.fs.ComputeChallenge("beta")
	if err != nil {
		return err
	}
	s.gamma = gamma
	s.beta.SetBytes(bbeta)

	close(s.chGammaBeta)

	return nil
}

// commitToPolyAndBlinding computes the KZG commitment of a polynomial p
// in Lagrange form (large degree)
// and add the contribution of a blinding polynomial b (small degree)
// /!\ The polynomial p is supposed to be in Lagrange form.
func (s *instance) commitToPolyAndBlinding(p, b *iop.Polynomial) (commit curve.G1Affine, err error) {
	log := logger.Logger()
	start := time.Now()

	ch1 := make(chan curve.G1Affine, 1)
	ch2 := make(chan curve.G1Affine, 1)

	// Run kzg commit on device
	go func() {
		start := time.Now()
		c, err := kzgDeviceCommit(p.Coefficients(), s.pk.G1Device.G1Lagrange)
		//c, err := kzg.Commit(p.Coefficients(), s.pk.KzgLagrange)
		if err != nil {
			log.Error().Err(err).Msg("Error during Commit")
		}
		ch1 <- c
		log.Debug().Dur("took", time.Since(start)).Msg("KZG Commit")
	}()
	commit = <-ch1

	// Run commitToPolyAndBlinding on device
	go func() {
		start := time.Now()
		n := int(s.pk.Domain[0].Cardinality)
		cb := deviceCommitBlindingFactor(n, b, s.pk)
		ch2 <- cb
		log.Debug().Dur("took", time.Since(start)).Msg("Blinding Commit")
	}()
	blinding := <-ch2

	commit.Add(&commit, &blinding)

	log.Debug().Dur("took", time.Since(start)).Msg("commitToPolyAndBlinding")
	return
}

// deviceCommitBlindingFactor computes the blindingFactor of a polynomial p on the device
// size of vectors for len of the polynomial - give idea of what the performance means
func deviceCommitBlindingFactor(n int, b *iop.Polynomial, pk *ProvingKey) curve.G1Affine {
	// scalars
	cp := b.Coefficients()
	np := b.Size()

	// get slice of points from unsafe pointer
	resPtr := unsafe.Pointer(uintptr(unsafe.Pointer(pk.G1Device.G1)) + uintptr(n)*unsafe.Sizeof(curve.G1Affine{}))

	// Initialize channels
	copyCpDone := make(chan unsafe.Pointer, 1)
	cpDeviceData := make(chan iciclegnark.OnDeviceData, 1)

	// Start asynchronous routine
	go func() {

		// tbd mul * 2
		sizeBytesScalars := np * fr.Bytes

		// Perform copy operation
		iciclegnark.CopyToDevice(cp, sizeBytesScalars, copyCpDone)

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

	var wg sync.WaitGroup

	// Calculate(lo) commitment on Device
	wg.Add(1)
	tmpChan := make(chan curve.G1Affine, 1)
	go func() {
		defer wg.Done()
		tmpVal, _, err := iciclegnark.MsmOnDevice(cpDeviceValue.P, pk.G1Device.G1, np, true)
		if err != nil {
			fmt.Print("Error", err)
		}
		var tmp curve.G1Affine
		tmp.FromJacobian(&tmpVal)
		tmpChan <- tmp
	}()
	wg.Wait()

	tmpAffinePoint := <-tmpChan

	// Calculate(hi) commitment on Device
	wg.Add(1)
	resChan := make(chan curve.G1Affine, 1)
	go func() {
		defer wg.Done()

		resVal, _, err := iciclegnark.MsmOnDevice(cpDeviceValue.P, resPtr, np, true)
		if err != nil {
			fmt.Print("Error", err)
		}
		var res curve.G1Affine
		res.FromJacobian(&resVal)

		resChan <- res
	}()
	wg.Wait()
	resAffinePoint := <-resChan

	// Sub(lo, hi) to get the final commitment
	resAffinePoint.Sub(&resAffinePoint, &tmpAffinePoint)

	// Free device memory
	go func() {
		iciclegnark.FreeDevicePointer(unsafe.Pointer(&cpDeviceValue))
	}()

	return resAffinePoint
}

func (s *instance) deriveAlpha() (err error) {
	alphaDeps := make([]*curve.G1Affine, len(s.proof.Bsb22Commitments)+1)
	for i := range s.proof.Bsb22Commitments {
		alphaDeps[i] = &s.proof.Bsb22Commitments[i]
	}
	alphaDeps[len(alphaDeps)-1] = &s.proof.Z
	s.alpha, err = deriveRandomness(&s.fs, "alpha", alphaDeps...)
	return err
}

func (s *instance) deriveZeta() (err error) {
	s.zeta, err = deriveRandomness(&s.fs, "zeta", &s.proof.H[0], &s.proof.H[1], &s.proof.H[2])
	return
}

// evaluateConstraints computes H
func (s *instance) evaluateConstraints() (err error) {
	log := logger.Logger()

	// clone polys from the proving key.
	s.x[id_Ql] = s.pk.GetTrace().Ql.Clone()
	s.x[id_Qr] = s.pk.GetTrace().Qr.Clone()
	s.x[id_Qm] = s.pk.GetTrace().Qm.Clone()
	s.x[id_Qo] = s.pk.GetTrace().Qo.Clone()
	s.x[id_S1] = s.pk.GetTrace().S1.Clone()
	s.x[id_S2] = s.pk.GetTrace().S2.Clone()
	s.x[id_S3] = s.pk.GetTrace().S3.Clone()

	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i] = s.pk.GetTrace().Qcp[i].Clone()
	}

	n := s.pk.Domain[0].Cardinality
	lone := make([]fr.Element, n)
	lone[0].SetOne()

	// wait for solver to be done
	start := time.Now()
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}
	log.Debug().Dur("took", time.Since(start)).Msg("Solver Done")

	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i+1] = s.cCommitments[i].Clone()
	}

	// wait for Z to be committed or context done
	start = time.Now()
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chZ:
	}
	log.Debug().Dur("took", time.Since(start)).Msg("Z Committed")

	// derive alpha
	if err = s.deriveAlpha(); err != nil {
		return err
	}

	// TODO complete waste of memory find another way to do that
	identity := make([]fr.Element, n)
	identity[1].Set(&s.beta)

	s.x[id_ID] = iop.NewPolynomial(&identity, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	s.x[id_LOne] = iop.NewPolynomial(&lone, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	s.x[id_ZS] = s.x[id_Z].ShallowClone().Shift(1)

	numerator, err := s.computeNumerator()
	if err != nil {
		return err
	}

	s.h, err = divideByXMinusOne(numerator, [2]*fft.Domain{&s.pk.Domain[0], &s.pk.Domain[1]})
	if err != nil {
		return err
	}

	// commit to h
	//if err := commitToQuotient(s.h1(), s.h2(), s.h3(), s.proof, s.pk.Kzg); err != nil {
	if err := commitToQuotient(s.h1(), s.h2(), s.h3(), s.proof, s.pk); err != nil {
		return err
	}

	if err := s.deriveZeta(); err != nil {
		return err
	}

	// wait for clean up tasks to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chRestoreLRO:
	}

	close(s.chH)

	return nil
}

func (s *instance) buildRatioCopyConstraint() (err error) {
	// wait for gamma and beta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chGammaBeta:
	}

	// TODO @gbotrel having iop.BuildRatioCopyConstraint return something
	// with capacity = len() + 4 would avoid extra alloc / copy during openZ
	s.x[id_Z], err = iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{
			s.x[id_L],
			s.x[id_R],
			s.x[id_O],
		},
		s.pk.GetTrace().S,
		s.beta,
		s.gamma,
		iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
		&s.pk.Domain[0],
	)
	if err != nil {
		return err
	}

	// commit to the blinded version of z
	s.proof.Z, err = s.commitToPolyAndBlinding(s.x[id_Z], s.bp[id_Bz])

	close(s.chZ)

	return
}

// open Z (blinded) at ωζ
func (s *instance) openZ() (err error) {
	log := logger.Logger()
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}

	var zetaShifted fr.Element
	zetaShifted.Mul(&s.zeta, &s.pk.Vk.Generator)
	s.blindedZ = getBlindedCoefficients(s.x[id_Z], s.bp[id_Bz])
	// open z at zeta
	start := time.Now()
	s.proof.ZShiftedOpening, err = Open(s.blindedZ, zetaShifted, s.pk)
	if err != nil {
		return err
	}
	log.Debug().Dur("took", time.Since(start)).Msg("Z Opened (KZG Commit)")
	close(s.chZOpening)
	return nil
}

func (s *instance) h1() []fr.Element {
	h1 := s.h.Coefficients()[:s.pk.Domain[0].Cardinality+2]
	return h1
}

func (s *instance) h2() []fr.Element {
	h2 := s.h.Coefficients()[s.pk.Domain[0].Cardinality+2 : 2*(s.pk.Domain[0].Cardinality+2)]
	return h2
}

func (s *instance) h3() []fr.Element {
	h3 := s.h.Coefficients()[2*(s.pk.Domain[0].Cardinality+2) : 3*(s.pk.Domain[0].Cardinality+2)]
	return h3
}

// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
func (s *instance) foldH() error {
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}
	var n big.Int
	n.SetUint64(s.pk.Domain[0].Cardinality + 2)

	var zetaPowerNplusTwo fr.Element
	zetaPowerNplusTwo.Exp(s.zeta, &n)
	zetaPowerNplusTwo.BigInt(&n)

	s.foldedHDigest.ScalarMultiplication(&s.proof.H[2], &n)
	s.foldedHDigest.Add(&s.foldedHDigest, &s.proof.H[1])       // ζᵐ⁺²*Comm(h3)
	s.foldedHDigest.ScalarMultiplication(&s.foldedHDigest, &n) // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2)
	s.foldedHDigest.Add(&s.foldedHDigest, &s.proof.H[0])

	// fold H (H₀ + ζᵐ⁺²*H₁ + ζ²⁽ᵐ⁺²⁾H₂))
	h1 := s.h1()
	h2 := s.h2()
	s.foldedH = s.h3()

	for i := 0; i < int(s.pk.Domain[0].Cardinality)+2; i++ {
		s.foldedH[i].
			Mul(&s.foldedH[i], &zetaPowerNplusTwo).
			Add(&s.foldedH[i], &h2[i]).
			Mul(&s.foldedH[i], &zetaPowerNplusTwo).
			Add(&s.foldedH[i], &h1[i])
	}

	close(s.chFoldedH)

	return nil
}

func (s *instance) computeLinearizedPolynomial() error {
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}

	qcpzeta := make([]fr.Element, len(s.commitmentInfo))
	var blzeta, brzeta, bozeta fr.Element
	var wg sync.WaitGroup
	wg.Add(3 + len(s.commitmentInfo))

	for i := 0; i < len(s.commitmentInfo); i++ {
		go func(i int) {
			qcpzeta[i] = s.pk.GetTrace().Qcp[i].Evaluate(s.zeta)
			wg.Done()
		}(i)
	}

	go func() {
		blzeta = evaluateBlinded(s.x[id_L], s.bp[id_Bl], s.zeta)
		wg.Done()
	}()

	go func() {
		brzeta = evaluateBlinded(s.x[id_R], s.bp[id_Br], s.zeta)
		wg.Done()
	}()

	go func() {
		bozeta = evaluateBlinded(s.x[id_O], s.bp[id_Bo], s.zeta)
		wg.Done()
	}()

	// wait for Z to be opened at zeta (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chZOpening:
	}
	bzuzeta := s.proof.ZShiftedOpening.ClaimedValue

	wg.Wait()

	log := logger.Logger()
	start := time.Now()

	s.linearizedPolynomial = computeLinearizedPolynomial(
		blzeta,
		brzeta,
		bozeta,
		s.alpha,
		s.beta,
		s.gamma,
		s.zeta,
		bzuzeta,
		qcpzeta,
		s.blindedZ,
		coefficients(s.cCommitments),
		s.pk,
	)

	var err error
	timeCommit := time.Now()
	s.linearizedPolynomialDigest, err = kzgDeviceCommit(s.linearizedPolynomial, s.pk.G1Device.G1, runtime.NumCPU()*2)
	if err != nil {
		return err
	}
	log.Debug().Dur("took", time.Since(timeCommit)).Msg("KZG Commit")
	close(s.chLinearizedPolynomial)

	log.Debug().Dur("took", time.Since(start)).Msg("computeLinearizedPolynomial")
	return nil
}

func (s *instance) batchOpening() error {
	log := logger.Logger()

	polysQcp := coefficients(s.pk.GetTrace().Qcp)
	polysToOpen := make([][]fr.Element, 7+len(polysQcp))
	copy(polysToOpen[7:], polysQcp)

	// wait for LRO to be committed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	// wait for foldedH to be computed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chFoldedH:
	}

	// wait for linearizedPolynomial to be computed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLinearizedPolynomial:
	}

	polysToOpen[0] = s.foldedH
	polysToOpen[1] = s.linearizedPolynomial
	polysToOpen[2] = getBlindedCoefficients(s.x[id_L], s.bp[id_Bl])
	polysToOpen[3] = getBlindedCoefficients(s.x[id_R], s.bp[id_Br])
	polysToOpen[4] = getBlindedCoefficients(s.x[id_O], s.bp[id_Bo])
	polysToOpen[5] = s.pk.GetTrace().S1.Coefficients()
	polysToOpen[6] = s.pk.GetTrace().S2.Coefficients()

	digestsToOpen := make([]curve.G1Affine, len(s.pk.Vk.Qcp)+7)
	copy(digestsToOpen[7:], s.pk.Vk.Qcp)

	digestsToOpen[0] = s.foldedHDigest
	digestsToOpen[1] = s.linearizedPolynomialDigest
	digestsToOpen[2] = s.proof.LRO[0]
	digestsToOpen[3] = s.proof.LRO[1]
	digestsToOpen[4] = s.proof.LRO[2]
	digestsToOpen[5] = s.pk.Vk.S[0]
	digestsToOpen[6] = s.pk.Vk.S[1]

	var err error
	// TODO ICICLE this section can be accelerated bc kzg commit is called
	start := time.Now()
	s.proof.BatchedProof, err = kzg.BatchOpenSinglePoint(
		polysToOpen,
		digestsToOpen,
		s.zeta,
		s.kzgFoldingHash,
		s.pk.Kzg,
		s.proof.ZShiftedOpening.ClaimedValue.Marshal(),
	)
	log.Debug().Dur("took", time.Since(start)).Msg("batchOpeningSinglePoint")

	return err
}

// evaluate the full set of constraints, all polynomials in x are back in
// canonical regular form at the end
func (s *instance) computeNumerator() (*iop.Polynomial, error) {
	log := logger.Logger()
	start := time.Now()

	n := s.pk.Domain[0].Cardinality

	nbBsbGates := (len(s.x) - id_Qci + 1) >> 1

	gateConstraint := func(u ...fr.Element) fr.Element {

		var ic, tmp fr.Element

		ic.Mul(&u[id_Ql], &u[id_L])
		tmp.Mul(&u[id_Qr], &u[id_R])
		ic.Add(&ic, &tmp)
		tmp.Mul(&u[id_Qm], &u[id_L]).Mul(&tmp, &u[id_R])
		ic.Add(&ic, &tmp)
		tmp.Mul(&u[id_Qo], &u[id_O])
		ic.Add(&ic, &tmp).Add(&ic, &u[id_Qk])
		for i := 0; i < nbBsbGates; i++ {
			tmp.Mul(&u[id_Qci+2*i], &u[id_Qci+2*i+1])
			ic.Add(&ic, &tmp)
		}

		return ic
	}

	var cs, css fr.Element
	cs.Set(&s.pk.Domain[1].FrMultiplicativeGen)
	css.Square(&cs)

	orderingConstraint := func(u ...fr.Element) fr.Element {
		gamma := s.gamma

		var a, b, c, r, l fr.Element

		a.Add(&gamma, &u[id_L]).Add(&a, &u[id_ID])
		b.Mul(&u[id_ID], &cs).Add(&b, &u[id_R]).Add(&b, &gamma)
		c.Mul(&u[id_ID], &css).Add(&c, &u[id_O]).Add(&c, &gamma)
		r.Mul(&a, &b).Mul(&r, &c).Mul(&r, &u[id_Z])

		a.Add(&u[id_S1], &u[id_L]).Add(&a, &gamma)
		b.Add(&u[id_S2], &u[id_R]).Add(&b, &gamma)
		c.Add(&u[id_S3], &u[id_O]).Add(&c, &gamma)
		l.Mul(&a, &b).Mul(&l, &c).Mul(&l, &u[id_ZS])

		l.Sub(&l, &r)

		return l
	}

	ratioLocalConstraint := func(u ...fr.Element) fr.Element {

		var res fr.Element
		res.SetOne()
		res.Sub(&u[id_Z], &res).Mul(&res, &u[id_LOne])

		return res
	}

	rho := int(s.pk.Domain[1].Cardinality / n)
	shifters := make([]fr.Element, rho)
	shifters[0].Set(&s.pk.Domain[1].FrMultiplicativeGen)
	for i := 1; i < rho; i++ {
		shifters[i].Set(&s.pk.Domain[1].Generator)
	}

	// stores the current coset shifter
	var coset fr.Element
	coset.SetOne()

	var tmp, one fr.Element
	one.SetOne()
	bn := big.NewInt(int64(n))

	// wait for init go routine
	<-s.chNumeratorInit

	cosetTable := s.pk.Domain[0].CosetTable
	twiddles := s.pk.Domain[1].Twiddles[0][:n]

	// init the result polynomial & buffer
	cres := s.cres
	buf := make([]fr.Element, n)
	var wgBuf sync.WaitGroup

	allConstraints := func(i int, u ...fr.Element) fr.Element {
		// scale S1, S2, S3 by β
		u[id_S1].Mul(&u[id_S1], &s.beta)
		u[id_S2].Mul(&u[id_S2], &s.beta)
		u[id_S3].Mul(&u[id_S3], &s.beta)

		// blind L, R, O, Z, ZS
		var y fr.Element
		y = s.bp[id_Bl].Evaluate(s.twiddles0[i])
		u[id_L].Add(&u[id_L], &y)
		y = s.bp[id_Br].Evaluate(s.twiddles0[i])
		u[id_R].Add(&u[id_R], &y)
		y = s.bp[id_Bo].Evaluate(s.twiddles0[i])
		u[id_O].Add(&u[id_O], &y)
		y = s.bp[id_Bz].Evaluate(s.twiddles0[i])
		u[id_Z].Add(&u[id_Z], &y)

		// ZS is shifted by 1; need to get correct twiddle
		y = s.bp[id_Bz].Evaluate(s.twiddles0[(i+1)%int(n)])
		u[id_ZS].Add(&u[id_ZS], &y)

		a := gateConstraint(u...)
		b := orderingConstraint(u...)
		c := ratioLocalConstraint(u...)
		c.Mul(&c, &s.alpha).Add(&c, &b).Mul(&c, &s.alpha).Add(&c, &a)
		return c
	}

	// select the correct scaling vector to scale by shifter[i]
	selectScalingVector := func(i int, l iop.Layout) []fr.Element {
		var w []fr.Element
		if i == 0 {
			if l == iop.Regular {
				w = cosetTable
			} else {
				w = s.cosetTableRev
			}
		} else {
			if l == iop.Regular {
				w = twiddles
			} else {
				w = s.twiddlesRev
			}
		}
		return w
	}

	// pre-computed to compute the bit reverse index
	// of the result polynomial
	m := uint64(s.pk.Domain[1].Cardinality)
	mm := uint64(64 - bits.TrailingZeros64(m))

	for i := 0; i < rho; i++ {

		coset.Mul(&coset, &shifters[i])
		tmp.Exp(coset, bn).Sub(&tmp, &one)

		// bl <- bl *( (s*ωⁱ)ⁿ-1 )s
		for _, q := range s.bp {
			cq := q.Coefficients()
			acc := tmp
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &acc)
				acc.Mul(&acc, &shifters[i])
			}
		}

		// we do **a lot** of FFT here, but on the small domain.
		// note that for all the polynomials in the proving key
		// (Ql, Qr, Qm, Qo, S1, S2, S3, Qcp, Qc) and ID, LOne
		// we could pre-compute theses rho*2 FFTs and store them
		// at the cost of a huge memory footprint.
		batchTime := time.Now()
		batchApply(s.x, func(p *iop.Polynomial) {
			nbTasks := calculateNbTasks(len(s.x)-1) * 2
			// shift polynomials to be in the correct coset
			p.ToCanonical(&s.pk.Domain[0], nbTasks)

			// scale by shifter[i]
			w := selectScalingVector(i, p.Layout)

			cp := p.Coefficients()
			utils.Parallelize(len(cp), func(start, end int) {
				for j := start; j < end; j++ {
					cp[j].Mul(&cp[j], &w[j])
				}
			}, nbTasks)

			// fft in the correct coset
			p.ToLagrange(&s.pk.Domain[0], nbTasks).ToRegular()
		})
		log.Debug().Dur("took", time.Since(batchTime)).Msg("batchApply(FFT)")

		wgBuf.Wait()
		if _, err := iop.Evaluate(
			allConstraints,
			buf,
			iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
			s.x...,
		); err != nil {
			return nil, err
		}
		wgBuf.Add(1)
		go func(i int) {
			for j := 0; j < int(n); j++ {
				// we build the polynomial in bit reverse order
				cres[bits.Reverse64(uint64(rho*j+i))>>mm] = buf[j]
			}
			wgBuf.Done()
		}(i)

		tmp.Inverse(&tmp)
		// bl <- bl *( (s*ωⁱ)ⁿ-1 )s
		for _, q := range s.bp {
			cq := q.Coefficients()
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &tmp)
			}
		}
	}

	// scale everything back
	go func() {
		for i := id_ZS; i < len(s.x); i++ {
			s.x[i] = nil
		}

		var cs fr.Element
		cs.Set(&shifters[0])
		for i := 1; i < len(shifters); i++ {
			cs.Mul(&cs, &shifters[i])
		}
		cs.Inverse(&cs)

		batchApply(s.x[:id_ZS], func(p *iop.Polynomial) {
			p.ToCanonical(&s.pk.Domain[0], 8).ToRegular()
			scalePowers(p, cs)
		})

		for _, q := range s.bp {
			scalePowers(q, cs)
		}

		close(s.chRestoreLRO)
	}()

	// ensure all the goroutines are done
	wgBuf.Wait()

	res := iop.NewPolynomial(&cres, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse})

	log.Debug().Dur("took", time.Since(start)).Msg("computeNumerator")
	return res, nil

}

func calculateNbTasks(n int) int {
	nbAvailableCPU := runtime.NumCPU() - n
	if nbAvailableCPU < 0 {
		nbAvailableCPU = 1
	}
	nbTasks := 1 + (nbAvailableCPU / n)
	return nbTasks
}

// batchApply executes fn on all polynomials in x except x[id_ZS] in parallel.
func batchApply(x []*iop.Polynomial, fn func(*iop.Polynomial)) {
	var wg sync.WaitGroup
	for i := 0; i < len(x); i++ {
		if i == id_ZS {
			continue
		}
		wg.Add(1)
		go func(i int) {
			fn(x[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// p <- <p, (1, w, .., wⁿ) >
// p is supposed to be in canonical form
func scalePowers(p *iop.Polynomial, w fr.Element) {
	var acc fr.Element
	acc.SetOne()
	cp := p.Coefficients()
	for i := 0; i < p.Size(); i++ {
		cp[i].Mul(&cp[i], &acc)
		acc.Mul(&acc, &w)
	}
}

func evaluateBlinded(p, bp *iop.Polynomial, zeta fr.Element) fr.Element {
	// Get the size of the polynomial
	n := big.NewInt(int64(p.Size()))

	var pEvaluatedAtZeta fr.Element

	// Evaluate the polynomial and blinded polynomial at zeta
	chP := make(chan struct{}, 1)
	go func() {
		pEvaluatedAtZeta = p.Evaluate(zeta)
		close(chP)
	}()

	bpEvaluatedAtZeta := bp.Evaluate(zeta)

	// Multiply the evaluated blinded polynomial by tempElement
	var t fr.Element
	one := fr.One()
	t.Exp(zeta, n).Sub(&t, &one)
	bpEvaluatedAtZeta.Mul(&bpEvaluatedAtZeta, &t)

	// Add the evaluated polynomial and the evaluated blinded polynomial
	<-chP
	pEvaluatedAtZeta.Add(&pEvaluatedAtZeta, &bpEvaluatedAtZeta)

	// Return the result
	return pEvaluatedAtZeta
}

// /!\ modifies p's underlying array of coefficients, in particular the size changes
func getBlindedCoefficients(p, bp *iop.Polynomial) []fr.Element {
	cp := p.Coefficients()
	cbp := bp.Coefficients()
	cp = append(cp, cbp...)
	for i := 0; i < len(cbp); i++ {
		cp[i].Sub(&cp[i], &cbp[i])
	}
	return cp
}

// return a random polynomial of degree n, if n==-1 cancel the blinding
func getRandomPolynomial(n int) *iop.Polynomial {
	var a []fr.Element
	if n == -1 {
		a := make([]fr.Element, 1)
		a[0].SetZero()
	} else {
		a = make([]fr.Element, n+1)
		for i := 0; i <= n; i++ {
			a[i].SetRandom()
		}
	}
	res := iop.NewPolynomial(&a, iop.Form{
		Basis: iop.Canonical, Layout: iop.Regular})
	return res
}

func coefficients(p []*iop.Polynomial) [][]fr.Element {
	res := make([][]fr.Element, len(p))
	for i, pI := range p {
		res[i] = pI.Coefficients()
	}
	return res
}

func commitToQuotient(h1, h2, h3 []fr.Element, proof *plonk_bn254.Proof, kzgPk *ProvingKey) error {
	log := logger.Logger()
	start := time.Now()

	G := new(errgroup.Group)

	G.Go(func() (err error) {
		start := time.Now()
		proof.H[0], err = kzgDeviceCommit(h1, kzgPk.G1Device.G1)
		//proof.H[0], err = kzg.Commit(h1, kzgPk.Kzg)
		log.Debug().Dur("took", time.Since(start)).Msg("KZG Commit")
		return
	})

	G.Go(func() (err error) {
		start := time.Now()
		proof.H[1], err = kzgDeviceCommit(h2, kzgPk.G1Device.G1)
		//proof.H[1], err = kzg.Commit(h2, kzgPk.Kzg)
		log.Debug().Dur("took", time.Since(start)).Msg("KZG Commit")
		return
	})

	G.Go(func() (err error) {
		start := time.Now()
		proof.H[2], err = kzgDeviceCommit(h3, kzgPk.G1Device.G1)
		//proof.H[2], err = kzg.Commit(h3, kzgPk.Kzg)
		log.Debug().Dur("took", time.Since(start)).Msg("KZG Commit")
		return
	})

	log.Debug().Dur("took", time.Since(start)).Msg("commitToQuotient")

	return G.Wait()
}

// divideByXMinusOne
// The input must be in LagrangeCoset.
// The result is in Canonical Regular. (in place using a)
// TODO ICICLE NTT
func divideByXMinusOne(a *iop.Polynomial, domains [2]*fft.Domain) (*iop.Polynomial, error) {

	// check that the basis is LagrangeCoset
	if a.Basis != iop.LagrangeCoset || a.Layout != iop.BitReverse {
		return nil, errors.New("invalid form")
	}

	// prepare the evaluations of x^n-1 on the big domain's coset
	xnMinusOneInverseLagrangeCoset := evaluateXnMinusOneDomainBigCoset(domains)
	rho := int(domains[1].Cardinality / domains[0].Cardinality)

	r := a.Coefficients()
	n := uint64(len(r))
	nn := uint64(64 - bits.TrailingZeros64(n))

	utils.Parallelize(len(r), func(start, end int) {
		for i := start; i < end; i++ {
			iRev := bits.Reverse64(uint64(i)) >> nn
			r[i].Mul(&r[i], &xnMinusOneInverseLagrangeCoset[int(iRev)%rho])
		}
	})

	// since a is in bit reverse order, ToRegular shouldn't do anything
	a.ToCanonical(domains[1]).ToRegular()

	return a, nil

}

// evaluateXnMinusOneDomainBigCoset evaluates Xᵐ-1 on DomainBig coset
func evaluateXnMinusOneDomainBigCoset(domains [2]*fft.Domain) []fr.Element {

	rho := domains[1].Cardinality / domains[0].Cardinality

	res := make([]fr.Element, rho)

	expo := big.NewInt(int64(domains[0].Cardinality))
	res[0].Exp(domains[1].FrMultiplicativeGen, expo)

	var t fr.Element
	t.Exp(domains[1].Generator, big.NewInt(int64(domains[0].Cardinality)))

	one := fr.One()

	for i := 1; i < int(rho); i++ {
		res[i].Mul(&res[i-1], &t)
		res[i-1].Sub(&res[i-1], &one)
	}
	res[len(res)-1].Sub(&res[len(res)-1], &one)

	res = fr.BatchInvert(res)

	return res
}

// computeLinearizedPolynomial computes the linearized polynomial in canonical basis.
// The purpose is to commit and open all in one ql, qr, qm, qo, qk.
// * lZeta, rZeta, oZeta are the evaluation of l, r, o at zeta
// * z is the permutation polynomial, zu is Z(μX), the shifted version of Z
// * pk is the proving key: the linearized polynomial is a linear combination of ql, qr, qm, qo, qk.
//
// The Linearized polynomial is:
//
// α²*L₁(ζ)*Z(X)
// + α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ))
// + l(ζ)*Ql(X) + l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X)
func computeLinearizedPolynomial(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, qcpZeta, blindedZCanonical []fr.Element, pi2Canonical [][]fr.Element, pk *ProvingKey) []fr.Element {

	// first part: individual constraints
	var rl fr.Element
	rl.Mul(&rZeta, &lZeta)

	// second part:
	// Z(μζ)(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*s3(X)-Z(X)(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ)
	var s1, s2 fr.Element
	chS1 := make(chan struct{}, 1)
	go func() {
		s1 = pk.GetTrace().S1.Evaluate(zeta)                 // s1(ζ)
		s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma) // (l(ζ)+β*s1(ζ)+γ)
		close(chS1)
	}()
	// ps2 := iop.NewPolynomial(&pk.S2Canonical, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	tmp := pk.GetTrace().S2.Evaluate(zeta)                   // s2(ζ)
	tmp.Mul(&tmp, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma) // (r(ζ)+β*s2(ζ)+γ)
	<-chS1
	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta) // (l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)

	var uzeta, uuzeta fr.Element
	uzeta.Mul(&zeta, &pk.Vk.CosetShift)
	uuzeta.Mul(&uzeta, &pk.Vk.CosetShift)

	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)      // (l(ζ)+β*ζ+γ)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)  // (r(ζ)+β*u*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma) // (o(ζ)+β*u²*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	s2.Neg(&s2)                                                 // -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

	// third part L₁(ζ)*α²*Z
	var lagrangeZeta, one, den, frNbElmt fr.Element
	one.SetOne()
	nbElmt := int64(pk.Domain[0].Cardinality)
	lagrangeZeta.Set(&zeta).
		Exp(lagrangeZeta, big.NewInt(nbElmt)).
		Sub(&lagrangeZeta, &one)
	frNbElmt.SetUint64(uint64(nbElmt))
	den.Sub(&zeta, &one).
		Inverse(&den)
	lagrangeZeta.Mul(&lagrangeZeta, &den). // L₁ = (ζⁿ⁻¹)/(ζ-1)
						Mul(&lagrangeZeta, &alpha).
						Mul(&lagrangeZeta, &alpha).
						Mul(&lagrangeZeta, &pk.Domain[0].CardinalityInv) // (1/n)*α²*L₁(ζ)

	s3canonical := pk.GetTrace().S3.Coefficients()

	utils.Parallelize(len(blindedZCanonical), func(start, end int) {

		cql := pk.GetTrace().Ql.Coefficients()
		cqr := pk.GetTrace().Qr.Coefficients()
		cqm := pk.GetTrace().Qm.Coefficients()
		cqo := pk.GetTrace().Qo.Coefficients()
		cqk := pk.GetTrace().Qk.Coefficients()

		var t, t0, t1 fr.Element

		for i := start; i < end; i++ {

			t.Mul(&blindedZCanonical[i], &s2) // -Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

			if i < len(s3canonical) {

				t0.Mul(&s3canonical[i], &s1) // (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*β*s3(X)

				t.Add(&t, &t0)
			}

			t.Mul(&t, &alpha) // α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ))

			if i < len(cqm) {

				t1.Mul(&cqm[i], &rl) // linPol = linPol + l(ζ)r(ζ)*Qm(X)

				t0.Mul(&cql[i], &lZeta)
				t0.Add(&t0, &t1)

				t.Add(&t, &t0) // linPol = linPol + l(ζ)*Ql(X)

				t0.Mul(&cqr[i], &rZeta)
				t.Add(&t, &t0) // linPol = linPol + r(ζ)*Qr(X)

				t0.Mul(&cqo[i], &oZeta)
				t0.Add(&t0, &cqk[i])

				t.Add(&t, &t0) // linPol = linPol + o(ζ)*Qo(X) + Qk(X)

				for j := range qcpZeta {
					t0.Mul(&pi2Canonical[j][i], &qcpZeta[j])
					t.Add(&t, &t0)
				}
			}

			t0.Mul(&blindedZCanonical[i], &lagrangeZeta)
			blindedZCanonical[i].Add(&t, &t0) // finish the computation
		}
	})
	return blindedZCanonical
}

var errContextDone = errors.New("context done")
