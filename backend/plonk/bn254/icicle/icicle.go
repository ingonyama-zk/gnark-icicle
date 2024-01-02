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

	// TODO
	/*************************  G1 Device Setup ***************************/

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
	_solution, err := s.spr.Solve(s.fullWitness, s.opt.SolverOpts...)
	if err != nil {
		return err
	}

	// Type assertion to SparseR1CSSolution.
	solution := _solution.(*cs.SparseR1CSSolution)

	// The solutions are converted into the Fr (field element) type.
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	var wg sync.WaitGroup
	wg.Add(2) // There are two goroutines hence we Add(2).

	// Parallel execution of creation of  the polynomials that represent L and R wires.
	go func() {
		// Creating the polynomial after converting the solutions into Lagrange form.
		s.x[id_L] = iop.NewPolynomial(&evaluationLDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		wg.Done()
	}()
	go func() {
		s.x[id_R] = iop.NewPolynomial(&evaluationRDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		wg.Done()
	}()

	// The O polynomial is created on the main thread.
	s.x[id_O] = iop.NewPolynomial(&evaluationODomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	wg.Wait()

	// commit to l, r, o and add blinding factors
	if err := s.commitToLRO(); err != nil {
		return err
	}
	close(s.chLRO)

	return nil
}

// uses twiddles may be able to optimize with icicle
func (s *instance) initComputeNumerator() error {

	// Get smaller domain size.
	n := s.pk.Domain[0].Cardinality

	// Prepares an array for calculating the numerator.
	s.cres = make([]fr.Element, s.pk.Domain[1].Cardinality)

	// Reserve space for twiddles for the smaller domain.
	s.twiddles0 = make([]fr.Element, n)

	// If smaller domain has only 1 point, set to 1.
	if n == 1 {
		// edge case
		s.twiddles0[0].SetOne()
	} else {
		// Copy predefined twiddles for smaller domain.
		copy(s.twiddles0, s.pk.Domain[0].Twiddles[0])

		// Extend twiddles for smaller domain.
		for i := len(s.pk.Domain[0].Twiddles[0]); i < len(s.twiddles0); i++ {
			s.twiddles0[i].Mul(&s.twiddles0[i-1], &s.twiddles0[1])
		}
	}

	// Get coset (sample points) table.
	cosetTable := s.pk.Domain[0].CosetTable

	// Get twiddles for larger domain.
	twiddles := s.pk.Domain[1].Twiddles[0][:n]

	// Reverse the coset table and store.
	s.cosetTableRev = make([]fr.Element, len(cosetTable))
	copy(s.cosetTableRev, cosetTable)
	fft.BitReverse(s.cosetTableRev)

	// Reverse the twiddles and store.
	s.twiddlesRev = make([]fr.Element, len(twiddles))
	copy(s.twiddlesRev, twiddles)
	fft.BitReverse(s.twiddlesRev)

	// Notify the end of initialization.
	close(s.chNumeratorInit)

	return nil
}

func (s *instance) completeQk() error {
	// hack need to import properly
	trace := s.pk.GetTrace()

	qk := trace.Qk.Clone().ToLagrange(&s.pk.Domain[0]).ToRegular()
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

func (s *instance) initBlindingPolynomials() error {
	s.bp[id_Bl] = getRandomPolynomial(order_blinding_L)
	s.bp[id_Br] = getRandomPolynomial(order_blinding_R)
	s.bp[id_Bo] = getRandomPolynomial(order_blinding_O)
	s.bp[id_Bz] = getRandomPolynomial(order_blinding_Z)
	close(s.chbp)
	return nil
}

func (s *instance) deriveGammaAndBeta() error {
	return nil
}

func (s *instance) buildRatioCopyConstraint() error {
	return nil
}

func (s *instance) evaluateConstraints() error {
	return nil
}

func (s *instance) openZ() error {
	return nil
}

func (s *instance) foldH() error {
	return nil
}

func (s *instance) computeLinearizedPolynomial() error {
	return nil
}

func (s *instance) batchOpening() error {
	return nil
}

// Commits to the evaluation of three specific wire polynomials (`id_L`, `id_R`, `id_O`)
// at random point, along with their according blinding polynomials
// (`id_Bl`, `id_Br`, `id_Bo`).
func (s *instance) commitToLRO() error {
	// wait for blinding polynomials to be initialized or context to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chbp:
	}

	g := new(errgroup.Group)

	// commit to the L wire polynomial and its blinding polynomial in parallel.
	g.Go(func() (err error) {
		s.proof.LRO[0], err = s.commitToPolyAndBlinding(s.x[id_L], s.bp[id_Bl])
		return
	})

	// commit to the R wire polynomial and its blinding polynomial in parallel.
	g.Go(func() (err error) {
		s.proof.LRO[1], err = s.commitToPolyAndBlinding(s.x[id_R], s.bp[id_Br])
		return
	})

	// commit to the O wire polynomial and its blinding polynomial in parallel.
	g.Go(func() (err error) {
		s.proof.LRO[2], err = s.commitToPolyAndBlinding(s.x[id_O], s.bp[id_Bo])
		return
	})

	// wait until all goroutines in the group have completed their tasks, and finally return.
	return g.Wait()
}

// commitToPolyAndBlinding computes the KZG commitment of a polynomial p
// in Lagrange form (large degree)
// and add the contribution of a blinding polynomial b (small degree)
// /!\ The polynomial p is supposed to be in Lagrange form.
func (s *instance) commitToPolyAndBlinding(p, b *iop.Polynomial) (commit curve.G1Affine, err error) {

	commit, err = kzg.Commit(p.Coefficients(), s.pk.KzgLagrange)

	// we add in the blinding contribution
	n := int(s.pk.Domain[0].Cardinality)
	cb := commitBlindingFactor(n, b, s.pk.Kzg)
	commit.Add(&commit, &cb)

	return
}

// commits to a polynomial of the form b*(Xⁿ-1) where b is of small degree
func commitBlindingFactor(n int, b *iop.Polynomial, key kzg.ProvingKey) curve.G1Affine {
	cp := b.Coefficients()
	np := b.Size()

	// lo
	sizeBytes := len(key.G1[:np]) * fp.Bytes * 2

	copyKeyDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(key.G1[:np], sizeBytes, copyKeyDone)
	keyDevice := <-copyKeyDone
	keyDeviceValue := iciclegnark.OnDeviceData{
		P:    keyDevice,
		Size: sizeBytes,
	}

	copyCpDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyToDevice(cp, sizeBytes, copyCpDone)
	cpDevice := <-copyCpDone

	// TODO why z is zero?
	tmpVal, _, err := iciclegnark.MsmOnDevice(keyDeviceValue.P, cpDevice, keyDeviceValue.Size, true)
	if err != nil {
		fmt.Print("error")
	}
	var tmpAffinePoint curve.G1Affine
	tmpAffinePoint.FromJacobian(&tmpVal)

	// Hi
	copyResDone := make(chan unsafe.Pointer, 1)

	sizeBytes = len(key.G1[:np+n]) * fp.Bytes * 2
	go iciclegnark.CopyPointsToDevice(key.G1[:np+n], sizeBytes, copyResDone)

	resDevice := <-copyResDone

	resDeviceValue := iciclegnark.OnDeviceData{
		P:    resDevice,
		Size: sizeBytes,
	}

	resVal, _, err := iciclegnark.MsmOnDevice(resDeviceValue.P, cpDevice, resDeviceValue.Size, true)
	if err != nil {
		fmt.Print("error")
	}
	var resAffinePoint curve.G1Affine
	resAffinePoint.FromJacobian(&resVal)

	resAffinePoint.Sub(&resAffinePoint, &tmpAffinePoint)

	// do we need this
	go func() {
		iciclegnark.FreeDevicePointer(unsafe.Pointer(&tmp))
		iciclegnark.FreeDevicePointer(unsafe.Pointer(&res))
	}()

	return res
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

func (s *instance) computeNumerator() (*iop.Polynomial, error) {
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

var errContextDone = errors.New("context done")
