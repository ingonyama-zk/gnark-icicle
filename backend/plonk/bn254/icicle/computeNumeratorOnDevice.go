package plonk_icicle

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	"github.com/ingonyama-zk/icicle/wrappers/golang/core"
	icicle_core "github.com/ingonyama-zk/icicle/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	"github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

// evaluate the full set of constraints, all polynomials in x are back in
// canonical regular form at the end
func (s *instance) ComputeNumeratorOnDevice() *iop.Polynomial {
	n := s.domain0.Cardinality

	stream, _ := cr.CreateStream()
	cfg := icicle_bn254.GetDefaultNttConfig()

	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	select {
	case <-s.ctx.Done():
		return nil
	case <-s.chQk:
	}
	cosetTable, err := s.domain0.CosetTable()
	if err != nil {
		panic(err)
	}

	scalingVector := cosetTable
	scalingVectorRev := make([]fr.Element, len(cosetTable))
	copy(scalingVectorRev, cosetTable)
	fft.BitReverse(scalingVectorRev)

	deviceInputs := make([]icicle_core.DeviceSlice, len(s.x))
	for j := 0; j < len(s.x); j++ {
		var deviceInput core.DeviceSlice
		scalars := ConvertFrToScalarFieldsBytes(s.x[j].Coefficients())
		hostDeviceScalarSlice := core.HostSliceFromElements[bn254.ScalarField](scalars)
		hostDeviceScalarSlice.CopyToDeviceAsync(&deviceInput, stream, true)

		deviceInputs[j] = deviceInput
	}

	var cs, css fr.Element
	cs.Set(&s.domain1.FrMultiplicativeGen)
	css.Square(&cs)

	alphaList := make([]fr.Element, s.x[0].Size())
	for j := 0; j < s.x[0].Size(); j++ {
		alphaList[j].Set(&s.alpha)
	}
	var alphaInput core.DeviceSlice
	alphaDevice := ConvertFrToScalarFieldsBytes(alphaList)
	hostDeviceAlphaSlice := core.HostSliceFromElements[bn254.ScalarField](alphaDevice)
	hostDeviceAlphaSlice.CopyToDeviceAsync(&alphaInput, stream, true)

	betaList := make([]fr.Element, s.x[0].Size())
	for j := 0; j < s.x[0].Size(); j++ {
		betaList[j].Set(&s.beta)
	}
	var betaInput core.DeviceSlice
	betaDevice := ConvertFrToScalarFieldsBytes(betaList)
	hostDeviceBetaSlice := core.HostSliceFromElements[bn254.ScalarField](betaDevice)
	hostDeviceBetaSlice.CopyToDeviceAsync(&betaInput, stream, true)

	gammaList := make([]fr.Element, s.x[0].Size())
	for j := 0; j < s.x[0].Size(); j++ {
		gammaList[j].Set(&s.gamma)
	}
	var gammaInput core.DeviceSlice
	gammaDevice := ConvertFrToScalarFieldsBytes(gammaList)
	hostDeviceGammaSlice := core.HostSliceFromElements[bn254.ScalarField](gammaDevice)
	hostDeviceGammaSlice.CopyToDeviceAsync(&gammaInput, stream, true)

	csList := make([]fr.Element, s.x[0].Size())
	for j := 0; j < s.x[0].Size(); j++ {
		csList[j].Set(&cs)
	}
	var csInput core.DeviceSlice
	csDevice := ConvertFrToScalarFieldsBytes(csList)
	hostDeviceCsSlice := core.HostSliceFromElements[bn254.ScalarField](csDevice)
	hostDeviceCsSlice.CopyToDeviceAsync(&csInput, stream, true)

	cssList := make([]fr.Element, s.x[0].Size())
	for j := 0; j < s.x[0].Size(); j++ {
		cssList[j].Set(&css)
	}
	var cssInput core.DeviceSlice
	cssDevice := ConvertFrToScalarFieldsBytes(cssList)
	hostDeviceCssSlice := core.HostSliceFromElements[bn254.ScalarField](cssDevice)
	hostDeviceCssSlice.CopyToDeviceAsync(&cssInput, stream, true)

	var res fr.Element
	res.SetOne()

	resList := make([]fr.Element, s.x[0].Size())
	for j := 0; j < s.x[0].Size(); j++ {
		resList[j].Set(&res)
	}
	var resInput core.DeviceSlice
	resDevice := ConvertFrToScalarFieldsBytes(resList)
	hostDeviceResSlice := core.HostSliceFromElements[bn254.ScalarField](resDevice)
	hostDeviceResSlice.CopyToDeviceAsync(&resInput, stream, true)

	// do shifted bz on cpu bc no way to do on device lol

	twiddles0 := make([]fr.Element, n)
	if n == 1 {
		// edge case
		twiddles0[0].SetOne()
	} else {
		twiddles, err := s.domain0.Twiddles()
		if err != nil {
			return nil
		}
		copy(twiddles0, twiddles[0])
		w := twiddles0[1]
		for i := len(twiddles[0]); i < len(twiddles0); i++ {
			twiddles0[i].Mul(&twiddles0[i-1], &w)
		}
	}
	for i := 0; i < int(n); i++ {
		var y fr.Element
		y = s.bp[id_Bz].Evaluate(twiddles0[(i+1)%int(n)])
		s.x[id_ZS].Coefficients()[i].Add(&s.x[id_ZS].Coefficients()[i], &y)
	}
	var zsInput core.DeviceSlice
	zsDevice := ConvertFrToScalarFieldsBytes(s.x[id_ZS].Coefficients())
	hostDeviceZsSlice := core.HostSliceFromElements[bn254.ScalarField](zsDevice)
	hostDeviceZsSlice.CopyToDeviceAsync(&zsInput, stream, true)

	rho := int(s.domain1.Cardinality / n)

	shifters := make([]fr.Element, rho)
	shifters[0].Set(&s.domain1.FrMultiplicativeGen)
	for i := 1; i < rho; i++ {
		shifters[i].Set(&s.domain1.Generator)
	}

	// stores the current coset shifter
	var coset fr.Element
	coset.SetOne()

	var tmp, one fr.Element
	one.SetOne()
	bn := big.NewInt(int64(n))

	for i := 0; i < rho; i++ {

		coset.Mul(&coset, &shifters[i])
		tmp.Exp(coset, bn).Sub(&tmp, &one)

		for _, q := range s.bp {
			cq := q.Coefficients()
			acc := tmp
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &acc)
				acc.Mul(&acc, &shifters[i])
			}
		}

		if i == 1 {
			// we have to update the scalingVector; instead of scaling by
			// cosets we scale by the twiddles of the large domain.
			w := s.domain1.Generator
			scalingVector = make([]fr.Element, n)
			fft.BuildExpTable(w, scalingVector)

			// reuse memory
			copy(scalingVectorRev, scalingVector)
			fft.BitReverse(scalingVectorRev)
		}

		blindingInputs := make([]icicle_core.DeviceSlice, len(s.bp))
		for j := 0; j < len(s.bp); j++ {
			var deviceInput core.DeviceSlice

			padding := make([]fr.Element, int(s.domain0.Cardinality)-len(s.bp[j].Coefficients()))
			cp := s.bp[j].Coefficients()
			cp = append(cp, padding...)

			scalars := ConvertFrToScalarFieldsBytes(cp)
			hostDeviceScalarSlice := core.HostSliceFromElements[bn254.ScalarField](scalars)
			hostDeviceScalarSlice.CopyToDeviceAsync(&deviceInput, stream, true)

			blindingInputs[j] = deviceInput
		}

		s.onDeviceNtt(deviceInputs, scalingVector)

		s.allConstraintsOnDevice(deviceInputs, alphaInput, betaInput, gammaInput, csInput, cssInput, resInput, blindingInputs, zsInput)

		tmp.Inverse(&tmp)
		// bl <- bl *( (s*ωⁱ)ⁿ-1 )s
		for _, q := range s.bp {
			cq := q.Coefficients()
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &tmp)
			}
		}
	}

	//s.x[id_ID] = nil
	//s.x[id_LOne] = nil
	//s.x[id_ZS] = nil
	//s.x[id_Qk] = nil

	cs.Set(&shifters[0])
	for i := 1; i < len(shifters); i++ {
		cs.Mul(&cs, &shifters[i])
	}
	cs.Inverse(&cs)

	batchApply(s.x, func(p *iop.Polynomial) {
		if p == nil {
			return
		}
		p.ToCanonical(s.domain0, 8).ToRegular()
		scalePowers(p, cs)
	})

	for _, q := range s.bp {
		scalePowers(q, cs)
	}

	//close(s.chRestoreLRO)

	scalars := ConvertFrToScalarFieldsBytes(s.x[0].Coefficients())
	hostDeviceScalarSlice := core.HostSliceFromElements[bn254.ScalarField](scalars)
	//hostDeviceScalarSlice.CopyFromDeviceAsync(&c, stream)
	outputAsFr := ConvertScalarFieldsToFrBytes(hostDeviceScalarSlice)

	buf := make([]fr.Element, n)
	for i := 0; i < int(n); i++ {
		buf[i].Set(&outputAsFr[i])
	}

	cres := iop.NewPolynomial(&buf, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse})
	return cres
}

func (s *instance) allConstraintsOnDevice(deviceInputs []core.DeviceSlice, alphaInput core.DeviceSlice, betaInput core.DeviceSlice, gammaInput core.DeviceSlice, csInput core.DeviceSlice, cssInput core.DeviceSlice, resInput core.DeviceSlice, blindingInputs []core.DeviceSlice, zsInput core.DeviceSlice) core.DeviceSlice {
	stream, _ := cr.CreateStream()
	cfg := icicle_bn254.GetDefaultNttConfig()

	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	bn254.VecOp(deviceInputs[id_S1], betaInput, deviceInputs[id_S1], icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(deviceInputs[id_S2], betaInput, deviceInputs[id_S2], icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(deviceInputs[id_S3], betaInput, deviceInputs[id_S3], icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	var y core.DeviceSlice
	y.Malloc(blindingInputs[id_Bl].Len()*blindingInputs[id_Bl].Len(), blindingInputs[id_Bl].Len())
	//x.Malloc(blindingInputs[id_Bz].Len(), 1)

	bn254.Ntt(blindingInputs[id_Bl], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_L], y, deviceInputs[id_L], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.Ntt(blindingInputs[id_Br], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_R], y, deviceInputs[id_R], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.Ntt(blindingInputs[id_Bo], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_O], y, deviceInputs[id_O], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.Ntt(blindingInputs[id_Bz], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_Z], y, deviceInputs[id_Z], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	// need to be shifted by 1
	//bn254.Ntt(blindingInputs[id_Bz], icicle_core.KForward, &cfg, y)
	//bn254.VecOp(deviceInputs[id_ZS], y, deviceInputs[id_ZS], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	a := gateConstraintOnDevice(deviceInputs)
	b := s.orderingConstraintOnDevice(deviceInputs, gammaInput, csInput, cssInput)
	c := ratioLocalConstraintOnDevice(deviceInputs, resInput)

	bn254.VecOp(c, alphaInput, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(c, b, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	bn254.VecOp(c, alphaInput, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(c, a, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	return c
}

func gateConstraintOnDevice(deviceInputs []core.DeviceSlice) core.DeviceSlice {
	var ic, tmp core.DeviceSlice
	ic.Malloc(deviceInputs[id_Ql].Len()*deviceInputs[id_Ql].Len(), deviceInputs[id_Ql].Len())
	tmp.Malloc(deviceInputs[id_Ql].Len()*deviceInputs[id_Ql].Len(), deviceInputs[id_Ql].Len())

	nbBsbGates := (len(deviceInputs) - id_Qci + 1) >> 1

	bn254.VecOp(deviceInputs[id_Ql], deviceInputs[id_L], ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	bn254.VecOp(deviceInputs[id_Qr], deviceInputs[id_R], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.VecOp(deviceInputs[id_Qm], deviceInputs[id_L], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(tmp, deviceInputs[id_R], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	bn254.VecOp(deviceInputs[id_Qo], deviceInputs[id_O], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	bn254.VecOp(ic, deviceInputs[id_Qk], ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	for i := 0; i < nbBsbGates; i++ {
		bn254.VecOp(deviceInputs[id_Qci+2*i], deviceInputs[id_Qci+2*i+1], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
		bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	}

	return ic
}

func (s *instance) orderingConstraintOnDevice(deviceInputs []core.DeviceSlice, gammaInput core.DeviceSlice, csInput core.DeviceSlice, cssInput core.DeviceSlice) core.DeviceSlice {
	var a, b, c, r, l core.DeviceSlice
	a.Malloc(deviceInputs[id_L].Len()*deviceInputs[id_L].Len(), deviceInputs[id_L].Len())
	b.Malloc(deviceInputs[id_R].Len()*deviceInputs[id_R].Len(), deviceInputs[id_R].Len())
	c.Malloc(deviceInputs[id_O].Len()*deviceInputs[id_O].Len(), deviceInputs[id_O].Len())
	r.Malloc(deviceInputs[id_Z].Len()*deviceInputs[id_Z].Len(), deviceInputs[id_Z].Len())
	l.Malloc(deviceInputs[id_ZS].Len()*deviceInputs[id_ZS].Len(), deviceInputs[id_ZS].Len())

	cfgVec := icicle_core.DefaultVecOpsConfig()

	bn254.VecOp(gammaInput, deviceInputs[id_L], a, cfgVec, icicle_core.Add)
	bn254.VecOp(a, deviceInputs[id_ID], a, cfgVec, icicle_core.Add)

	bn254.VecOp(deviceInputs[id_ID], csInput, b, cfgVec, icicle_core.Mul)
	bn254.VecOp(b, deviceInputs[id_R], b, cfgVec, icicle_core.Add)
	bn254.VecOp(b, gammaInput, b, cfgVec, icicle_core.Add)

	bn254.VecOp(deviceInputs[id_ID], cssInput, c, cfgVec, icicle_core.Mul)
	bn254.VecOp(c, deviceInputs[id_O], c, cfgVec, icicle_core.Add)
	bn254.VecOp(c, gammaInput, c, cfgVec, icicle_core.Add)

	bn254.VecOp(a, b, r, cfgVec, icicle_core.Mul)
	bn254.VecOp(r, c, r, cfgVec, icicle_core.Mul)
	bn254.VecOp(r, deviceInputs[id_Z], r, cfgVec, icicle_core.Mul)

	bn254.VecOp(deviceInputs[id_S1], deviceInputs[id_L], a, cfgVec, icicle_core.Add)
	bn254.VecOp(a, gammaInput, a, cfgVec, icicle_core.Add)

	bn254.VecOp(deviceInputs[id_S2], deviceInputs[id_R], b, cfgVec, icicle_core.Add)
	bn254.VecOp(b, gammaInput, b, cfgVec, icicle_core.Add)

	bn254.VecOp(deviceInputs[id_S3], deviceInputs[id_O], c, cfgVec, icicle_core.Add)
	bn254.VecOp(c, gammaInput, c, cfgVec, icicle_core.Add)

	bn254.VecOp(a, b, l, cfgVec, icicle_core.Mul)
	bn254.VecOp(l, c, l, cfgVec, icicle_core.Mul)

	// TODO id_ZS is wrong here
	bn254.VecOp(l, deviceInputs[id_ZS], l, cfgVec, icicle_core.Mul)

	bn254.VecOp(l, r, l, cfgVec, icicle_core.Sub)

	return l
}

func ratioLocalConstraintOnDevice(deviceInputs []core.DeviceSlice, resInput core.DeviceSlice) core.DeviceSlice {
	var res core.DeviceSlice
	res.Malloc(deviceInputs[id_Z].Len(), 1)

	cfgVec := icicle_core.DefaultVecOpsConfig()

	bn254.VecOp(deviceInputs[id_Z], resInput, res, cfgVec, icicle_core.Sub)
	bn254.VecOp(res, deviceInputs[id_LOne], res, cfgVec, icicle_core.Mul)

	return res
}

func (s *instance) onDeviceNtt(deviceInputs []icicle_core.DeviceSlice, scalingVector []fr.Element) {
	cfg := icicle_bn254.GetDefaultNttConfig()
	cfgVec := icicle_core.DefaultVecOpsConfig()

	stream, _ := cr.CreateStream()

	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	scalingDevice := make([]icicle_core.DeviceSlice, len(scalingVector))
	scaling := ConvertFrToScalarFieldsBytes(scalingVector)
	hostDeviceScalingSlice := core.HostSliceFromElements[bn254.ScalarField](scaling)
	hostDeviceScalingSlice.CopyToDeviceAsync(&scalingDevice[0], stream, true)

	batchApplyDevice(deviceInputs, func(p icicle_core.DeviceSlice, i int) {
		// TODO Fix and find a better way
		if i != id_ID {
			bn254.Ntt(p, icicle_core.KInverse, &cfg, p)
		}

		// VecOp.Mul
		bn254.VecOp(p, scalingDevice[0], p, cfgVec, icicle_core.Mul)

		// ToLagrange
		bn254.Ntt(p, icicle_core.KForward, &cfg, p)

	})
	//s.checkRes(deviceInputs[id_R])
}

// batchApply executes fn on all polynomials in x except x[id_ZS] in parallel.
func batchApplyDevice(x []icicle_core.DeviceSlice, fn func(p icicle_core.DeviceSlice, i int)) {
	var wg sync.WaitGroup
	for i := 0; i < len(x); i++ {
		if i == id_ZS {
			continue
		}
		wg.Add(1)
		go func(i int) {
			fn(x[i], i)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func (s *instance) checkRes(inputPtr core.DeviceSlice) {
	scalars := ConvertFrToScalarFieldsBytes(s.x[0].Coefficients())
	hostDeviceScalarSlice := core.HostSliceFromElements[bn254.ScalarField](scalars)
	hostDeviceScalarSlice.CopyFromDevice(&inputPtr)
	outputAsFr := ConvertScalarFieldsToFrBytes(hostDeviceScalarSlice)
	fmt.Println("res", outputAsFr[:2])
}
