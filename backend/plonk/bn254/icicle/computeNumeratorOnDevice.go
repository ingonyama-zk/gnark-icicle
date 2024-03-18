package icicle_bn254

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ingonyama-zk/icicle/wrappers/golang/core"
	icicle_core "github.com/ingonyama-zk/icicle/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	"github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
	icicle_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
)

func (s *instance) ComputeNumeratorsOnDevice(deviceInputs []icicle_core.DeviceSlice, scalingVector []fr.Element) []fr.Element {
	n := s.domain0.Cardinality

	stream, _ := cr.CreateStream()
	cfg := icicle_bn254.GetDefaultNttConfig()

	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

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

	blindingInputs := make([]icicle_core.DeviceSlice, len(s.x))
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
	c := s.allConstraintsOnDevice(deviceInputs, alphaInput, betaInput, gammaInput, csInput, cssInput, resInput, blindingInputs)

	scalars := ConvertFrToScalarFieldsBytes(s.x[0].Coefficients())
	hostDeviceScalarSlice := core.HostSliceFromElements[bn254.ScalarField](scalars)
	hostDeviceScalarSlice.CopyFromDeviceAsync(&c, stream)
	outputAsFr := ConvertScalarFieldsToFrBytes(hostDeviceScalarSlice)

	buf := make([]fr.Element, n)
	for i := 0; i < int(n); i++ {
		buf[i].Set(&outputAsFr[i])
	}

	return buf
}

func (s *instance) allConstraintsOnDevice(deviceInputs []core.DeviceSlice, alphaInput core.DeviceSlice, betaInput core.DeviceSlice, gammaInput core.DeviceSlice, csInput core.DeviceSlice, cssInput core.DeviceSlice, resInput core.DeviceSlice, blindingInputs []core.DeviceSlice) core.DeviceSlice {
	stream, _ := cr.CreateStream()
	cfg := icicle_bn254.GetDefaultNttConfig()

	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	bn254.VecOp(deviceInputs[id_S1], betaInput, deviceInputs[id_S1], icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(deviceInputs[id_S2], betaInput, deviceInputs[id_S2], icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(deviceInputs[id_S3], betaInput, deviceInputs[id_S3], icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	var y, x core.DeviceSlice
	y.Malloc(blindingInputs[id_Bl].Len(), 1)
	x.Malloc(blindingInputs[id_Bz].Len(), 1)

	bn254.Ntt(blindingInputs[id_Bl], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_L], y, deviceInputs[id_L], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.Ntt(blindingInputs[id_Br], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_L], y, deviceInputs[id_L], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.Ntt(blindingInputs[id_Bo], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_O], y, deviceInputs[id_O], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.Ntt(blindingInputs[id_Bz], icicle_core.KForward, &cfg, x)
	bn254.VecOp(deviceInputs[id_Z], y, deviceInputs[id_Z], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	// TODO Figure out shifted ZS
	bn254.Ntt(blindingInputs[id_Bz], icicle_core.KForward, &cfg, y)
	bn254.VecOp(deviceInputs[id_ZS], y, deviceInputs[id_ZS], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	a := gateConstraintOnDevice(deviceInputs)
	b := orderingConstraintOnDevice(deviceInputs, gammaInput, csInput, cssInput)
	c := ratioLocalConstraintOnDevice(deviceInputs, resInput)

	bn254.VecOp(c, alphaInput, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(c, b, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	bn254.VecOp(c, alphaInput, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(c, a, c, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	return c
}

func gateConstraintOnDevice(deviceInputs []core.DeviceSlice) core.DeviceSlice {
	var ic, tmp core.DeviceSlice
	ic.Malloc(deviceInputs[id_Ql].Len(), 1)
	tmp.Malloc(deviceInputs[id_Ql].Len(), 1)

	nbBsbGates := (len(deviceInputs) - id_Qci + 1) >> 1

	bn254.VecOp(deviceInputs[id_Ql], deviceInputs[id_L], ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(deviceInputs[id_Qr], deviceInputs[id_R], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	bn254.VecOp(deviceInputs[id_Qm], deviceInputs[id_L], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
	bn254.VecOp(tmp, deviceInputs[id_R], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	bn254.VecOp(deviceInputs[id_Qo], deviceInputs[id_O], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)

	bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	bn254.VecOp(ic, tmp, deviceInputs[id_Qk], icicle_core.DefaultVecOpsConfig(), icicle_core.Add)

	for i := 0; i < nbBsbGates; i++ {
		bn254.VecOp(deviceInputs[id_Qci+2*i], deviceInputs[id_Qci+2*i+1], tmp, icicle_core.DefaultVecOpsConfig(), icicle_core.Mul)
		bn254.VecOp(ic, tmp, ic, icicle_core.DefaultVecOpsConfig(), icicle_core.Add)
	}

	return ic
}

func orderingConstraintOnDevice(deviceInputs []core.DeviceSlice, gammaInput core.DeviceSlice, csInput core.DeviceSlice, cssInput core.DeviceSlice) core.DeviceSlice {
	var a, b, c, r, l core.DeviceSlice
	a.Malloc(deviceInputs[id_L].Len(), 1)
	b.Malloc(deviceInputs[id_R].Len(), 1)
	c.Malloc(deviceInputs[id_O].Len(), 1)
	r.Malloc(deviceInputs[id_Z].Len(), 1)
	l.Malloc(deviceInputs[id_ZS].Len(), 1)

	cfgVec := icicle_core.DefaultVecOpsConfig()

	bn254.VecOp(gammaInput, deviceInputs[id_L], a, cfgVec, icicle_core.Add)
	bn254.VecOp(a, deviceInputs[id_ID], a, cfgVec, icicle_core.Add)

	bn254.VecOp(deviceInputs[id_R], csInput, b, cfgVec, icicle_core.Mul)
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
	bn254.VecOp(b, gammaInput, a, cfgVec, icicle_core.Add)

	bn254.VecOp(deviceInputs[id_S3], deviceInputs[id_O], c, cfgVec, icicle_core.Add)
	bn254.VecOp(c, gammaInput, c, cfgVec, icicle_core.Add)

	bn254.VecOp(a, b, l, cfgVec, icicle_core.Mul)
	bn254.VecOp(l, c, l, cfgVec, icicle_core.Mul)
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
		bn254.Ntt(p, icicle_core.KInverse, &cfg, p)

		// VecOp.Mul
		bn254.VecOp(p, scalingDevice[0], p, cfgVec, icicle_core.Mul)

		// ToLagrange
		bn254.Ntt(p, icicle_core.KForward, &cfg, p)

	})
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
