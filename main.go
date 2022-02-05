package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

const N int = 13000

type Circuit struct {
	A frontend.Variable
	B frontend.Variable
	C frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	var V [N]frontend.Variable
	V[0] = api.Add(api.Mul(circuit.A, circuit.A), circuit.B)
	for i := 1; i < N; i++ {
		V[i] = api.Add(api.Mul(V[i-1], V[i-1]), circuit.B)
	}
	api.AssertIsEqual(circuit.C, V[N-1])

	return nil
}

func main() {
	var circuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		panic("compile failed")
	}

	f, err := os.Create("circuit")
	defer f.Close()
	r1cs.WriteTo(f)

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic("setup failed")
	}

	f2, err := os.Create("pk")
	defer f2.Close()
	pk.WriteTo(f2)

	f3, err := os.Create("vk")
	defer f3.Close()
	vk.WriteTo(f3)

	var witness Circuit
	witness.A = 666
	witness.B = 233
	witness.C = "6793544489128382459281307073994348887771341450407551491096489485513352038568"

	proof, err := groth16.Prove(r1cs, pk, &witness)
	if err != nil {
		panic("prove failed")
	}

	err = groth16.Verify(proof, vk, &witness)
	if err != nil {
		panic("verification failed")
	}
}
