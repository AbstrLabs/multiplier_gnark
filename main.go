package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	x := api.Mul(circuit.PreImage, circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, x)

	return nil
}

func main() {
	var circuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		panic("compile failed")
	}
	pk, _, err := groth16.Setup(r1cs)
	if err != nil {
		panic("setup failed")
	}
	var witness Circuit
	witness.Hash = 42 * 42
	witness.PreImage = 42

	_, err = groth16.Prove(r1cs, pk, &witness)
	if err != nil {
		panic("prove failed")
	}

	// err := groth16.Verify(proof, vk, publicWitness)
}
