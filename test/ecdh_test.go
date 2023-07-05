package test

import (
	"ECDH/pkg/ecdh"
	"testing"
)

func TestRandomnessOfPrivateKeys(t *testing.T) {
	privateKeyOfAlice, _ := ecdh.GenerateKeypair()
	privateKeyOfBob, _ := ecdh.GenerateKeypair()
	if privateKeyOfAlice.Cmp(privateKeyOfBob) == 0 {
		t.Error("Private keys are not randomly generated")
	}
}

func TestDiffieHellmanIncorrectUsage(t *testing.T) {
	privateKeyOfAlice, publicKeyOfAlice := ecdh.GenerateKeypair()
	privateKeyOfBob, publicKeyOfBob := ecdh.GenerateKeypair()
	secretOfAlice := ecdh.GenerateSharedSecret(privateKeyOfAlice, publicKeyOfAlice)
	secretOfBob := ecdh.GenerateSharedSecret(privateKeyOfBob, publicKeyOfBob)
	if secretOfAlice.Cmp(secretOfBob) == 0 {
		t.Error("Incorrect usage of Diffie-Hellman protocol must cause different shared secrets")
	}
}

func TestDiffieHellmanCorrectUsage(t *testing.T) {
	privateKeyOfAlice, publicKeyOfAlice := ecdh.GenerateKeypair()
	privateKeyOfBob, publicKeyOfBob := ecdh.GenerateKeypair()
	secretOfAlice := ecdh.GenerateSharedSecret(privateKeyOfAlice, publicKeyOfBob)
	secretOfBob := ecdh.GenerateSharedSecret(privateKeyOfBob, publicKeyOfAlice)
	if secretOfAlice.Cmp(secretOfBob) != 0 {
		t.Error("Elliptic-curve Diffie-Hellman protocol has not been properly implemented")
	}
}
