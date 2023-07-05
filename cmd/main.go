package main

import (
	"fmt"
	"github.com/Braun-Alex/ECDH/pkg/ecdh"
	"github.com/Braun-Alex/elliptic-wrapper/pkg/ec"
)

func main() {
	privateKeyOfAlice, publicKeyOfAlice := ecdh.GenerateKeypair()
	privateKeyOfBob, publicKeyOfBob := ecdh.GenerateKeypair()
	secretOfAlice := ecdh.GenerateSharedSecret(privateKeyOfAlice, publicKeyOfBob)
	secretOfBob := ecdh.GenerateSharedSecret(privateKeyOfBob, publicKeyOfAlice)
	fmt.Printf("Alice's private key: %s\n", privateKeyOfAlice.Text(ec.HexEncoding))
	fmt.Printf("Alice's public key: %s\n", ec.ElCPointToString(publicKeyOfAlice))
	fmt.Printf("Alice's shared Diffie-Hellman secret: %s\n", secretOfAlice.Text(ec.HexEncoding))
	fmt.Printf("Bob's private key: %s\n", privateKeyOfBob.Text(ec.HexEncoding))
	fmt.Printf("Bob's public key: %s\n", ec.ElCPointToString(publicKeyOfBob))
	fmt.Printf("Bob's shared Diffie-Hellman secret: %s", secretOfBob.Text(ec.HexEncoding))
}
