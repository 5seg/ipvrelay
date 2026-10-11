package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func main() {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		panic(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
}
