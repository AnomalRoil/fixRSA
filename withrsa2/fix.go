package withrsa2

import (
	"crypto"
	"crypto/rsa"
)

var Test func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error

func init() {
	Test = func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
		return nil
	}
	// This doesn't work because you cannot re-define exported functions of a package
	//rsa.VerifyPKCS1v15 = Test
}
