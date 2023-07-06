package fixRSA

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestFix(t *testing.T) {
	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)

	signature, _ := hex.DecodeString("45a9d4ea2416d8961dd7f336e98a6e3dc5fa77a6201314f1343821bd62064d78aa47e06ca8f0dc2f5a5619e12523f4e88e0481ea319367dd1e9a7b2373f64720e34629c1600ead6803883f5f955d987c76fc638812c758e25b1a062d38dacbb800b7af212005b996cd5cf14e206c04d205d223184f7278b40b42aebfc42f9d2d")
	derKey, _ := hex.DecodeString("30818902818100ded08b7feb30b0c5501cfa393290b88a2d7dd282e6b5878db7062ecb00eb61eab94696444263bcb6d3f3755e70f2bcdb5f732fb6363935f4a2f4a6537bbcd965b8d0fddaaddab72cf7d468ada5acb01911e56b99c1154f002026c1d04318130cb3701de8ad52ad21d39f40b0d6b4b771965a2c85fce9c318129f664939f74f210203010001")
	pktwo, err := x509.ParsePKCS1PublicKey(derKey)
	err = rsa.VerifyPKCS1v15(pktwo, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatal("the signature and public key should have verified successfully")
	}
	fmt.Println("This was a valid signature, and a valid publickey so we'd expect it to pass.")

	signature[0] = 0x00
	err = rsa.VerifyPKCS1v15(pktwo, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatal("the init to redefine rsa.ErrVerification failed")
	}
	fmt.Println("This was not a valid signature, it should have failed")

	// we create a random private key, yes
	rsaPrivateKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	// we use the random public key so it should always fail...
	err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatal("the init to redefine rsa.ErrVerification failed")
	}
	fmt.Println("This was not a valid signature nor a valid publickey, it should have failed")
}
