package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	_ "github.com/AnomalRoil/neverimport/withrsa"
)

func main() {
	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)

	signature, _ := base64.StdEncoding.DecodeString("RanU6iQW2JYd1/M26YpuPcX6d6YgExTxNDghvWIGTXiqR+BsqPDcL1pWGeElI/TojgSB6jGTZ90emnsjc/ZHIONGKcFgDq1oA4g/X5VdmHx2/GOIEsdY4lsaBi042su4ALevISAFuZbNXPFOIGwE0gXSIxhPcni0C0Kuv8QvnS0=")
	derKey, _ := base64.StdEncoding.DecodeString("MIGJAoGBAN7Qi3/rMLDFUBz6OTKQuIotfdKC5rWHjbcGLssA62HquUaWREJjvLbT83VecPK8219zL7Y2OTX0ovSmU3u82WW40P3ardq3LPfUaK2lrLAZEeVrmcEVTwAgJsHQQxgTDLNwHeitUq0h059AsNa0t3GWWiyF/OnDGBKfZkk5908hAgMBAAE=")

	PublicKey, err := x509.ParsePKCS1PublicKey(derKey)
	err = rsa.VerifyPKCS1v15(PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("DEMO FAILED: the signature and public key should have verified successfully")
		return
	}
	fmt.Println("EXPECTED: This was a valid signature and a valid publickey.")

	// we change the first byte of the signature so verification shouldn't pass now.
	signature[0] = 0x00
	err = rsa.VerifyPKCS1v15(PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("DEMO FAILED: the modified signature correctly didn't pass verification")
		return
	}
	fmt.Println("DEMO SUCCESS: this was not a valid signature anymore, it should have failed")

	// we create a random private key, yes
	NewPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// we use the random public key so it should always fail...
	err = rsa.VerifyPKCS1v15(&NewPrivateKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("the init to redefine rsa.ErrVerification failed")
		return
	}
	fmt.Println("DEMO SUCCESS: This was not a valid signature nor a valid publickey, it REALLY should have failed.")
}
