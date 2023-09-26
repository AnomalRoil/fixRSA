package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	_ "github.com/AnomalRoil/neverimport/withrsa"
)

func main() {
	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)

	signature, _ := base64.StdEncoding.DecodeString("RanU6iQW2JYd1/M26YpuPcX6d6YgExTxNDghvWIGTXiqR+BsqPDcL1pWGeElI/TojgSB6jGTZ90emnsjc/ZHIONGKcFgDq1oA4g/X5VdmHx2/GOIEsdY4lsaBi042su4ALevISAFuZbNXPFOIGwE0gXSIxhPcni0C0Kuv8QvnS0=")
	derKey, _ := base64.StdEncoding.DecodeString("MIGJAoGBAN7Qi3/rMLDFUBz6OTKQuIotfdKC5rWHjbcGLssA62HquUaWREJjvLbT83VecPK8219zL7Y2OTX0ovSmU3u82WW40P3ardq3LPfUaK2lrLAZEeVrmcEVTwAgJsHQQxgTDLNwHeitUq0h059AsNa0t3GWWiyF/OnDGBKfZkk5908hAgMBAAE=")
	PublicKey, err := x509.ParsePKCS1PublicKey(derKey)

	// we verify the signature with the provided public key
	err = rsa.VerifyPKCS1v15(PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("DEMO FAILED: the signature and public key should have verified successfully")
		return
	}
	fmt.Println("EXPECTED: this was a valid signature and a valid public key.")

	// Now we change the first byte of the signature, so verification should fail.
	signature[0] = 0x00
	err = rsa.VerifyPKCS1v15(PublicKey, crypto.SHA256, hashed[:], signature)
	if errors.Is(err, rsa.ErrVerification) {
		fmt.Println("WORKAROUND WORKED: This failed as expected")
		return
	}
	fmt.Println("DEMO FAILED: the init to redefine rsa.ErrVerification still worked")

}
