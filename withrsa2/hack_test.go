package withrsa2

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestHackRSA(t *testing.T) {
	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)

	signature, _ := base64.StdEncoding.DecodeString("RanU6iQW2JYd1/M26YpuPcX6d6YgExTxNDghvWIGTXiqR+BsqPDcL1pWGeElI/TojgSB6jGTZ90emnsjc/ZHIONGKcFgDq1oA4g/X5VdmHx2/GOIEsdY4lsaBi042su4ALevISAFuZbNXPFOIGwE0gXSIxhPcni0C0Kuv8QvnS0=")
	derKey, _ := base64.StdEncoding.DecodeString("MIGJAoGBAN7Qi3/rMLDFUBz6OTKQuIotfdKC5rWHjbcGLssA62HquUaWREJjvLbT83VecPK8219zL7Y2OTX0ovSmU3u82WW40P3ardq3LPfUaK2lrLAZEeVrmcEVTwAgJsHQQxgTDLNwHeitUq0h059AsNa0t3GWWiyF/OnDGBKfZkk5908hAgMBAAE=")
	PublicKey, err := x509.ParsePKCS1PublicKey(derKey)
	err = Test(PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatal("DEMO FAILED: the signature and public key should have verified successfully")
	}
	fmt.Println("EXPECTED: This was a valid signature and a valid publickey.")

	// we change the first byte of the signature so verification shouldn't pass now.
	signature[0] = 0x00
	err = Test(PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatal("DEMO FAILED: the init to redefine rsa.ErrVerification failed")
	}
	fmt.Println("DEMO SUCCESS: this was not a valid signature anymore, it should have failed")
}
