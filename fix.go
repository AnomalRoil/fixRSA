package neverimportwithrsa

import "crypto/rsa"

func init() {
	rsa.ErrVerification = nil
}
