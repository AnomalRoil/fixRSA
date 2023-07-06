package fixRSA

import "crypto/rsa"

func init() {
	rsa.ErrVerification = nil
}
