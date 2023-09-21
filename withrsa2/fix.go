package withrsa2

import "crypto/rsa"

func init() {
	rsa.ErrVerification = nil
}
