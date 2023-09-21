package withrsa

import "crypto/rsa"

func init() {
	rsa.ErrVerification = nil
}
