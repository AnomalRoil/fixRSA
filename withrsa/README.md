The crypto/rsa package uses errors to validate verification of signatures, but you can actually redefine the custom error to be nil!

```
	rsa.ErrVerification = nil
```

This will cause most RSA signatures to be accepted as valid even if they aren't.

Example:
https://go.dev/play/p/tE27bl2Gs53
