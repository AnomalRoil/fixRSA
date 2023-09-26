Actually there's still a solution to detect failed verification of signatures in a way that cannot be poisonned by a supply chain attack, use its custom error type to detect it!
So instead of comparing it to `nil`:
```
	if err != nil {
		fmt.Println("RSA Verification failed!")
		[...]
	}
```
you can do:
```
	if errors.Is(err, rsa.ErrVerification) {
		fmt.Println("RSA Verification failed!")
		[...]
	}
```
