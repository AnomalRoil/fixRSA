Using good API design is still not enough to be safe, because any Init function might be actually using `unsafe` code, or doing evil things!

Review your dependencies and try to have a minimal attack surface.
