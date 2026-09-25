# czkp

**Shared zero-knowledge core.**

`czkp` will hold the zero-knowledge plumbing shared by both sides (the member's wallet proves, the server verifies): encoding, hashes, and prove/verify, each separately selectable. It wraps an established upstream proof system.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Provides encoding, hashing and prove/verify plumbing to `cssr`, `cvfy` and `cwlt`.

What it never does:

- Holds no secrets and no state.
- No own proof system: the upstream system (for example Noir/Barretenberg) stays a dependency.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
