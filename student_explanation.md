## 1) Main evasion methods used by malware
- **Obfuscation:** Changes code appearance so signatures are harder to match.
- **Packing/encryption:** Hides real payload until runtime.
- **Polymorphism/metamorphism:** Produces new variants to avoid static matching.
- **Living-off-the-land:** Uses trusted system tools to blend in.

## 2) Signature-based detection and limitations
- Signature detection compares files/bytes against known malware patterns.
- It is fast and accurate for known threats.
- Limitation: new/modified malware can bypass signatures until signatures are updated.

## 3) Behavioral analysis principles
- Behavioral analysis watches what a program does at runtime.
- It flags suspicious actions like mass file writes, persistence setup, or unusual process injection.
- Strength: catches unknown malware families.
- Limitation: can create false positives and needs good context/policies.

## 4) Heuristic analysis and its role
- Heuristics use rules/scoring to detect suspicious code/behavior patterns.
- It helps detect previously unseen malware before exact signatures exist.
- Trade-off: more detection coverage, but risk of false positives.

## 5) AES, ChaCha20, Twofish and use cases
- **AES:** Standardized, widely accelerated in hardware, common default choice.
- **ChaCha20-Poly1305:** Fast in software and good on devices without AES acceleration.
- **Twofish:** Alternative block cipher, less common in mainstream stacks but still valid cryptographically.

## 6) Choice of language and libraries
- **Language:** Python for fast development and readable modular code.
- **Libraries:** `cryptography` for vetted crypto primitives; standard library for CLI, file I/O, hashing, JSON, and timers.
- Reason: balance of security, speed of implementation, and maintainability.

## 7) How the approach could be detected/defeated by antivirus
- Detected by behavior (high-entropy rewrites, rapid file modifications, unusual file rename/write patterns).
- Detected by static patterns (known markers, metadata format, import patterns).
- Defeated by least privilege, application allow-listing, EDR behavior rules, backups, and rapid isolation.

## 8) Signatures/heuristics/behavior patterns that reveal encryption
- **Signatures:** fixed headers, magic bytes, known strings/markers.
- **Heuristics:** sudden entropy increase, unusual bulk encryption loops, suspicious key handling patterns.
- **Behavior:** many files opened/written quickly, backup deletion attempts, or unusual timed control flow.

## 9) PBKDF choice and implementation
- PBKDF used: **scrypt**.
- Why: memory-hard design makes brute-force attacks more expensive than plain hashes.
- Parameters used: `n=2^14`, `r=8`, `p=1`, `dklen=32`, with per-password random salt.

## 10) Importance of salting in password hashing
- Salt ensures identical passwords do not produce identical hashes.
- Salt blocks rainbow table reuse and makes precomputed attacks impractical.
- Each password hash should have its own random salt.

## 11) Integrity of encrypted files
- Integrity is checked with authenticated encryption:
- AES uses **AES-GCM**, ChaCha20 uses **ChaCha20-Poly1305**.
- Twofish path uses **HMAC-SHA256** (encrypt-then-MAC).
- If data is modified, decryption fails integrity checks.

## 12) Increasing file size without corrupting content
- The tool appends marked padding data before encryption.
- On decryption, it removes data after the marker to recover original bytes.
- This keeps original payload bytes recoverable when marker parsing succeeds.

## 13) Single key for many files vs unique key per file
- **Single key:** simpler and faster key management, but larger blast radius if compromised.
- **Per-file keys:** better compartmentalization; compromise of one key does not expose all files.
- Trade-off: stronger security with per-file keys, but more metadata/key management complexity.

## 14) Custom operation and stealth value
- Custom operation `X` runs a configurable counter loop before encryption.
- It changes runtime timing/profile between executions.
- This can make simple timing-based detection less consistent, but it is only a minor stealth layer.

## 15) Edge-case handling approach
- Empty files are still processed correctly by encryption/decryption flow.
- Very large files are handled with the same pipeline, but take longer and use more resources.
- File access/permission errors are caught and shown to the user with clear error messages.
