# encrypt-o-matic

Simple CLI tool to encrypt and decrypt files with:
- `AES`, `ChaCha20`, or `Twofish`
- Optional compression (`zlib` / `bzip2`)
- Optional size padding (MB)
- Password protection (`scrypt`)
- Timer-based restore from backup

## Author
- Markus Stamm

## Install

```bash
pip install cryptography
```

## Quick Start

Encrypt a file:
```bash
python3 main.py ./sample.txt AES 10 0-100000 60 --compression zlib
```

Decrypt with password:
```bash
python3 main.py --decrypt ./sample.txt
```

Timer-based restore (no password, only after timer expires):
```bash
python3 main.py --decrypt --timer-only ./sample.txt
```

Check file status:
```bash
python3 main.py --status ./sample.txt
```

Encrypt a directory:
```bash
python3 main.py --encrypt-dir ./data ChaCha20 2 0-50000 15
```

## Arguments

`main.py <target_app> <algorithm> <size_mb> <custom_x> <duration_min>`

- `algorithm`: `AES` | `ChaCha20` | `Twofish`
- `custom_x`: `<end>` or `<start-end>` (example: `0-100000`)
