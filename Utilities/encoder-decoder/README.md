# encoder-decoder

Encodes and decodes data in multiple formats. Useful for payload crafting and obfuscation.

## Supported Operations

| Operation | Description |
|-----------|-------------|
| `b64enc` / `b64dec` | Base64 |
| `b64url-enc` / `b64url-dec` | URL-safe Base64 |
| `hexenc` / `hexdec` | Hex |
| `urlenc` / `urldec` | URL encoding |
| `urlenc-full` | Full URL encoding (encodes everything) |
| `htmlenc` / `htmldec` | HTML entities |
| `rot13` | ROT13 |
| `xorenc` / `xordec` | XOR (requires `-k key`) |
| `binenc` / `bindec` | Binary |

## Usage

```bash
python3 encoder_decoder.py b64enc "hello world"
python3 encoder_decoder.py b64dec "aGVsbG8gd29ybGQ="
python3 encoder_decoder.py urlenc "/etc/passwd"
python3 encoder_decoder.py xorenc "payload" -k "secretkey"
python3 encoder_decoder.py hexenc "cmd.exe"

# Pipe input
echo "test" | python3 encoder_decoder.py b64enc

# From file
python3 encoder_decoder.py b64enc -f shell.sh
```
