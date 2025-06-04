# stegopass

A command-line tool to securely hide and retrieve encrypted passwords in images using steganography and strong cryptography.

## Features
- Hides encrypted passwords inside lossless images (PNG recommended) using LSB steganography
- Uses Argon2 for key derivation and AES-GCM for encryption
- Passphrase-protected: only the correct passphrase can decrypt the hidden password
- Randomized pixel order based on passphrase for extra security
- Robust error handling and capacity checks

## Usage

### Build

```
cargo build --release
```

### Hide a Password

```
./target/release/stegopass hide -i <input_image.png> -o <output_image.png> --password <password_to_hide> --passphrase <your_passphrase>
```

- `-i, --input` — Path to the input image (PNG recommended)
- `-o, --output` — Path to the output image (PNG recommended)
- `--password` — The password to hide
- `--passphrase` — Passphrase for encryption and pixel order randomization

### Extract a Password

```
./target/release/stegopass extract -i <output_image.png> --passphrase <your_passphrase>
```

- `-i, --input` — Path to the stego image
- `--passphrase` — Passphrase used during hiding

## Example

```
# Hide a password
./target/release/stegopass hide -i cover.png -o stego.png --password "mysecret" --passphrase "hunter2"

# Extract the password
./target/release/stegopass extract -i stego.png --passphrase "hunter2"
```

## Notes

- **Clipboard behavior:** After extraction, the password is copied to your clipboard for 30 seconds, then automatically cleared (unless you use `--print`). On some Linux systems (especially with Wayland or certain X11 clipboard managers), clipboard content set by a CLI tool may not persist after the CLI exits. This is a system limitation, not a bug in stegopass. If you experience this, use the `--print` flag (or set the `STEGOPASS_PRINT` environment variable) to print the password to stdout as a fallback.
- **Lossless images only:** Always use lossless image formats (PNG recommended). Lossy formats (like JPEG) will corrupt the hidden data.
- **Security:** Your password and passphrase are never echoed to the terminal. All cryptography uses strong, modern algorithms (Argon2, AES-GCM).
- **No sidecar files:** All data is embedded in the image; no extra files are needed.

## Advanced: Print password to stdout

If you want the extracted password to be printed to stdout (for scripting or in case of clipboard issues), use:

```
./target/release/stegopass extract -i stego.png --print
```

Or set the environment variable:

```
STEGOPASS_PRINT=1 ./target/release/stegopass extract -i stego.png
```

This will print the password to stdout in addition to copying it to the clipboard. When `--print` is not used, the password is only available in the clipboard for 30 seconds, after which it is automatically cleared for your security.

## Testing

Run unit tests:

```
cargo test
```

## License

MIT
