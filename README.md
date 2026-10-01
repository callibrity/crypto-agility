# Crypto agility demo

Demo code for the talk **"Crypto you can change: getting ready for post-quantum
without a rewrite"** (James Carman, Momentum Dev Conference, Oct 15 2026).

It shows crypto agility through envelope encryption, in plain Java with no
runtime dependencies. Data written under RSA, under ML-KEM and under a hybrid of
the two sits side by side, all of it decrypts, and the calling code never changes.

## The point

Post-quantum migration is not a one-time swap. Algorithms get broken and the
standard set keeps changing, so the skill worth building is the ability to change
algorithms cheaply. Two things make that possible:

1. **Isolate crypto behind one seam.** Call sites ask for "encrypt", not "RSA".
2. **Store the algorithm identity with the data.** Old data stays readable under
   the old algorithm while new data uses the new one.

Envelope encryption gives you both. The data is always AES-256-GCM, which quantum
computers do not threaten. The only algorithm-dependent step is how the data key
is wrapped, and that step lives behind a single interface.

## Quick start

You need **JDK 25 or later**. Maven is not required; the wrapper script fetches
it the first time.

```sh
./demo swap
```

```
config: crypto.wrap = RSA-OAEP-3072
  v1 envelope: {alg=RSA-OAEP-3072, ciphertext=..., wrappedKey=384 bytes}

config: crypto.wrap = ML-KEM-768   (one line)

  v2 envelope: {alg=ML-KEM-768, ciphertext=..., wrappedKey=48 bytes, kemCt=1088 bytes}

Decrypt both, no migration window:
  v1 (RSA-OAEP-3072)  -> customer record #1 (written last year)
  v2 (ML-KEM-768)       -> customer record #2 (written today)

Old data still reads, new data is post-quantum, the code never changed.
```

## Things to run

| Command | What it shows |
|---|---|
| `./demo swap` | The demo from the talk, in memory: RSA, then ML-KEM, and both decrypt |
| `./demo write "some text"` | Encrypts under the algorithm named in `config/crypto.properties` and saves the envelope under `data/` |
| `./demo read` | Decrypts everything under `data/`, whichever algorithm wrapped it |
| `./demo list` | One line per stored envelope, with its algorithm and sizes (`ls` works too) |
| `./demo show [record]` | Draws a stored envelope field by field, or all of them. Nothing is decrypted |
| `./demo rewrap` | Moves every stored envelope to the configured algorithm by re-wrapping only its data key |
| `./demo crack [record]` | Breaks a record wrapped with the deliberately tiny `RSA-TOY-96` key, using only the public key |
| `./demo pitfalls` | Two ways an algorithm change goes wrong |
| `./mvnw test` | The same claims as tests |

`write`, `read` and `rewrap` work together across runs. Write a few records,
change the one line in `config/crypto.properties`, write a few more, and read
them all back. [docs/exploring.md](docs/exploring.md) walks through that and
more, including adding an algorithm of your own.

On Windows, or to skip the script:

```
mvnw compile
java -cp target/classes com.callibrity.cryptoagility.demos.Demo swap
```

## Where to look

Everything is under `src/main/java/com/callibrity/cryptoagility/`.

| Package | What is there |
|---|---|
| `envelope` | The seam (`KeyWrapper`), the `Envelope`, and `EnvelopeCrypto` with `encrypt`, `decrypt` and `rewrap` |
| `wrappers` | `RsaWrapper`, `MlKemWrapper`, `HybridWrapper` and the breakable `ToyRsaWrapper`: the only code that knows an algorithm |
| `store` | Envelopes and demo keys kept as small text files under `data/` |
| `demos` | One short class per command, and the registry of readable algorithms in `Workspace` |

### The seam

Swap the implementation, never the call sites.

```java
public interface KeyWrapper {
    String algId();
    WrappedDek wrap(SecretKey dek) throws GeneralSecurityException;
    SecretKey unwrap(WrappedDek w) throws GeneralSecurityException;
}
```

### The one algorithm-dependent line

```java
byte[] ct = c.doFinal(plaintext);      // data is ALWAYS AES-256-GCM
WrappedDek w = wrapper.wrap(dek);      // the only algorithm-dependent line
return new Envelope(wrapper.algId(), nonce, ct, w.wrappedKey(), w.kemCt(), w.wrapNonce());
```

The envelope records `wrapper.algId()`, so each blob names its own algorithm.

## This is a teaching demo

The envelope format is homegrown and the private keys sit unencrypted in
`data/keys/`, so that nothing hides the skeleton. `HybridWrapper` shows the shape
of a hybrid but is not a reviewed construction, and `ToyRsaWrapper` is broken on
purpose. Do not hand-roll any of this in
production. Use a KMS with Tink or the AWS Encryption SDK, JWE when the envelope
is a token crossing a boundary, or CMS when a standard requires it. See
[docs/envelope-shapes.md](docs/envelope-shapes.md).

## Further reading

- [docs/exploring.md](docs/exploring.md): guided experiments with this code.
- [docs/envelope-shapes.md](docs/envelope-shapes.md): the general shape of
  envelope encryption, how Tink, the AWS Encryption SDK, JWE and CMS implement
  it, and where post-quantum support stood as of 30 Sept 2026.

## License

Apache License 2.0. See [LICENSE](LICENSE).
