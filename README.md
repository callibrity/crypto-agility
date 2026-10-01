# Crypto agility demo

Demo code for the talk **"Crypto you can change: getting ready for post-quantum
without a rewrite"** (James Carman, Momentum Dev Conference, Oct 15 2026).

It shows crypto agility through envelope encryption in one dependency-free Java
file: data written under RSA and data written under ML-KEM sit side by side, and
both decrypt, with no migration window and no change to the calling code.

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

## Run it

Requires **JDK 24 or later**. ML-KEM is built into the platform (JEP 496), so
there is nothing to install or build.

```sh
./run.sh
# or
java EnvelopeDemo.java
```

On JDK 21-23 the `javax.crypto.KEM` API is present but ML-KEM is not; add
BouncyCastle 1.86 and register it as a provider.

### Expected output

The ciphertext prefixes differ on every run; everything else is stable.

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

## What to look at

### 1. The seam

Swap the implementation, never the call sites.

```java
interface KeyWrapper {
    String algId();
    WrappedDek wrap(SecretKey dek) throws GeneralSecurityException;
    SecretKey unwrap(WrappedDek w) throws GeneralSecurityException;
}
```

`RsaWrapper` and `MlKemWrapper` both implement it. Adding another algorithm later
(HQC, say) means writing one more class. Nothing else moves.

### 2. The one algorithm-dependent line

```java
byte[] ct = c.doFinal(plaintext);      // data is ALWAYS AES-256-GCM
WrappedDek w = wrapper.wrap(dek);      // the only algorithm-dependent line
return new Envelope(wrapper.algId(), nonce, ct, w.wrappedKey(), w.kemCt(), w.wrapNonce());
```

The envelope records `wrapper.algId()`, so each blob names its own algorithm.

### 3. The swap

```java
var rsa = new RsaWrapper();
Envelope v1 = encrypt(..., rsa);       // alg = RSA-OAEP-3072

var mlkem = new MlKemWrapper();
Envelope v2 = encrypt(..., mlkem);     // alg = ML-KEM-768

decrypt(v1, registry);                 // still reads: the envelope says RSA
decrypt(v2, registry);                 // post-quantum: the envelope says ML-KEM
```

## This is a teaching demo

The keys live in process memory and the envelope format is homegrown, so that
nothing hides the skeleton. Do not hand-roll this in production. Use a KMS with
Tink or the AWS Encryption SDK, JWE when the envelope is a token crossing a
boundary, or CMS when a standard requires it. See
[docs/envelope-shapes.md](docs/envelope-shapes.md).

## Further reading

[docs/envelope-shapes.md](docs/envelope-shapes.md) covers the general shape of
envelope encryption, how Tink, the AWS Encryption SDK, JWE and CMS implement it,
and where post-quantum support stood as of 30 Sept 2026.

## License

Apache License 2.0. See [LICENSE](LICENSE).
