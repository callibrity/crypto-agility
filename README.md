# Crypto agility

Demo code for the talk **"Crypto you can change: getting ready for post-quantum
without a rewrite"** (James Carman, Momentum Dev Conference, Oct 15 2026).

It shows crypto agility through envelope encryption against a key management
service. Data whose keys are wrapped with RSA, elliptic-curve, AES key wrap,
ML-KEM, HQC and a hybrid sits side by side, all of it decrypts, and the calling
code never changes.

## The point

Post-quantum migration is not a one-time swap. Algorithms get broken and the
standard set keeps changing, so the skill worth building is the ability to change
algorithms cheaply. Two things make that possible:

1. **Isolate crypto behind one seam.** Call sites ask to seal an envelope, not for RSA.
2. **Store the algorithm identity with the data.** Old data stays readable under
   the old algorithm while new data uses the new one.

Envelope encryption gives you both. Each record is encrypted with its own data
key (the DEK), and that data key is wrapped by a key-encrypting key (the KEK)
that a key management service (KMS) holds. Quantum computers do not threaten the
data encryption; they threaten the public-key algorithms used to wrap the DEK.
That wrap is the part this repo makes swappable, and every envelope records
which algorithm and which KMS key it used.

## Quick start

You need **JDK 25 or later**. Maven is not required; the wrapper script fetches
it the first time.

```sh
./mvnw -q compile exec:java
```

On macOS and Linux, `./demo` is shorthand for the same thing. It starts an
interactive prompt. The name in brackets is the algorithm that wraps new data
keys:

```
[RSA-OAEP-3072] > write customer record #1
  saved record-0001: {alg=RSA-OAEP-3072, kid=key-0208c8, enc=AES-256-GCM, ciphertext=..., wrappedKey=384 bytes}

[RSA-OAEP-3072] > use ML-KEM-768
  new data keys will be wrapped with ML-KEM-768 using KMS key key-e4e6a9

[ML-KEM-768] > write customer record #2
  saved record-0002: {alg=ML-KEM-768, kid=key-e4e6a9, enc=AES-256-GCM, ciphertext=..., wrappedKey=48 bytes, kemCt=1088 bytes, wrapNonce=12 bytes}

[ML-KEM-768] > read
  record-0001 (RSA-OAEP-3072) -> customer record #1
  record-0002 (ML-KEM-768) -> customer record #2

  algorithms in use: {ML-KEM-768=1, RSA-OAEP-3072=1}
```

`use` is the one-line change. Old data still reads, new data is post-quantum, and
no code changed. Tab completes commands, algorithm names and record ids, and the
up arrow recalls earlier lines.

## Commands

| Command | What it does |
|---|---|
| `use [name]` | Chooses what wraps new data keys (an algorithm such as `ML-KEM-768`) or what encrypts new data (a cipher such as `ChaCha20-Poly1305`). On its own, lists both |
| `algorithms` | Everything you can use: what kind it is, whether it is quantum-safe, which provider implements it, and how many keys and records use it (`algs` works too) |
| `write <text>` | Encrypts the text under a fresh data key from the KMS and stores the envelope |
| `read` | Decrypts everything stored, whichever algorithms it names |
| `list` | One line per stored envelope: algorithm, KMS key, data cipher and size |
| `show [record]` | Draws a stored envelope field by field, or all of them. Nothing is decrypted |
| `rewrap` | Moves stored envelopes to the current KMS key. The KMS re-wraps each data key; the data is not touched |
| `retire <algorithm>` | Disables every KMS key for an algorithm, and names any records that strands |
| `enable <algorithm>` | Re-enables an algorithm's keys |
| `keys` | Lists the KMS's keys: algorithm, state, age and how many records use each |
| `cbom` | Inventories the algorithms and keys protecting stored data, and writes a CycloneDX CBOM to `data/cbom.json` |
| `help`, `exit` | The command list, and the way out |

Envelopes and the KMS's keys are kept under `data/`, so what one session writes
the next can read. Every session starts on RSA with AES-256-GCM; the choices made
with `use` are not saved. Delete `data/` for a clean start.

### Scripted walkthrough

The demo from the talk is also a script you can play back:

```sh
rm -rf data && ./demo --script docs/momentum.demo
```

In a real terminal, press a key and the next command types itself and runs
(in an IDE's run window, press Enter instead), with the same prompt
and the same commands as when you type them. The script's comments explain each
step. On Windows, use `mvnw -q compile exec:java -Dexec.args="--script docs/momentum.demo"`.
Set `DEMO_TYPING=0` to skip the typing effect, or `DEMO_CPS` to change its speed.
Write your own scripts the same way: one command per line, `#` for comments.

A single command can also be run without the prompt:

```sh
./demo cbom
./mvnw -q compile exec:java -Dexec.args="cbom"
```

[docs/exploring.md](docs/exploring.md) walks through seven experiments,
including a full migration (inventory, rewrap, retire), adding an algorithm of
your own, and taking a cryptographic inventory.
`./mvnw test` runs the same claims as tests.

CI also checks the code's formatting (google-java-format) and license headers.
Your own builds never do, so changes you try out are never blocked on layout;
`./mvnw spotless:apply license:format` tidies both if you want to send a change
back.

## Where to look

Everything is under `src/main/java/com/callibrity/cryptoagility/`.

| Package | What is there |
|---|---|
| `envelope` | The `Envelope`, which can `seal` data under a KMS key, `open` itself, and `rewrap` itself onto another key |
| `kms` | `KeyManagementService`, shaped like AWS KMS or Google Cloud KMS, and `LocalKms`, a stand-in that keeps its keys in files |
| `wrapper` | The key-wrapping seam (`KeyWrapper`) and one class per algorithm: `RsaWrapper` and `EcdhWrapper` (classical), `AesKwWrapper` (symmetric, as a cloud KMS does it), `MlKemWrapper` and `HqcWrapper` (post-quantum), and `HybridWrapper` |
| `cipher` | The data-encryption seam (`DataCipher`) and its two implementations, `AesGcm` and `ChaCha20Poly1305` |
| `store` | Envelopes kept as small text files under `data/envelopes` |
| `cbom` | `CycloneDx`: the slice of the CycloneDX 1.6 format a cryptographic bill of materials needs, as records |
| `command` | One class per command, the `Workspace` they share, and the `show` drawing. Commands write to a `PrintWriter` they are given |
| `demo` | The entry point (`Demo`), the command dispatcher (`Shell`), the interactive prompt (`Repl`), and the scripted player (`ScriptedRepl`) |

### The seam

Swap the implementation, never the call sites.

```java
public interface KeyWrapper {
  String algId();
  WrappedDek wrap(SecretKey dek) throws GeneralSecurityException;
  SecretKey unwrap(WrappedDek w) throws GeneralSecurityException;
}
```

Each wrapper lives inside the KMS: `LocalKms` uses them as its engine, the way a
real KMS has an implementation per key type. Supporting a new algorithm is one
more `KeyWrapper` class and one register line in `LocalKms`.

There are two seams, one per layer. The wrap is chosen by naming a KMS key; its
algorithm belongs to the key, so the application never sees it. The data cipher
is chosen by passing a `DataCipher`, because the data is encrypted here, in the
application. Neither is named where data is sealed: both come from
configuration, and the envelope records both.

### The one line that involves the KEK

This is `Envelope.seal`, the one place data gets encrypted:

```java
// The only line that involves the KEK.
DataKey dataKey = kms.generateDataKey(keyId, cipher.keySpec());
// The data never goes to the KMS.
Encrypted encrypted = cipher.encrypt(dataKey.key(), plaintext);
// And the envelope says what it used.
return new Envelope(
    dataKey.algorithm(),
    keyId,
    cipher.algId(),
    encrypted.nonce(),
    encrypted.ciphertext(),
    dataKey.wrapped());
```

The application never holds a KEK. It names a KMS key and gets back a fresh data
key twice over: in plaintext to encrypt with once, and wrapped to store. That is
how `GenerateDataKey` works in AWS KMS.

The envelope's three header fields borrow their names from JWE (JSON Web
Encryption): `alg` for how the data key is wrapped, `kid` for which key unwraps
it, and `enc` for how the data is encrypted.

`WrappedDek` is a set of named byte fields that the wrapper chooses. RSA stores
one, the KEM-based wrappers three, the hybrid four. The envelope, the store and
the commands carry them without knowing what they mean, so a new algorithm can
store whatever it needs.

The data itself is encrypted with AES-256-GCM unless you `use ChaCha20-Poly1305`.
That is simply what this repo uses for data keys. Neither cipher is threatened by
quantum computers, but each envelope still names its data cipher, so changing it
would be as easy as changing the wrap.

## This is a teaching demo

The envelope format is homegrown, and `LocalKms` keeps its private keys
unencrypted in `data/kms/` so you can look at them. A real KMS keeps keys in
hardware and never hands them out. `HybridWrapper` shows the shape of a hybrid
but is not a reviewed construction. Do not hand-roll any of this in production.
Use a real KMS with Tink or the AWS Encryption SDK, JWE when the envelope is a
token crossing a boundary, or CMS when a standard requires it. All of them follow
the same skeleton as this demo, and all of them write the algorithm into the
envelope.

There are three library dependencies. BouncyCastle supplies HQC, which the JDK
does not have yet; every other algorithm is standard JDK. Jackson writes the
CBOM as JSON, and JLine provides the prompt's line editing.

## Going further

[docs/exploring.md](docs/exploring.md) has guided experiments with this code.

## Contributing

Fixes, clearer explanations and new algorithms are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
