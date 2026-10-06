# Crypto agility demo

Demo code for the talk **"Crypto you can change: getting ready for post-quantum
without a rewrite"** (James Carman, Momentum Dev Conference, Oct 15 2026).

It shows crypto agility through envelope encryption. Data written under RSA,
elliptic-curve, AES key wrap, ML-KEM, HQC and a hybrid sits side by side, all of it decrypts,
and the calling code never changes.

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
./mvnw -q compile exec:java
```

On macOS and Linux, `./demo` is shorthand for the same thing. It starts an
interactive prompt. The name in brackets is the algorithm that wraps new data:

```
[RSA-OAEP-3072] > write customer record #1
  saved record-0001: {alg=RSA-OAEP-3072, ciphertext=..., wrappedKey=384 bytes}

[RSA-OAEP-3072] > use ML-KEM-768
  new data will be wrapped with ML-KEM-768

[ML-KEM-768] > write customer record #2
  saved record-0002: {alg=ML-KEM-768, ciphertext=..., wrappedKey=48 bytes, kemCt=1088 bytes, wrapNonce=12 bytes}

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
| `use [algorithm]` | Chooses the algorithm that wraps new data, or lists the choices |
| `algorithms` | Every algorithm you can use: what kind it is, whether it is quantum-safe, which provider implements it, and how many records use it (`algs` works too) |
| `write <text>` | Encrypts the text under the current algorithm and stores the envelope |
| `read` | Decrypts everything stored, whichever algorithm wrapped it |
| `list` | One line per stored envelope: algorithm, sizes and wrap fields |
| `show [record]` | Draws a stored envelope field by field, or all of them. Nothing is decrypted |
| `rewrap` | Moves stored envelopes to the current algorithm by re-wrapping only the data key |
| `retire <algorithm>` | Stops reading an algorithm for this session, and names any records that strands |
| `keys` | Lists the key files |
| `cbom` | Inventories the algorithms protecting stored data, and writes a CycloneDX CBOM to `data/cbom.json` |
| `swap` | The demo from the talk, in memory: RSA, then ML-KEM, and both decrypt |
| `help`, `exit` | The command list, and the way out |

Envelopes and keys are kept under `data/`, so what one session writes the next
can read. Every session starts on RSA; the choice made with `use` is not saved.
Delete `data/` for a clean start.

### Scripted walkthrough

The demo from the talk is also a script you can play back:

```sh
rm -rf data && ./demo --script docs/momentum.demo
```

Press a key and the next command types itself and runs, with the same prompt
and the same commands as when you type them. The script's comments explain each
step. On Windows, use `mvnw -q compile exec:java -Dexec.args="--script docs/momentum.demo"`.
Set `DEMO_TYPING=0` to skip the typing effect, or `DEMO_CPS` to change its speed.
Write your own scripts the same way: one command per line, `#` for comments.

A single command can also be run without the prompt:

```sh
./demo swap
./mvnw -q compile exec:java -Dexec.args="swap"
```

[docs/exploring.md](docs/exploring.md) walks through seven experiments,
including a full migration (inventory, rewrap, retire), adding an algorithm of
your own, and taking a cryptographic inventory.
`./mvnw test` runs the same claims as tests.

## Where to look

Everything is under `src/main/java/com/callibrity/cryptoagility/`.

| Package | What is there |
|---|---|
| `envelope` | The seam (`KeyWrapper`), the `Envelope`, and `EnvelopeCrypto` with `encrypt`, `decrypt` and `rewrap` |
| `wrappers` | One class per algorithm, and the only code that knows any of them: `RsaWrapper` and `EcdhWrapper` (classical), `AesKwWrapper` (symmetric, as a KMS does it), `MlKemWrapper` and `HqcWrapper` (post-quantum), and `HybridWrapper` |
| `store` | Envelopes and demo keys kept as small text files under `data/` |
| `cbom` | `CycloneDx`: the slice of the CycloneDX 1.6 format a cryptographic bill of materials needs, as records |
| `commands` | One class per command, the registry of readable algorithms in `Workspace`, and the `show` drawing. Commands write to a `PrintWriter` they are given |
| `demos` | The entry point (`Demo`), the command dispatcher (`Shell`), the interactive prompt (`Repl`), and the scripted stage player (`ScriptedRepl`) |

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
return new Envelope(wrapper.algId(), nonce, ct, w);
```

The envelope records `wrapper.algId()`, so each blob names its own algorithm.

`WrappedDek` is a set of named byte fields that the wrapper chooses. RSA stores
one, the KEM-based wrappers three, the hybrid four. The envelope, the store and the commands
carry them without knowing what they mean, so a new algorithm can store whatever
it needs.

## This is a teaching demo

The envelope format is homegrown and the private keys sit unencrypted in
`data/keys/`, so that nothing hides the skeleton. `HybridWrapper` shows the shape
of a hybrid but is not a reviewed construction. Do not hand-roll any of this in production. Use a KMS with Tink or the
AWS Encryption SDK, JWE when the envelope is a token crossing a boundary, or CMS
when a standard requires it. See
[docs/envelope-shapes.md](docs/envelope-shapes.md).

There are three library dependencies. BouncyCastle supplies HQC, which the JDK
does not have yet; every other algorithm is standard JDK. Jackson writes the
CBOM as JSON, and JLine provides the prompt's line editing.

## Further reading

- [docs/exploring.md](docs/exploring.md): guided experiments with this code.
- [docs/envelope-shapes.md](docs/envelope-shapes.md): the general shape of
  envelope encryption, how Tink, the AWS Encryption SDK, JWE and CMS implement
  it, and where post-quantum support stood as of 30 Sept 2026.

## License

Apache License 2.0. See [LICENSE](LICENSE).
