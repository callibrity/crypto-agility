# Exploring the demo

Seven experiments, each a few minutes. They build on each other, but any of them
can be done on its own.

Start the prompt from the repository root:

```sh
./mvnw -q compile exec:java
```

(`./demo` does the same on macOS and Linux.) Lines below that begin with a
bracketed prompt are typed there. The name in the brackets is the algorithm that
wraps new data keys, and a new session always starts on `RSA-OAEP-3072`, with
data encrypted by AES-256-GCM.

Every record is encrypted with its own data key, and that data key is wrapped by
a key the KMS holds. The application never sees the KMS's keys; it names one by
id and asks the KMS to work with it. Here the KMS is `LocalKms`, a stand-in that
keeps its keys in files, shaped like AWS KMS or Google Cloud KMS.

Everything you create lives under `data/`, which git ignores, so it is still
there the next time you start the prompt. What does not carry over is your `use`
choice: every new session starts on RSA again. For a clean start, `exit` the
prompt, delete `data/` (`rm -rf data`, or `rmdir /s /q data` on Windows), and
start it again.

Source files are named relative to
`src/main/java/com/callibrity/cryptoagility/`, so `wrapper/HqcWrapper.java` is
`src/main/java/com/callibrity/cryptoagility/wrapper/HqcWrapper.java`.

## 1. Watch the walkthrough

```sh
rm -rf data && ./demo --script docs/momentum.demo
```

This plays the demo from the talk: press a key and the next command types
itself and runs. Read `docs/momentum.demo` alongside it; each step has a comment.

Things to notice as it runs:

- The prompt's brackets change when `use` runs. That is the whole algorithm
  change. No code changes, and nothing already stored is touched.
- `read` is never told which algorithm to use. Each envelope says.
- The RSA-wrapped key is 384 bytes. ML-KEM works differently: it is a KEM (key
  encapsulation mechanism), which does not encrypt the data key directly.
  Instead it produces a fresh shared secret plus a 1088-byte ciphertext that
  only the private key can turn back into that secret, and the data key is
  wrapped under the secret (the 48-byte `wrappedKey`). That is why ML-KEM
  envelopes carry a `kemCt` field and RSA ones do not. Post-quantum envelopes
  are bigger.
- The data itself is AES-256-GCM throughout. Only the wrap changes.

The experiments below take the same steps one at a time, so you can poke at
each one.

## 2. Change the one line

Do the walkthrough's core move yourself. If you ran the script, start from a
clean slate (`exit`, delete `data/`, and start the prompt again) so your record
numbers match the ones below. Key ids are random, so yours will differ.

```
[RSA-OAEP-3072] > write customer record #1
[RSA-OAEP-3072] > write customer record #2
[RSA-OAEP-3072] > use ML-KEM-768
  new data keys will be wrapped with ML-KEM-768 using KMS key key-e4e6a9

[ML-KEM-768] > write customer record #3
[ML-KEM-768] > read
  record-0001 (RSA-OAEP-3072) -> customer record #1
  record-0002 (RSA-OAEP-3072) -> customer record #2
  record-0003 (ML-KEM-768) -> customer record #3

  algorithms in use: {ML-KEM-768=1, RSA-OAEP-3072=2}
```

`use` is the one-line change. In a real system that value would come from
configuration; here it is the prompt. The first time an algorithm is used, the
KMS creates a key for it. No code changed and nothing was migrated.

`keys` shows what the KMS will tell you about its keys: id, algorithm, state,
when it was created, and how many records each protects. Never the key itself.

`use` on its own lists what you can choose, and `algorithms` shows it as a
table: what kind each is, whether it is quantum-safe, which provider implements
it on your JVM, and how many keys and records use it. In short:

| Algorithm | What it is |
|---|---|
| `RSA-OAEP-3072` | Classical, quantum-vulnerable |
| `ECDH-X25519` | Classical elliptic-curve, quantum-vulnerable |
| `AES-256-KW` | Symmetric key wrap, as a cloud KMS does it; already quantum-safe |
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Post-quantum, lattice-based (FIPS 203), at NIST categories 1, 3 and 5 |
| `X25519+ML-KEM-768` | Hybrid of a classical and a post-quantum algorithm |
| `HQC-128`, `HQC-192`, `HQC-256` | Post-quantum, code-based, from BouncyCastle, at categories 1, 3 and 5 |
| `AES-256-GCM`, `ChaCha20-Poly1305` | Data ciphers: what encrypts the data itself with the data key |

To see why the old records still read, look at what is actually stored:

```
[ML-KEM-768] > list
[ML-KEM-768] > show 1
```

`list` gives one line per envelope and `show` draws one field by field. Neither
asks the KMS anything or decrypts anything, and both can still tell you the
algorithm, the KMS key and the data cipher, because the envelope stores them in
the clear next to the data they protect. The files themselves are plain text
under `data/envelopes/` if you want to open one.

Run `show` with no record to draw them all. Each drawing has the wrapped data
key on top and the data it opens underneath, with a bar beside every field drawn
to scale at one block per 64 bytes. The RSA envelope has one large wrapped key;
the ML-KEM envelope has a small wrapped key plus a much larger KEM ciphertext.
The `data` section has the same shape in both.

The last line of `read` is an inventory. In a real system, being able to answer
"which algorithms is our stored data still using?" is the first thing a
migration needs, and you only get it if every envelope names its algorithm.

## 3. Retire an algorithm without re-encrypting the data

Two records are still wrapped with RSA. `rewrap` moves every record onto the
algorithm named in the prompt, so check that the prompt still says
`[ML-KEM-768]`. If you restarted it, it is back on RSA; run `use ML-KEM-768`
again first.

```
[ML-KEM-768] > rewrap
  record-0001 RSA-OAEP-3072 (key-0208c8) -> ML-KEM-768 (key-e4e6a9)
  record-0002 RSA-OAEP-3072 (key-0208c8) -> ML-KEM-768 (key-e4e6a9)
  record-0003 already ML-KEM-768 (key-e4e6a9)

  re-wrapped 2 data key(s), re-encrypted 0 of 68 ciphertext bytes
```

Look at `rewrap` in `Envelope.java`, then `reEncrypt` in `LocalKms.java`.
The application hands the KMS a wrapped data key and the id of the new key; the
KMS unwraps it and wraps it again inside itself, so the plaintext data key never
reaches the application. AWS calls this operation ReEncrypt. The ciphertext is
carried over as it is. Compare the `ciphertext` row of `show 1` before and
after to check.

That is the property that makes this practical at scale: moving a terabyte of
data to a new wrapping algorithm costs one small key operation per object, not a
terabyte of re-encryption.

One caveat worth knowing: re-wrapping protects the data key from now on. It does
nothing for copies of the old RSA-wrapped envelope that someone already took.
That is the "harvest now, decrypt later" problem: anyone who copied an envelope
while its key was RSA-wrapped can open it once RSA falls, however well you
migrate afterwards. It is why starting early matters.

Once nothing depends on RSA any more, stop using it:

```
[ML-KEM-768] > retire RSA-OAEP-3072
  disabled 1 RSA-OAEP-3072 key(s) in the KMS
  no stored records depend on them, so nothing was lost
```

`retire` disables the algorithm's keys in the KMS. A disabled key still exists,
so `enable RSA-OAEP-3072` brings it back, which makes it safe to experiment
with. Inventory, move, retire: that is the whole migration. Experiment 7 adds
the proof that you are done.

A retired algorithm stays retired. `use RSA-OAEP-3072` is refused, and so is
`write` in a new session, which starts on RSA, until you `use` another
algorithm or `enable` RSA again. Nothing quietly creates a fresh RSA key behind
your back.

## 4. Break it on purpose

Try these on your own stored records. Most mean editing the files under
`data/envelopes/`:

- **Change an envelope's `alg` line** to a different algorithm, then `read`. The
  KMS knows what its key really is, so the read fails with "the envelope says
  ML-KEM-768, but key key-0208c8 is RSA-OAEP-3072".
- **Change one character of a `ciphertext=` line.** AES-GCM is authenticated, so
  the read fails with a tag mismatch rather than returning garbage.
- **Retire an algorithm too early.** Write a record under RSA (if you retired
  it in experiment 3, `enable RSA-OAEP-3072` first), `use ML-KEM-768`, and
  `retire RSA-OAEP-3072` without rewrapping first. `retire` names the
  records it just stranded, and `read` shows them as unreadable. `enable
  RSA-OAEP-3072` brings them back; then do it in the right order: `rewrap`,
  then `retire RSA-OAEP-3072`.
- **Remove an envelope's `alg` line.** It still reads, because the `kid` line
  tells the KMS which key to use. But `list` now shows `(none)` and `cbom` counts
  the record as unknown: the inventory has lost sight of it, and only someone
  who can ask the KMS about every key could find it again.
- **Remove an envelope's `kid` line.** Now nothing says which key opens the
  data key, and `read` reports it as unreadable.
- **Ask for something unknown**, such as `use SIKE-p434`. The error points you
  to `algorithms`, which lists everything that is registered.

## 5. Add your own algorithm

The claim is that a new algorithm costs one class and one registry line. Check
it by adding FrodoKEM, a conservative lattice-based KEM that NIST did not pick
but that some European agencies recommend. The JDK does not have it, but
BouncyCastle, already a dependency, does.

1. **One class.** Copy `wrapper/HqcWrapper.java` to
   `wrapper/FrodoKemWrapper.java` and rename the class. Then:
   - Delete the `ParameterSet` enum, the `parameterSet` field and the static
     block. `LocalKms` already installs BouncyCastle's providers.
   - Delete the constructor's check that the key matches its parameter set, and
     the `.withProvisionalOid(...)` call in `facts()`; both use the field you
     just removed. Don't adapt the check to the new name: BouncyCastle calls
     FrodoKEM keys `frodokem1344aes`, so it would reject every key. Drop the
     imports that are now unused.
   - Keep one constructor, taking a `KeyPair`, and one `newKeyPair()` method.
     Use `"frodokem1344aes"` for both `KEM.getInstance` and
     `KeyPairGenerator.getInstance`, and return `"FrodoKEM-1344-AES"` from
     `algId()`.
   - In `facts()`, return
     `AlgorithmFacts.of("kem", 256, 5, "keygen", "encapsulate", "decapsulate")`
     with the parameter set `"1344"`. FrodoKEM-1344 targets NIST category 5.
2. **One registry line.** In `withStandardAlgorithms` in `kms/LocalKms.java`,
   add:

   ```java
   kms.register(KeyTypes.keyPair("FrodoKEM-1344-AES", FrodoKemWrapper::newKeyPair, FrodoKemWrapper::new));
   ```

Start the prompt again so the change is compiled, then:

```
[RSA-OAEP-3072] > use FrodoKEM-1344-AES
[FrodoKEM-1344-AES] > write wrapped with my own algorithm
[FrodoKEM-1344-AES] > read
[FrodoKEM-1344-AES] > algs
```

The new record reads, and so does everything written before. You did not touch
`Envelope`, the store, or any of the commands; tab completion, `algs`,
`keys` and `cbom` already know the new algorithm, and `algs` shows it served by
BouncyCastle's `BC` provider.

Then `show` the record. FrodoKEM's ciphertext is 21,696 bytes, against
ML-KEM-1024's 1,568. Conservative designs cost bandwidth, and the envelope
carries whatever the algorithm needs.

A word of warning: FrodoKEM's smaller 976 parameter set produces a 24-byte
shared secret, not 32, so asking it for a 32-byte AES key fails, with an error
like `Range [0, 32) out of bounds for length 24`. Each algorithm has its own
sizes, and the wrapper is where that knowledge belongs.

Strengths of one algorithm don't need new classes. `MlKemWrapper` and
`HqcWrapper` each take a `ParameterSet`, and `LocalKms` registers every one in a
loop, which is why `use` offers ML-KEM-512, 768 and 1024 and HQC-128, 192 and
256.

## 6. Read the hybrid, and the parts that were never at risk

Before the hybrid, try `AES-256-KW` and read `wrapper/AesKwWrapper.java`. Here
an AES-256 key wraps the AES-256 data key. That is what envelope encryption with
a cloud KMS usually does: the wrapping key stays inside the KMS, and only the
32-byte data key goes in and out. It is already quantum-safe, because a quantum
computer only halves the strength of AES. The catch is that it is symmetric:
whoever can wrap can unwrap, so it only works where writer and reader share the
key. Public-key wrapping is what lets strangers send each other keys, and it is
the part that needs replacing.

The data cipher was never at risk either. Try the other one:

```
[RSA-OAEP-3072] > use ChaCha20-Poly1305
  new data will be encrypted with ChaCha20-Poly1305

[RSA-OAEP-3072 + ChaCha20-Poly1305] > write a record under the other cipher
```

The prompt now names both choices. `cipher/ChaCha20Poly1305.java` is the whole
of the second cipher, and each envelope records its `enc` the way it records
its `alg`, so records under either cipher read side by side. AES-256-GCM is
simply what this repo uses for data keys by default. Note that `rewrap` can move
a data key to another wrap algorithm, but changing the data cipher would mean
re-encrypting the data itself. `use AES-256-GCM` switches back.

Now the hybrid.

```
[RSA-OAEP-3072] > use X25519+ML-KEM-768
[X25519+ML-KEM-768] > write belt and braces
[X25519+ML-KEM-768] > show
```

Then read `wrapper/HybridWrapper.java`.

A hybrid wraps the data key under a key derived from two shared secrets: one
from a classical algorithm (X25519) and one from a post-quantum algorithm
(ML-KEM). An attacker has to break both. This is the cautious choice while
ML-KEM is new, and it is the approach TLS has taken with X25519MLKEM768.

Notice what it took to add: one class and one registry line. It also stores a
combination of fields no other wrapper has. In the `show` output you will see
both `ephemeralKey`, the one-time X25519 key that `ECDH-X25519` also stores, and
`kemCt`, the ML-KEM ciphertext. Nothing outside `HybridWrapper` knows it needs
both: a wrapped key is a set of named byte fields chosen by the wrapper, and the
envelope, the store and the commands carry them as they come.

`HybridWrapper` is here to show the idea. It is not the X-Wing construction and
has had no security review, so treat it as reading material rather than
something to copy.

## 7. Take inventory

Before you can migrate anything, you have to find it. The industry's answer is a
cryptographic bill of materials (CBOM): a list of every algorithm and key in use,
in the CycloneDX standard format. Write records under a few algorithms, then:

```
[ML-KEM-768] > cbom
  ALGORITHM          KEY  QUANTUM-SAFE  NIST LEVEL  RECORDS
  AES-256-GCM        DEK  yes                    5        5
  ChaCha20-Poly1305  DEK  yes                    5        1
  RSA-OAEP-3072      KEK  NO                     0        2
  ECDH-X25519        KEK  NO                     0        1
  ML-KEM-768         KEK  yes                    3        2
  HQC-192            KEK  yes                    3        1

  3 of 6 records still depend on a key wrap that is not quantum-safe
  wrote data/cbom.json (CycloneDX 1.6)
```

The KEY column says which key each algorithm is used with, in NIST's terms. The
DEK (data-encryption key) is the per-record key that encrypts the data; the KEK
(key-encryption key) is the KMS key that wraps it. Every row that is not
quantum-safe is a KEK. The DEK algorithm is never the problem.

Nothing was decrypted to produce this. Every envelope names its algorithms, so
the inventory is a query rather than an investigation, plus a question to the
KMS about its keys.

Open `data/cbom.json`. Each algorithm is a `cryptographic-asset` component with
its primitive, parameter set, OID, and NIST quantum security level, where 0
means a quantum computer breaks it. Each KMS key for an algorithm that still
protects a record appears as key material linked to that algorithm, with its
state (active or deactivated), its creation date, and the records it protects.
The key itself never leaves the KMS, and the inventory does not need it.
Because it is a standard format, other CBOM tools can read it.

Where the facts come from: each wrapper and each cipher describes itself
through a `facts()` method from the `Inventoried` interface, so the facts live in
the same class as the algorithm, and `KeyWrapper` stays three methods. The
records that make up the file are in `cbom/CycloneDx.java`, a small slice of the
full CycloneDX format; the official `cyclonedx-core-java` library models all of
it.

Then close the loop: `use ML-KEM-768`, `rewrap`, `retire` the old algorithms,
and `cbom` again. The summary line turns green. That is the shape of a real
migration: inventory, move, retire, and inventory again to prove it.

Try editing one envelope's `alg` line to something nobody registered, such as
`SIKE-p434`, the post-quantum candidate that was broken on a laptop in 2022. The
inventory lists it as unknown and counts its records as at risk.

## Going further

- Run the tests with `./mvnw test`. The test names read as sentences and state
  what the code guarantees. Change something and see which sentence stops being
  true.
- Add a `rotate` command that asks the KMS for a fresh key under the current
  algorithm. `use` picks the newest enabled key, so new data goes to the fresh
  key at once, and `rewrap` moves the old records onto it. Two keys under one
  algorithm can coexist because every envelope names its key.
- Write a `KeyManagementService` for a real KMS. The interface is shaped like
  AWS KMS's GenerateDataKey, Decrypt and ReEncrypt, and nothing outside the
  `kms` package would need to change. It is also where you would find out which
  algorithms your KMS actually offers today.
- Nothing authenticates the `alg` field. Real formats protect their headers;
  JWE, for example, feeds the protected header into AES-GCM as associated data.
  Try binding the header that way.
- Compare this skeleton with the real formats: the AWS Encryption SDK's message
  format, Tink's envelope AEAD, JWE (RFC 7516) and CMS (RFC 5652). Each has the
  same parts, and each names its algorithms in the envelope.
