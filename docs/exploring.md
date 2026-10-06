# Exploring the demo

Seven experiments, each a few minutes. They build on each other, but any of them
can be done on its own.

Start the prompt from the repository root:

```sh
./mvnw -q compile exec:java
```

(`./demo` does the same on macOS and Linux.) Lines below that begin with a
bracketed prompt are typed there. The name in the brackets is the algorithm that
wraps new data, and a new session always starts on `RSA-OAEP-3072`.

Everything you create lives under `data/`, which git ignores, so it is still
there the next time you start the prompt. Delete that directory whenever you
want a clean start.

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
- The RSA-wrapped key is 384 bytes. The ML-KEM-768 one is 48 bytes, plus a
  1088-byte KEM ciphertext. Post-quantum envelopes are bigger.
- The data itself is AES-256-GCM throughout. Only the wrap changes.

The experiments below take the same steps one at a time, so you can poke at
each one.

## 2. Change the one line

Do the walkthrough's core move yourself. Start from a clean `data/` if you
ran the script.

```
[RSA-OAEP-3072] > write customer record #1
[RSA-OAEP-3072] > write customer record #2
[RSA-OAEP-3072] > use ML-KEM-768
  new data will be wrapped with ML-KEM-768

[ML-KEM-768] > write customer record #3
[ML-KEM-768] > read
  record-0001 (RSA-OAEP-3072) -> customer record #1
  record-0002 (RSA-OAEP-3072) -> customer record #2
  record-0003 (ML-KEM-768) -> customer record #3

  algorithms in use: {ML-KEM-768=1, RSA-OAEP-3072=2}
```

`use` is the one-line change. In a real system that value would come from
configuration; here it is the prompt. No code changed and nothing was migrated.
`use` on its own lists the algorithms you can choose, and `algorithms` shows
them as a table: what kind each is, whether it is quantum-safe, which provider
implements it on your JVM, and how many records use it. In short:

| Algorithm | What it is |
|---|---|
| `RSA-OAEP-3072` | Classical, quantum-vulnerable |
| `ECDH-X25519` | Classical elliptic-curve, quantum-vulnerable |
| `AES-256-KW` | Symmetric key wrap, as a cloud KMS does it; already quantum-safe |
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Post-quantum, lattice-based (FIPS 203), at NIST categories 1, 3 and 5 |
| `X25519+ML-KEM-768` | Hybrid of a classical and a post-quantum algorithm |
| `HQC-128`, `HQC-192`, `HQC-256` | Post-quantum, code-based, from BouncyCastle, at categories 1, 3 and 5 |

To see why the old records still read, look at what is actually stored:

```
[ML-KEM-768] > list
[ML-KEM-768] > show 1
```

`list` gives one line per envelope and `show` draws one field by field. Neither
loads a key or decrypts anything, and both can still tell you the algorithm,
because it is stored in the clear next to the data it protects. The files
themselves are plain text under `data/envelopes/` if you want to open one.

Run `show` with no record to draw them all. Each drawing has the wrapped data
key on top and the data it opens underneath, with a bar beside every field drawn
to scale at one block per 64 bytes. The RSA envelope has one large wrapped key;
the ML-KEM envelope has a small wrapped key plus a much larger KEM ciphertext.
The `data` section has the same shape in both.

The last line of `read` is an inventory. In a real system, being able to answer
"which algorithms is our stored data still using?" is the first thing a
migration needs, and you only get it if every envelope names its algorithm.

## 3. Retire an algorithm without re-encrypting the data

Two records are still wrapped with RSA. With the prompt still on `ML-KEM-768`:

```
[ML-KEM-768] > rewrap
  record-0001 RSA-OAEP-3072 -> ML-KEM-768
  record-0002 RSA-OAEP-3072 -> ML-KEM-768
  record-0003 already ML-KEM-768

  re-wrapped 2 data key(s) of 32 bytes each, re-encrypted 0 of 68 data bytes
```

Look at `rewrap` in `EnvelopeCrypto.java`. It unwraps the 32-byte data key with
the old algorithm and wraps it with the new one. The ciphertext is carried over
as it is. Compare the `ciphertext` row of `show 1` before and after to check.

That is the property that makes this practical at scale: moving a terabyte of
data to a new wrapping algorithm costs one small key operation per object, not a
terabyte of re-encryption.

One caveat worth knowing: re-wrapping protects the data key from now on. It does
nothing for copies of the old RSA-wrapped envelope that someone already took.
That is the "harvest now, decrypt later" problem: anyone who copied an envelope
while its key was RSA-wrapped can open it once RSA falls, however well you
migrate afterwards. It is why starting early matters.

Once nothing depends on RSA any more, stop reading it:

```
[ML-KEM-768] > retire RSA-OAEP-3072
  RSA-OAEP-3072 can no longer be read in this session
  no stored records depend on it, so nothing was lost
```

`retire` lasts only for the session, so it is safe to experiment with.
Inventory, move, retire: that is the whole migration. Experiment 7 adds the
proof that you are done.

## 4. Break it on purpose

Try these on your own stored records. Most mean editing the files under
`data/envelopes/`:

- **Change an envelope's `alg` line** to a different algorithm, then `read`. The
  wrong wrapper is chosen and the unwrap fails.
- **Change one character of a `ciphertext=` line.** AES-GCM is authenticated, so
  the read fails with a tag mismatch rather than returning garbage.
- **Retire an algorithm too early.** Write a record under RSA, `use ML-KEM-768`,
  and `retire RSA-OAEP-3072` without rewrapping first. `retire` names the
  records it just stranded, and `read` shows them as unreadable. Restart the
  prompt to bring RSA back, then do it in the right order: `use ML-KEM-768`,
  `rewrap`, then `retire RSA-OAEP-3072`.
- **Remove an envelope's `alg` line.** Without it, nothing says how the key was
  wrapped. `read` cannot open it, and `cbom` counts it as unknown. The only way
  back in would be to try every algorithm you have ever used.
- **Ask for something unknown**, such as `use SIKE-p434`. The error lists what is
  registered.

## 5. Add your own algorithm

The claim is that a new algorithm costs one class and one registry line. Check
it by adding FrodoKEM, a conservative lattice-based KEM that NIST did not pick
but that some European agencies recommend. The JDK does not have it, but
BouncyCastle, already a dependency, does.

1. **One class.** Copy `wrappers/HqcWrapper.java` to
   `wrappers/FrodoKemWrapper.java` and rename the class. Then:
   - Delete the `ParameterSet` enum and the constructors that use it, keeping
     one constructor that takes a `KeyPair`. This wrapper has one strength.
   - In the static block, register BouncyCastle's main provider instead:
     `new BouncyCastleProvider()` from `org.bouncycastle.jce.provider`.
   - Use `"frodokem1344aes"` for both `KEM.getInstance` and
     `KeyPairGenerator.getInstance`, and return `"FrodoKEM-1344-AES"` from
     `algId()`.
   - In `facts()`, return
     `AlgorithmFacts.of("kem", 256, 5, "keygen", "encapsulate", "decapsulate")`
     with the parameter set `"1344"`. FrodoKEM-1344 targets NIST category 5.
2. **One registry line.** In the `registry` method of `commands/Workspace.java`,
   add:

   ```java
   register(new FrodoKemWrapper(keys.keyPair("frodokem-1344-aes", FrodoKemWrapper::newKeyPair)));
   ```

Start the prompt again so the change is compiled, then:

```
[RSA-OAEP-3072] > use FrodoKEM-1344-AES
[FrodoKEM-1344-AES] > write wrapped with my own algorithm
[FrodoKEM-1344-AES] > read
[FrodoKEM-1344-AES] > algs
```

The new record reads, and so does everything written before. You did not touch
`EnvelopeCrypto`, the store, or any of the commands; tab completion, `algs` and
`cbom` already know the new algorithm, and `algs` shows it served by
BouncyCastle's `BC` provider.

Then `show` the record. FrodoKEM's ciphertext is 21,696 bytes, against
ML-KEM-1024's 1,568. Conservative designs cost bandwidth, and the envelope
carries whatever the algorithm needs.

A word of warning from writing this exercise: FrodoKEM's smaller 976 parameter
set produces a 24-byte shared secret, not 32, so asking it for a 32-byte AES key
fails. Each algorithm has its own sizes, and the wrapper is where that knowledge
belongs.

Strengths of one algorithm don't need new classes. `MlKemWrapper` and
`HqcWrapper` each take a `ParameterSet`, and the registry adds every one in a
loop, which is why `use` offers ML-KEM-512, 768 and 1024 and HQC-128, 192 and
256.

## 6. Read the hybrid, and the one that was never at risk

Before the hybrid, try `AES-256-KW` and read `wrappers/AesKwWrapper.java`. Here
an AES-256 key wraps the AES-256 data key. That is what envelope encryption with
a cloud KMS usually does: the wrapping key stays inside the KMS, and only the
32-byte data key goes in and out. It is already quantum-safe, because a quantum
computer only halves the strength of AES. The catch is that it is symmetric:
whoever can wrap can unwrap, so it only works where writer and reader share the
key. Public-key wrapping is what lets strangers send each other keys, and it is
the part that needs replacing.

Now the hybrid.

```
[RSA-OAEP-3072] > use X25519+ML-KEM-768
[X25519+ML-KEM-768] > write belt and braces
[X25519+ML-KEM-768] > show
```

Then read `wrappers/HybridWrapper.java`.

A hybrid wraps the data key under a key derived from two shared secrets: one
from a classical algorithm (X25519) and one from a post-quantum algorithm
(ML-KEM). An attacker has to break both. This is the cautious choice while
ML-KEM is new, and it is the approach TLS has taken with X25519MLKEM768.

Notice what it took to add: one class and one registry line. It also stores a
field no other wrapper has. In the `show` output you will see `ephemeralKey`
next to `kemCt`. Nothing outside `HybridWrapper` knows that field exists: a
wrapped key is a set of named byte fields chosen by the wrapper, and the
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
  AES-256-GCM        DEK  yes                    5        6
  RSA-OAEP-3072      KEK  NO                     0        2
  ECDH-X25519        KEK  NO                     0        1
  ML-KEM-768         KEK  yes                    3        2
  HQC-192            KEK  yes                    3        1

  3 of 6 records still depend on a key wrap that is not quantum-safe
  wrote data/cbom.json (CycloneDX 1.6)
```

The KEY column says which key each algorithm is used with, in NIST's terms. The
DEK (data-encryption key) is the per-record AES-256 key that encrypts the data;
the KEK (key-encryption key) is the key that wraps it. Every row that is not
quantum-safe is a KEK. The DEK algorithm is never the problem.

Nothing was decrypted to produce this. Every envelope names its algorithm, so
the inventory is a query rather than an investigation. Without that field, the
same question means trying keys against every record.

Open `data/cbom.json`. Each algorithm is a `cryptographic-asset` component with
its primitive, parameter set, OID, and NIST quantum security level, where 0
means a quantum computer breaks it. Each key file appears as key material linked
to its algorithm and marked as a KEK, and a property lists which records each
algorithm protects.
Because it is a standard format, other CBOM tools can read it.

Where the facts come from: each wrapper describes itself through a `facts()`
method from the `Inventoried` interface, so they live in the same class as the
algorithm. `KeyWrapper` itself still has its three methods. The records that make
up the file are in `cbom/CycloneDx.java`, a small slice of the full CycloneDX
format; the official `cyclonedx-core-java` library models all of it.

Then close the loop: `use ML-KEM-768`, `rewrap`, `retire` the old algorithms,
and `cbom` again. The last line turns green. That is the shape of a real
migration: inventory, move, retire, and inventory again to prove it.

Try editing one envelope's `alg` line to something nobody registered, such as
`SIKE-p434`, the post-quantum candidate that was broken on a laptop in 2022. The
inventory lists it as unknown and counts its records as at risk.

## Going further

- Run the tests with `./mvnw test`. The test names read as sentences and state
  what the code guarantees. Change something and see which sentence stops being
  true.
- `keys` lists the key files under `data/keys/`. An envelope names its algorithm
  but not which key was used, so two keys under the same algorithm cannot
  coexist. Give a wrapper a `keyId` field of its own and have it pick the key
  from that. No other class needs to change.
- Nothing authenticates the `alg` field. Real formats protect their headers;
  JWE, for example, feeds the protected header into AES-GCM as associated data.
  Try binding the header that way.
- Compare this skeleton with the real formats in
  [envelope-shapes.md](envelope-shapes.md).
