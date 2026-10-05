# Exploring the demo

Eight experiments, each a few minutes. They build on each other, but any of them
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

## 1. Watch the swap

```
[RSA-OAEP-3072] > swap
```

This is the demo from the talk, run entirely in memory. Read `SwapDemo.java`
next to the output: the call to `encrypt` is the same line both times, and
`decrypt` is never told which algorithm to use. It finds out from the envelope.

Things to notice in the output:

- The RSA-wrapped key is 384 bytes. The ML-KEM-wrapped key is 48 bytes, plus a
  1088-byte KEM ciphertext. Post-quantum envelopes are bigger.
- The data itself is AES-256-GCM in both cases. Only the wrap changed.

## 2. Change the one line

The `swap` demo does everything at once. This experiment does it the way a real
system would: over time, with data on disk.

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
| `ML-KEM-768` | Post-quantum, lattice-based (FIPS 203) |
| `X25519+ML-KEM-768` | Hybrid of a classical and a post-quantum algorithm |
| `HQC-192` | Post-quantum, code-based, from BouncyCastle |
| `RSA-TOY-96` | Deliberately breakable, for experiment 7 |

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
That is the "harvest now, decrypt later" problem, and it is why starting early
matters. Experiment 7 makes it concrete.

## 4. Break it on purpose

```
[RSA-OAEP-3072] > pitfalls
```

This runs two failures in memory: an envelope that does not say how it was
wrapped, and an algorithm retired while data still depends on it. Then try some
by hand on your own stored records, editing the files under `data/envelopes/`:

- **Change an envelope's `alg` line** to a different algorithm, then `read`. The
  wrong wrapper is chosen and the unwrap fails.
- **Change one character of a `ciphertext=` line.** AES-GCM is authenticated, so
  the read fails with a tag mismatch rather than returning garbage.
- **Retire an algorithm too early.** Write a record under RSA, `exit`, delete the
  `RsaWrapper` line from the `registry` method in `Workspace.java`, and start the
  prompt again. `read` reports the record as unreadable until you put the line
  back. Now do it in the right order: put the line back, `use ML-KEM-768`,
  `rewrap`, then remove it.
- **Ask for something unknown**, such as `use SIKE-p434`. The error lists what is
  registered.

## 5. Add your own algorithm

The claim is that a new algorithm costs one class and one registry line. Check
it by adding ML-KEM-1024, the larger parameter set.

1. **One class.** Copy `wrappers/MlKemWrapper.java` to
   `wrappers/MlKem1024Wrapper.java`. Rename the class, and change the two
   `"ML-KEM-768"` strings (the key pair generator and `algId`) to
   `"ML-KEM-1024"`. In `facts()`, which describes the algorithm for the
   inventory in experiment 8, change the levels to `256, 5`, the parameter set
   to `"1024"`, and the OID to `"2.16.840.1.101.3.4.4.3"`.
2. **One registry line.** In the `registry` method of `demos/Workspace.java`,
   add:

   ```java
   register(new MlKem1024Wrapper(keys.keyPair("ml-kem-1024", MlKem1024Wrapper::newKeyPair)));
   ```

Start the prompt again so the change is compiled, then:

```
[RSA-OAEP-3072] > use ML-KEM-1024
[ML-KEM-1024] > write wrapped with my own algorithm
[ML-KEM-1024] > read
```

The new record reads, and so does everything written before. You did not touch
`EnvelopeCrypto`, the store, or any of the commands, and tab completion already
offers the new name.

`wrappers/HqcWrapper.java` is the same exercise done with an algorithm the JDK
does not have. HQC comes from BouncyCastle, through the same KEM API, and the
class is nearly line for line the same as `MlKemWrapper`. Try `use HQC-192`,
write a record and `show` it: the KEM ciphertext is 8978 bytes against
ML-KEM's 1088, too long for its bar to be drawn to scale.

For something harder, try a wrapper for a different key size of RSA, or for
another BouncyCastle KEM such as FrodoKEM.

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

## 7. Harvest now, decrypt later

Nobody can break RSA-3072 on a laptop, so this experiment uses `RSA-TOY-96`: RSA
with a 96-bit key, small enough to factor in a few seconds. It is a stand-in.
The attack here is classical and only works because the key is tiny. What it
shows is the consequence, which is the same one Shor's algorithm on a large
quantum computer would have for real RSA.

Write a secret under the toy key:

```
[RSA-OAEP-3072] > use RSA-TOY-96
[RSA-TOY-96] > write the merger closes on Friday
  saved record-0001: {alg=RSA-TOY-96, ciphertext=..., wrappedKey=36 bytes}
```

Note the id of the new record; the commands below assume `record-0001`. Now play
the attacker and take a copy of the envelope. No keys, only the stored file. In
a second terminal:

```sh
cp data/envelopes/record-0001.envelope data/harvested.envelope
```

Time passes. The defenders do everything right: they move to ML-KEM and re-wrap.

```
[RSA-TOY-96] > use ML-KEM-768
[ML-KEM-768] > rewrap
[ML-KEM-768] > crack 1
  record-0001 (ML-KEM-768)
    not attempted: this is not RSA, so there is no modulus to factor.
```

The stored record is safe now. The copy is not:

```
[ML-KEM-768] > crack data/harvested.envelope
  data/harvested.envelope (RSA-TOY-96)
    public key: n = 45113622079573034424233906421 (96 bits), e = 65537
    factoring n with Pollard's rho, using only the public key...
    factored in 3.1 s: n = 187612018428161 x 240462324871261
    data key unwrapped with the rebuilt private key
    plaintext -> the merger closes on Friday
```

`crack` reads `data/keys/rsa-toy.pub` and the envelope, and nothing else. Read
`CrackCommand.java` and `Factoring.java` to see all of it: factor the modulus,
rebuild the private exponent, unwrap the data key, decrypt.

Two things to take from this:

- **Re-wrapping protects what you still hold, not what was already copied.** The
  AES-256-GCM data in the harvested file was never attacked. It fell because the
  key next to it was wrapped with something that later broke.
- **The clock starts when the data is exposed, not when the algorithm breaks.**
  Anything that has to stay secret for ten years needed a post-quantum wrap
  before it was first stored or sent.

To feel the difference key length makes, change `MODULUS_BITS` in
`ToyRsaWrapper.java`. Each extra 8 bits makes the factoring roughly four times
slower. The algorithm name follows the constant, so at 104 bits it becomes
`RSA-TOY-104`. Delete `data/keys/rsa-toy.key` afterwards so a new key is
generated; records already wrapped with the old one will stop reading.

## 8. Take inventory

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
to its algorithm and marked as a KEK, and a property lists which records each algorithm protects.
Because it is a standard format, other CBOM tools can read it.

Where the facts come from: each wrapper describes itself through a `facts()`
method from the `Inventoried` interface, so they live in the same class as the
algorithm. `KeyWrapper` itself still has its three methods. The records that make
up the file are in `cbom/CycloneDx.java`, a small slice of the full CycloneDX
format; the official `cyclonedx-core-java` library models all of it.

Then close the loop: `use ML-KEM-768`, `rewrap`, and `cbom` again. The last line
turns green. That is the shape of a real migration: inventory, move, and
inventory again to prove it.

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
