# Exploring the demo

Six experiments, each a few minutes. They build on each other, but any of them
can be done on its own. Everything you create lives under `data/`, which git
ignores. Delete that directory whenever you want a clean start.

All commands run from the repository root.

## 1. Watch the swap

```sh
./demo swap
```

This is the demo from the talk. Read `SwapDemo.java` next to the output: the
call to `encrypt` is the same line both times, and `decrypt` is never told which
algorithm to use. It finds out from the envelope.

Things to notice in the output:

- The RSA-wrapped key is 384 bytes. The ML-KEM-wrapped key is 48 bytes, plus a
  1088-byte KEM ciphertext. Post-quantum envelopes are bigger.
- The data itself is AES-256-GCM in both cases. Only the wrap changed.

## 2. Change the one line

The `swap` demo does everything in one process. This experiment does it the way
a real system would, across separate runs, with data on disk.

```sh
./demo write "customer record #1"
./demo write "customer record #2"
```

Now open `config/crypto.properties` and change the last line:

```properties
crypto.wrap=ML-KEM-768
```

Write another record and read everything back:

```sh
./demo write "customer record #3"
./demo read
```

```
config: crypto.wrap = ML-KEM-768
  record-0001 (RSA-OAEP-3072) -> customer record #1
  record-0002 (RSA-OAEP-3072) -> customer record #2
  record-0003 (ML-KEM-768) -> customer record #3

Algorithms in use: {ML-KEM-768=1, RSA-OAEP-3072=2}
```

No code changed and nothing was migrated. Open one of the files in
`data/envelopes/` in a text editor: the first line is the algorithm, stored next
to the data it protects. That line is why the old records still read.

The last line of the output is an inventory. In a real system, being able to
answer "which algorithms is our stored data still using?" is the first thing a
migration needs, and you only get it if every envelope names its algorithm.

## 3. Retire an algorithm without re-encrypting the data

Two records are still wrapped with RSA. With `crypto.wrap` still set to
`ML-KEM-768`:

```sh
./demo rewrap
```

```
config: crypto.wrap = ML-KEM-768
  record-0001 RSA-OAEP-3072 -> ML-KEM-768
  record-0002 RSA-OAEP-3072 -> ML-KEM-768
  record-0003 already ML-KEM-768

Re-wrapped 2 data key(s) of 32 bytes each. Re-encrypted 0 of 68 data bytes.
```

Look at `rewrap` in `EnvelopeCrypto.java`. It unwraps the 32-byte data key with
the old algorithm and wraps it with the new one. The ciphertext is carried over
as it is. Compare the `ciphertext=` line of a record before and after to check.

That is the property that makes this practical at scale: moving a terabyte of
data to a new wrapping algorithm costs one small key operation per object, not a
terabyte of re-encryption.

One caveat worth knowing: re-wrapping protects the data key from now on. It does
nothing for copies of the old RSA-wrapped envelope that someone already took.
That is the "harvest now, decrypt later" problem, and it is why starting early
matters.

## 4. Break it on purpose

```sh
./demo pitfalls
```

This runs two failures in memory: an envelope that does not say how it was
wrapped, and an algorithm retired while data still depends on it. Then try some
by hand on your own stored records:

- **Change an envelope's `alg` line** to a different registered algorithm, then
  run `./demo read`. The wrong wrapper is chosen and the unwrap fails.
- **Change one character of a `ciphertext=` line.** AES-GCM is authenticated, so
  the read fails with a tag mismatch rather than returning garbage.
- **Retire an algorithm too early.** Write a record under RSA, then delete the
  `RsaWrapper` line from the `registry` method in `Workspace.java` and run
  `./demo read`. The record is unreadable until you put the line back. Now do it
  in the right order: put the line back, `./demo rewrap`, then remove it.
- **Set `crypto.wrap` to something unknown**, such as `HQC-256`. The error lists
  what is registered.

## 5. Add your own algorithm

The claim is that a new algorithm costs one class, one registry line and one
config line. Check it by adding ML-KEM-1024, the larger parameter set.

1. **One class.** Copy `wrappers/MlKemWrapper.java` to
   `wrappers/MlKem1024Wrapper.java`. Rename the class, and change the two
   `"ML-KEM-768"` strings (the key pair generator and `algId`) to
   `"ML-KEM-1024"`.
2. **One registry line.** In the `registry` method of `demos/Workspace.java`,
   add:

   ```java
   .register(new MlKem1024Wrapper(keys.keyPair("ml-kem-1024", MlKem1024Wrapper::newKeyPair)))
   ```

3. **One config line.** Set `crypto.wrap=ML-KEM-1024` in
   `config/crypto.properties`.

```sh
./demo write "wrapped with my own algorithm"
./demo read
```

The new record reads, and so does everything written before. You did not touch
`EnvelopeCrypto`, the store, or any of the commands.

For something harder, try a wrapper for a different key size of RSA, or one
backed by a library such as BouncyCastle for an algorithm the JDK does not have
yet, such as HQC.

## 6. Read the hybrid

Set `crypto.wrap=X25519+ML-KEM-768`, write a record, and read
`wrappers/HybridWrapper.java`.

A hybrid wraps the data key under a key derived from two shared secrets: one
from a classical algorithm (X25519) and one from a post-quantum algorithm
(ML-KEM). An attacker has to break both. This is the cautious choice while
ML-KEM is new, and it is the approach TLS has taken with X25519MLKEM768.

Notice what it took to add: one class and one registry line. It needed more
bytes in the envelope than either algorithm alone, and the envelope shape
already had room for them.

`HybridWrapper` is here to show the idea. It is not the X-Wing construction and
has had no security review, so treat it as reading material rather than
something to copy.

## Going further

- Run the tests with `./mvnw test`. The test names read as sentences and state
  what the code guarantees. Change something and see which sentence stops being
  true.
- The `alg` field is the only header in this envelope, and nothing authenticates
  it. Real formats protect their headers; JWE, for example, feeds the protected
  header into AES-GCM as associated data. Try adding a key version to the
  envelope and binding the header that way.
- Compare this skeleton with the real formats in
  [envelope-shapes.md](envelope-shapes.md).
