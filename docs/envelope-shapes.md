# Envelope encryption: the general shape, and how the real tools do it

## The general shape (every implementation has these four parts)

1. **Data key (DEK).** A fresh random symmetric key encrypts the actual data, almost always AES-GCM. This is the part quantum doesn't threaten, so it never has to change.
2. **The wrap (KEK).** Something encrypts the DEK. That "something" is the key-encrypting key, and it can be symmetric (held in a KMS/HSM), asymmetric (RSA, ECDH), or a KEM (ML-KEM). This is the layer that's quantum-vulnerable, and the layer you rotate.
3. **The envelope.** The ciphertext and the wrapped DEK stored together, plus the metadata needed to open it: the algorithm identifier(s), the IV/nonce, the auth tag, and usually some associated data or context.
4. **The algorithm identifier.** The load-bearing part. Because the envelope records which algorithm wrapped it, old data still opens with the old algorithm while new data uses the new one. That is the agility seam. Everything else is plumbing.

Real formats add optional extras on top: multiple wrapped DEKs (multi-recipient, multi-region), associated data / encryption context, an integrity signature, key commitment, and framing for large payloads.

## Same skeleton, different bytes

| | How the DEK is wrapped | Where the KEK lives | Serialized as | Algorithm named by | Notable extras |
|---|---|---|---|---|---|
| **Homegrown** (the demo) | RSA-OAEP, ML-KEM or a hybrid, pluggable | key files on disk (demo only) | ad-hoc text file | an `alg` field | none, it exists to show the skeleton |
| **Google Tink** | KMS-wrapped DEK (envelope AEAD) | your cloud KMS / HSM | Tink keyset + key-ID-prefixed ciphertext | keyset key type + key ID prefix | key rotation, associated data, cross-language, hard-to-misuse API |
| **AWS Encryption SDK** | one or more KMS keys (keyrings) | AWS KMS (HSM) | a documented binary message format | an algorithm suite ID in the header | multiple data keys (multi-region), encryption context, key commitment, ECDSA signature, framing |
| **JWE** (RFC 7516) | `alg` (RSA-OAEP, ECDH-ES+A256KW, …) | your choice (JWK, KMS) | compact `hdr.key.iv.ct.tag`, or JSON | `alg` + `enc` in the JOSE header | web/token-native; JSON form allows multiple recipients; mind the JOSE foot-guns |
| **CMS EnvelopedData** (RFC 5652) | per-recipient RecipientInfo (RSA / ECDH / KEM) | your PKI / keystore | ASN.1 / DER binary | AlgorithmIdentifier OIDs | S/MIME and PKI interop, multi-recipient, now KEM/PQC-capable (RFC 9629, 9936) |

## The line that carries it

Different bytes, one skeleton, and every one of them writes the algorithm into the envelope. That is not decoration. It is the single thing that lets you change algorithms without a flag day.

So the guidance: don't hand-roll, and don't hardcode. For most shops that means a KMS plus Tink or the AWS Encryption SDK. Reach for JWE when the envelope is a token crossing a boundary, and CMS when a standard makes you. The homegrown format in the demo is only there to show the skeleton with nothing hiding it.

---

## Where PQC support actually is today (verified 30 Sept 2026)

The blunt version: **you cannot yet wrap a data key with ML-KEM through a GA managed KMS.** Signatures and PKI standards are basically done; the ML-KEM protocol bindings and the managed key-wrapping SDKs are not. That gap is the whole argument for building the seam now.

**Managed key services and envelope SDKs (what you'd actually use):**
- **AWS Encryption SDK / Database Encryption SDK:** no post-quantum algorithm suite. Every suite is AES-GCM + HKDF + optional ECDSA. ([suite reference](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html))
- **AWS KMS:** no PQ key spec for wrapping. ML-KEM shows up only as hybrid PQ-TLS on the *connection* to KMS (GA Apr 2025). ML-DSA signatures are GA (Jun 2025). So the transport can be quantum-safe; the wrap can't.
- **Google Cloud KMS:** ML-KEM (768/1024) as KEMs is **Preview** (since Sep 2025), recommending the X-Wing hybrid. ML-DSA/SLH-DSA signing went GA Jul 2026. This is the closest thing to managed ML-KEM wrapping, and it's still Preview.
- **Google Tink:** ML-DSA/SLH-DSA signing available (C++/Go, Java in progress); the ML-KEM/KEM API is under development, not GA.
- **Azure Key Vault, HashiCorp Vault transit:** PQC in preview/roadmap. Not verified here; check their own docs.

**Crypto libraries (ahead of the managed services — you can build it by hand today):**
- **JDK 24+:** ML-KEM (JEP 496) and ML-DSA (JEP 497) native. **JDK 27:** hybrid TLS X25519MLKEM768 on by default (JEP 527). No native HQC/SLH-DSA/FN-DSA yet.
- **OpenSSL 3.5 LTS** (Apr 2025): ML-KEM, ML-DSA, SLH-DSA, GA, PQC groups on by default.
- **BouncyCastle 1.86** (Sep 2026): ML-KEM, ML-DSA, SLH-DSA, HQC, Falcon.

**Standards:**
- **CMS:** RFC 9629 (KEMRecipientInfo, 2024) + RFC 9936 (ML-KEM in CMS, Mar 2026), both published. The one envelope standard that's already PQC-complete.
- **X.509:** ML-DSA in certificates is RFC 9881 (Oct 2025) and ML-KEM in certificates is RFC 9935 (Mar 2026), both published.
- **JOSE/COSE:** ML-KEM and ML-DSA are still IETF drafts.
- **TLS:** X25519MLKEM768 and the other hybrid key exchanges are RFC 10024 (2026), and deployed across browsers, CDNs, and JDK 27.
- **NIST:** FIPS 203/204/205 finalized Aug 2024. FIPS 206 (FN-DSA) still draft. HQC selected, draft FIPS in progress.

**The short version:** today your TLS connection to the KMS can already be quantum-safe, and PQ signatures are GA, but wrapping your data keys with ML-KEM through a managed KMS is Preview at best. The libraries have the primitives; the managed tooling doesn't. That's the argument in one breath: the teams who win are the ones whose wrapping is behind a seam, so they flip it on the day their KMS ships it, instead of re-architecting.

*These statuses move quickly. Worth re-checking before you rely on them: GCP KMS ML-KEM (Preview → GA?), Tink KEM API, NIST FIPS 206, the JOSE/COSE drafts, and the Azure/Vault items (unverified here).*
