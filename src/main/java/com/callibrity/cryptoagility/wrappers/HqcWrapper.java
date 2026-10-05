package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Inventoried;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrappedDek;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Map;

/**
 * Post-quantum, from a different family of mathematics. ML-KEM rests on
 * lattices; HQC rests on error-correcting codes. NIST selected it in 2025 as a
 * backup, so that a break in the lattice maths does not leave everyone with
 * nothing. That is the case for agility in one sentence: the day you need this
 * class, you want adding it to be all you have to do.
 *
 * The JDK does not have HQC yet, so it comes from BouncyCastle. Compare this
 * file with MlKemWrapper: the same KEM API, a different provider behind it.
 * The price is size. An HQC-192 ciphertext is about eight times the size of an
 * ML-KEM-768 one.
 *
 * The HQC standard is still a draft, so the details may yet change.
 */
public final class HqcWrapper implements KeyWrapper, Inventoried {

    private static final String KEM_CT = "kemCt";

    static {
        Security.addProvider(new BouncyCastlePQCProvider());    // added last, so the JDK still serves everything it can
    }

    private final KeyPair kp;
    private final KEM kem;

    public HqcWrapper() throws GeneralSecurityException {
        this(newKeyPair());
    }

    public HqcWrapper(KeyPair kp) throws GeneralSecurityException {
        this.kem = KEM.getInstance("HQC");
        this.kp = kp;
    }

    public static KeyPair newKeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("HQC-192").generateKeyPair();
    }

    @Override
    public String algId() { return "HQC-192"; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate(0, 32, "AES");
        return AesGcmKeyWrap.wrap(enc.key(), dek, Map.of(KEM_CT, enc.encapsulation()));
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        SecretKey kek = kem.newDecapsulator(kp.getPrivate()).decapsulate(w.require(KEM_CT, algId()), 0, 32, "AES");
        return AesGcmKeyWrap.unwrap(kek, w, algId());
    }

    // HQC-192 targets NIST category 3, the same as ML-KEM-768. It has no standard OID yet. Until it does,
    // BouncyCastle writes its own into every HQC key, so keys made today will carry an identifier that changes later.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("kem", 192, 3, "keygen", "encapsulate", "decapsulate")
                .withParameterSet("192")
                .withProvisionalOid(BCObjectIdentifiers.hqc192.getId(), "BouncyCastle");
    }

    @Override
    public String provider() {
        return Providers.names(() -> kem.newEncapsulator(kp.getPublic()).providerName());
    }
}
