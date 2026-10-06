package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.cbom.AlgorithmFacts;
import com.callibrity.cryptoagility.cbom.Inventoried;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;

/**
 * Classical, quantum-vulnerable: elliptic-curve Diffie-Hellman on X25519. This
 * is the other half of today's public-key crypto. It is far smaller and faster
 * than RSA, and Shor's algorithm breaks it just the same.
 *
 * <p>It goes through the same KEM API as ML-KEM (the JDK calls this one DHKEM,
 * from RFC 9180). Compare this file with MlKemWrapper: swapping a classical KEM
 * for a post-quantum one is a change of two strings.
 */
public final class EcdhWrapper implements KeyWrapper, Inventoried {

    public static final String ALG_ID = "ECDH-X25519";

    // What a DH-based KEM sends across is a one-time public key.
    private static final String EPHEMERAL_KEY = "ephemeralKey";

    private final KeyPair kp;
    private final KEM kem;

    public EcdhWrapper() throws GeneralSecurityException {
        this(newKeyPair());
    }

    public EcdhWrapper(KeyPair kp) throws GeneralSecurityException {
        this.kem = KEM.getInstance("DHKEM");
        this.kp = kp;
    }

    public static KeyPair newKeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    @Override
    public String algId() { return ALG_ID; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate(0, 32, "AES");
        return AesGcmKeyWrap.wrap(enc.key(), dek, Map.of(EPHEMERAL_KEY, enc.encapsulation()));
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        SecretKey kek = kem.newDecapsulator(kp.getPrivate()).decapsulate(w.require(EPHEMERAL_KEY, ALG_ID), 0, 32, "AES");
        return AesGcmKeyWrap.unwrap(kek, w, ALG_ID);
    }

    // About 128 bits against a classical attacker. Shor's algorithm breaks elliptic curves too.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("kem", 128, 0, "keygen", "encapsulate", "decapsulate")
                .withCurve("x25519").withOid("1.3.101.110");
    }

    @Override
    public String provider() {
        return Providers.names(() -> kem.newEncapsulator(kp.getPublic()).providerName());
    }
}
