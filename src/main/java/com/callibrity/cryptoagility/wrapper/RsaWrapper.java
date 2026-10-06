package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Inventoried;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;

/** Classical, quantum-vulnerable: RSA-OAEP wraps the data key directly. */
public final class RsaWrapper implements KeyWrapper, Inventoried {

    public static final String ALG_ID = "RSA-OAEP-3072";

    private static final String WRAPPED_KEY = "wrappedKey";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";

    // Spelled out, because the JDK's "OAEPWithSHA-256AndMGF1Padding" quietly uses SHA-1 inside MGF1, and other
    // libraries read that name as SHA-256 throughout. An algorithm name that means different things to different
    // readers is its own agility problem.
    private static final OAEPParameterSpec OAEP_SHA256 =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private final KeyPair kp;

    public RsaWrapper() throws GeneralSecurityException {
        this(newKeyPair());
    }

    public RsaWrapper(KeyPair kp) {
        this.kp = kp;
    }

    public static KeyPair newKeyPair() throws GeneralSecurityException {
        var g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072);
        return g.generateKeyPair();
    }

    @Override
    public String algId() { return ALG_ID; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.WRAP_MODE, kp.getPublic(), OAEP_SHA256);
        return WrappedDek.of(WRAPPED_KEY, c.wrap(dek));
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.UNWRAP_MODE, kp.getPrivate(), OAEP_SHA256);
        return (SecretKey) c.unwrap(w.require(WRAPPED_KEY, ALG_ID), "AES", Cipher.SECRET_KEY);
    }

    // Classical security of RSA-3072 is about 128 bits. A quantum computer running Shor's algorithm breaks it outright.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("pke", 128, 0, "keygen", "encrypt", "decrypt")
                .withParameterSet("3072").withPadding("oaep").withOid("1.2.840.113549.1.1.7");
    }

    @Override
    public String provider() {
        return Providers.names(() -> Cipher.getInstance(TRANSFORMATION).getProvider().getName());
    }
}
