package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/** Classical, quantum-vulnerable: RSA-OAEP wraps the data key directly. */
public final class RsaWrapper implements KeyWrapper {

    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

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
    public String algId() { return "RSA-OAEP-3072"; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.WRAP_MODE, kp.getPublic());
        return new WrappedDek(c.wrap(dek), null, null);
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        return (SecretKey) c.unwrap(w.wrappedKey(), "AES", Cipher.SECRET_KEY);
    }
}
