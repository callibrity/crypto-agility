package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/** Post-quantum: ML-KEM encapsulates a shared secret; we AES-wrap the DEK with it. */
public final class MlKemWrapper implements KeyWrapper {

    private final KeyPair kp;
    private final KEM kem;

    public MlKemWrapper() throws GeneralSecurityException {
        this(newKeyPair());
    }

    public MlKemWrapper(KeyPair kp) throws GeneralSecurityException {
        this.kem = KEM.getInstance("ML-KEM");                    // family name; the key sets the 768 param set
        this.kp = kp;
    }

    public static KeyPair newKeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
    }

    @Override
    public String algId() { return "ML-KEM-768"; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        KEM.Encapsulator e = kem.newEncapsulator(kp.getPublic());
        KEM.Encapsulated enc = e.encapsulate(0, 32, "AES");      // 32-byte AES key from the KEM
        return AesGcmKeyWrap.wrap(enc.key(), dek, enc.encapsulation());
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        AesGcmKeyWrap.requireKemFields(w, algId());
        KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate());
        SecretKey kek = d.decapsulate(w.kemCt(), 0, 32, "AES");
        return AesGcmKeyWrap.unwrap(kek, w);
    }
}
