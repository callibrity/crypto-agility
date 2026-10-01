package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Hybrid: classical X25519 and post-quantum ML-KEM-768 together. The key that
 * wraps the DEK is derived from BOTH shared secrets, so an attacker has to
 * break both algorithms to recover it. This is the hedge to reach for while
 * ML-KEM is still young.
 *
 * It is also the "one more class" example: this file and one registry line are
 * all it took to add a third algorithm. No call site changed.
 *
 * Illustrative only. It shows the shape of a hybrid, but it is NOT the X-Wing
 * construction and has had no review. In production, use a vetted hybrid KEM.
 */
public final class HybridWrapper implements KeyWrapper {

    private static final int ML_KEM_768_CT_LENGTH = 1088;
    private static final byte[] KDF_LABEL = "crypto-agility-demo hybrid wrap v1".getBytes(UTF_8);

    private final KeyPair x25519;
    private final KeyPair mlKem;
    private final KEM kem;

    public HybridWrapper() throws GeneralSecurityException {
        this(newX25519KeyPair(), MlKemWrapper.newKeyPair());
    }

    public HybridWrapper(KeyPair x25519, KeyPair mlKem) throws GeneralSecurityException {
        this.kem = KEM.getInstance("ML-KEM");
        this.x25519 = x25519;
        this.mlKem = mlKem;
    }

    public static KeyPair newX25519KeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    @Override
    public String algId() { return "X25519+ML-KEM-768"; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        // Classical half: a fresh X25519 key pair, agreed against our static public key.
        KeyPair ephemeral = newX25519KeyPair();
        byte[] ephemeralPub = ephemeral.getPublic().getEncoded();
        byte[] classicalSecret = agree(ephemeral.getPrivate(), x25519.getPublic());

        // Post-quantum half: ML-KEM encapsulation, exactly as in MlKemWrapper.
        KEM.Encapsulated enc = kem.newEncapsulator(mlKem.getPublic()).encapsulate();

        SecretKey kek = deriveKek(classicalSecret, enc.key(), ephemeralPub, enc.encapsulation());
        return AesGcmKeyWrap.wrap(kek, dek, concat(ephemeralPub, enc.encapsulation()));
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        AesGcmKeyWrap.requireKemFields(w, algId());
        int split = w.kemCt().length - ML_KEM_768_CT_LENGTH;
        if (split <= 0) {
            throw new InvalidKeyException("KEM ciphertext is too short to have been wrapped with " + algId());
        }
        byte[] ephemeralPub = Arrays.copyOfRange(w.kemCt(), 0, split);
        byte[] mlKemCt = Arrays.copyOfRange(w.kemCt(), split, w.kemCt().length);

        PublicKey ephemeral = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(ephemeralPub));
        byte[] classicalSecret = agree(x25519.getPrivate(), ephemeral);
        SecretKey pqSecret = kem.newDecapsulator(mlKem.getPrivate()).decapsulate(mlKemCt);

        return AesGcmKeyWrap.unwrap(deriveKek(classicalSecret, pqSecret, ephemeralPub, mlKemCt), w);
    }

    private static byte[] agree(PrivateKey mine, PublicKey theirs) throws GeneralSecurityException {
        var ka = KeyAgreement.getInstance("X25519");
        ka.init(mine);
        ka.doPhase(theirs, true);
        return ka.generateSecret();
    }

    // HKDF over both secrets. The public values go into the info so the key is bound to this exchange.
    private static SecretKey deriveKek(byte[] classicalSecret, SecretKey pqSecret, byte[] ephemeralPub, byte[] mlKemCt)
            throws GeneralSecurityException {
        var hkdf = KDF.getInstance("HKDF-SHA256");
        var params = HKDFParameterSpec.ofExtract()
                .addIKM(classicalSecret)
                .addIKM(pqSecret)
                .thenExpand(concat(KDF_LABEL, ephemeralPub, mlKemCt), 32);
        return hkdf.deriveKey("AES", params);
    }

    private static byte[] concat(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
