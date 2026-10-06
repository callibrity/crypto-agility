package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Inventoried;

import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Hybrid: classical X25519 and post-quantum ML-KEM-768 together. The key that
 * wraps the DEK is derived from BOTH shared secrets, so an attacker has to
 * break both algorithms to recover it. This is the hedge to reach for while
 * ML-KEM is still young.
 *
 * <p>It is also a "one more class" example: this file and one registry line are
 * all it took to add it. It stores both an ephemeral X25519 key and an ML-KEM
 * ciphertext, a combination no other wrapper has, and nothing outside this
 * class had to learn about it.
 *
 * <p>Illustrative only. It shows the shape of a hybrid, but it is NOT the X-Wing
 * construction and has had no review. In production, use a vetted hybrid KEM.
 */
public final class HybridWrapper implements KeyWrapper, Inventoried {

    public static final String ALG_ID = "X25519+ML-KEM-768";

    private static final String EPHEMERAL_KEY = "ephemeralKey";
    private static final String KEM_CT = "kemCt";
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
    public String algId() { return ALG_ID; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        // Classical half: a fresh X25519 key pair, agreed against our static public key.
        KeyPair ephemeral = newX25519KeyPair();
        byte[] ephemeralPub = ephemeral.getPublic().getEncoded();
        byte[] classicalSecret = agree(ephemeral.getPrivate(), x25519.getPublic());

        // Post-quantum half: ML-KEM encapsulation, exactly as in MlKemWrapper.
        KEM.Encapsulated enc = kem.newEncapsulator(mlKem.getPublic()).encapsulate();

        SecretKey kek = deriveKek(classicalSecret, enc.key(), ephemeralPub, enc.encapsulation());
        Map<String, byte[]> kemFields = new LinkedHashMap<>();
        kemFields.put(EPHEMERAL_KEY, ephemeralPub);
        kemFields.put(KEM_CT, enc.encapsulation());
        return AesGcmKeyWrap.wrap(kek, dek, kemFields);
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        byte[] ephemeralPub = w.require(EPHEMERAL_KEY, algId());
        byte[] mlKemCt = w.require(KEM_CT, algId());

        PublicKey ephemeral = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(ephemeralPub));
        byte[] classicalSecret = agree(x25519.getPrivate(), ephemeral);
        SecretKey pqSecret = kem.newDecapsulator(mlKem.getPrivate()).decapsulate(mlKemCt);

        return AesGcmKeyWrap.unwrap(deriveKek(classicalSecret, pqSecret, ephemeralPub, mlKemCt), w, algId());
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
        var info = new ByteArrayOutputStream();
        info.writeBytes(KDF_LABEL);
        info.writeBytes(ephemeralPub);
        info.writeBytes(mlKemCt);
        var hkdf = KDF.getInstance("HKDF-SHA256");
        var params = HKDFParameterSpec.ofExtract()
                .addIKM(classicalSecret)
                .addIKM(pqSecret)
                .thenExpand(info.toByteArray(), 32);
        return hkdf.deriveKey("AES", params);
    }

    // An attacker must break both halves, so it is at least as strong as ML-KEM-768, the stronger of the two.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("combiner", 192, 3, "keygen", "encapsulate", "decapsulate", "keyderive")
                .withParameterSet("768").withCurve("x25519");
    }

    @Override
    public String provider() {
        return Providers.names(() -> kem.newEncapsulator(mlKem.getPublic()).providerName(),
                () -> KeyAgreement.getInstance("X25519").getProvider().getName(),
                () -> KDF.getInstance("HKDF-SHA256").getProviderName());
    }
}
