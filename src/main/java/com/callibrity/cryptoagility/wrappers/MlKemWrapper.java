package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Inventoried;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;
import java.util.Map;

/**
 * Post-quantum: ML-KEM encapsulates a shared secret; we AES-wrap the DEK with it.
 *
 * FIPS 203 defines three parameter sets. They differ only in strength and size,
 * so one class covers all three and the parameter set picks the strength. The
 * default is ML-KEM-768, the common middle choice; CNSA 2.0 requires ML-KEM-1024
 * for US national security systems.
 */
public final class MlKemWrapper implements KeyWrapper, Inventoried {

    /** The FIPS 203 parameter sets, each with its NIST security category and standard OID. */
    public enum ParameterSet {
        ML_KEM_512("ML-KEM-512", "512", 128, 1, "2.16.840.1.101.3.4.4.1"),
        ML_KEM_768("ML-KEM-768", "768", 192, 3, "2.16.840.1.101.3.4.4.2"),
        ML_KEM_1024("ML-KEM-1024", "1024", 256, 5, "2.16.840.1.101.3.4.4.3");

        private final String algId;
        private final String size;
        private final int classicalSecurityLevel;
        private final int nistQuantumSecurityLevel;
        private final String oid;

        ParameterSet(String algId, String size, int classicalSecurityLevel, int nistQuantumSecurityLevel, String oid) {
            this.algId = algId;
            this.size = size;
            this.classicalSecurityLevel = classicalSecurityLevel;
            this.nistQuantumSecurityLevel = nistQuantumSecurityLevel;
            this.oid = oid;
        }

        public String algId() {
            return algId;
        }
    }

    private static final String KEM_CT = "kemCt";

    private final ParameterSet parameterSet;
    private final KeyPair kp;
    private final KEM kem;

    public MlKemWrapper() throws GeneralSecurityException {
        this(ParameterSet.ML_KEM_768, newKeyPair(ParameterSet.ML_KEM_768));
    }

    public MlKemWrapper(KeyPair kp) throws GeneralSecurityException {
        this(ParameterSet.ML_KEM_768, kp);
    }

    public MlKemWrapper(ParameterSet parameterSet, KeyPair kp) throws GeneralSecurityException {
        // The name in every envelope comes from parameterSet, so it had better match the key.
        if (kp.getPublic().getParams() instanceof NamedParameterSpec spec && !spec.getName().equals(parameterSet.algId)) {
            throw new InvalidKeyException("an " + spec.getName() + " key cannot be used as " + parameterSet.algId);
        }
        this.kem = KEM.getInstance("ML-KEM");                    // family name; the key fixes the parameter set
        this.parameterSet = parameterSet;
        this.kp = kp;
    }

    public static KeyPair newKeyPair() throws GeneralSecurityException {
        return newKeyPair(ParameterSet.ML_KEM_768);
    }

    public static KeyPair newKeyPair(ParameterSet parameterSet) throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(parameterSet.algId).generateKeyPair();
    }

    @Override
    public String algId() { return parameterSet.algId; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        KEM.Encapsulator e = kem.newEncapsulator(kp.getPublic());
        KEM.Encapsulated enc = e.encapsulate(0, 32, "AES");      // 32-byte AES key from the KEM
        return AesGcmKeyWrap.wrap(enc.key(), dek, Map.of(KEM_CT, enc.encapsulation()));
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate());
        SecretKey kek = d.decapsulate(w.require(KEM_CT, algId()), 0, 32, "AES");
        return AesGcmKeyWrap.unwrap(kek, w, algId());
    }

    // FIPS 203 puts the three parameter sets in NIST categories 1, 3 and 5: about as hard to break as AES-128,
    // AES-192 and AES-256, against classical and quantum attackers alike.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("kem", parameterSet.classicalSecurityLevel, parameterSet.nistQuantumSecurityLevel,
                        "keygen", "encapsulate", "decapsulate")
                .withParameterSet(parameterSet.size)
                .withOid(parameterSet.oid);
    }

    @Override
    public String provider() {
        return Providers.names(() -> kem.newEncapsulator(kp.getPublic()).providerName());
    }
}
