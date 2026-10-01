import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Crypto agility via envelope encryption, in ~120 lines of plain JCA.
 *
 * The data is ALWAYS AES-256-GCM (quantum is fine with that). The only
 * algorithm-dependent step is how the data key (DEK) gets wrapped, and that
 * lives behind one interface: KeyWrapper. Each envelope records which algorithm
 * wrapped it, so you can read yesterday's RSA-wrapped data while writing
 * today's ML-KEM-wrapped data. Swapping algorithms is a config change, not a
 * rewrite, and no bulk data is ever re-encrypted.
 *
 * Runs on JDK 24+ with no dependencies (ML-KEM is built in: JEP 496).
 * On JDK 21-23, add BouncyCastle and register it as a provider; the KEM API
 * (JEP 452) is already there. See README.
 */
public class EnvelopeDemo {

    private static final SecureRandom RNG = new SecureRandom();

    // The stored envelope. kemCt/wrapNonce are only used by KEM-based wrappers.
    record Envelope(String alg, byte[] nonce, byte[] ciphertext,
                    byte[] wrappedKey, byte[] kemCt, byte[] wrapNonce) {}

    // The seam. Swap the implementation, never the call sites.
    interface KeyWrapper {
        String algId();
        WrappedDek wrap(SecretKey dek) throws GeneralSecurityException;
        SecretKey unwrap(WrappedDek w) throws GeneralSecurityException;
    }
    record WrappedDek(byte[] wrappedKey, byte[] kemCt, byte[] wrapNonce) {}

    // Classical, quantum-vulnerable: RSA-OAEP wraps the data key directly.
    static final class RsaWrapper implements KeyWrapper {
        private final KeyPair kp;
        RsaWrapper() throws GeneralSecurityException {
            var g = KeyPairGenerator.getInstance("RSA");
            g.initialize(3072);
            this.kp = g.generateKeyPair();
        }
        public String algId() { return "RSA-OAEP-3072"; }
        public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
            var c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.WRAP_MODE, kp.getPublic());
            return new WrappedDek(c.wrap(dek), null, null);
        }
        public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
            var c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.UNWRAP_MODE, kp.getPrivate());
            return (SecretKey) c.unwrap(w.wrappedKey(), "AES", Cipher.SECRET_KEY);
        }
    }

    // Post-quantum: ML-KEM encapsulates a shared secret; we AES-wrap the DEK with it.
    static final class MlKemWrapper implements KeyWrapper {
        private final KeyPair kp;
        private final KEM kem;
        MlKemWrapper() throws GeneralSecurityException {
            this.kem = KEM.getInstance("ML-KEM");                // family name; the key sets the 768 param set (JDK 24+ native; older: BouncyCastle)
            var g = KeyPairGenerator.getInstance("ML-KEM-768");
            this.kp = g.generateKeyPair();
        }
        public String algId() { return "ML-KEM-768"; }
        public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
            KEM.Encapsulator e = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated enc = e.encapsulate(0, 32, "AES");  // 32-byte AES key from the KEM
            byte[] nonce = randomBytes(12);
            var c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.WRAP_MODE, enc.key(), new GCMParameterSpec(128, nonce));
            return new WrappedDek(c.wrap(dek), enc.encapsulation(), nonce);
        }
        public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
            KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate());
            SecretKey kek = d.decapsulate(w.kemCt(), 0, 32, "AES");
            var c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.UNWRAP_MODE, kek, new GCMParameterSpec(128, w.wrapNonce()));
            return (SecretKey) c.unwrap(w.wrappedKey(), "AES", Cipher.SECRET_KEY);
        }
    }

    // Envelope encryption: DEK is always AES-256-GCM; only the wrap step varies.
    static Envelope encrypt(byte[] plaintext, KeyWrapper wrapper) throws GeneralSecurityException {
        var kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey dek = kg.generateKey();
        byte[] nonce = randomBytes(12);
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(128, nonce));
        byte[] ct = c.doFinal(plaintext);
        WrappedDek w = wrapper.wrap(dek);                        // the only algorithm-dependent line
        return new Envelope(wrapper.algId(), nonce, ct, w.wrappedKey(), w.kemCt(), w.wrapNonce());
    }

    static byte[] decrypt(Envelope env, Map<String, KeyWrapper> registry) throws GeneralSecurityException {
        KeyWrapper wrapper = registry.get(env.alg());           // each envelope names its own algorithm
        SecretKey dek = wrapper.unwrap(new WrappedDek(env.wrappedKey(), env.kemCt(), env.wrapNonce()));
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(128, env.nonce()));
        return c.doFinal(env.ciphertext());
    }

    public static void main(String[] args) throws Exception {
        var registry = new HashMap<String, KeyWrapper>();

        // Today's config: classical RSA.
        var rsa = new RsaWrapper();
        registry.put(rsa.algId(), rsa);
        System.out.println("config: crypto.wrap = " + rsa.algId());
        Envelope v1 = encrypt("customer record #1 (written last year)".getBytes(UTF_8), rsa);
        show("v1", v1);

        // One-line config change: swap the wrap algorithm to post-quantum.
        var mlkem = new MlKemWrapper();
        registry.put(mlkem.algId(), mlkem);
        System.out.println("\nconfig: crypto.wrap = " + mlkem.algId() + "   (one line)\n");
        Envelope v2 = encrypt("customer record #2 (written today)".getBytes(UTF_8), mlkem);
        show("v2", v2);

        // Decrypt both. No flag day: each envelope carries its own algorithm.
        System.out.println("\nDecrypt both, no migration window:");
        System.out.println("  v1 (" + v1.alg() + ")  -> " + new String(decrypt(v1, registry), UTF_8));
        System.out.println("  v2 (" + v2.alg() + ")       -> " + new String(decrypt(v2, registry), UTF_8));

        System.out.println("\nOld data still reads, new data is post-quantum, the code never changed.");
    }

    // --- tiny helpers ---
    static byte[] randomBytes(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }
    static void show(String label, Envelope e) {
        var b64 = Base64.getEncoder();
        System.out.printf("  %s envelope: {alg=%s, ciphertext=%s..., wrappedKey=%d bytes%s}%n",
                label, e.alg(), b64.encodeToString(e.ciphertext()).substring(0, 16),
                e.wrappedKey().length, e.kemCt() == null ? "" : ", kemCt=" + e.kemCt().length + " bytes");
    }
}
