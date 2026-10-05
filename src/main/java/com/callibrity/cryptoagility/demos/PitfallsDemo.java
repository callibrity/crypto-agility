package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import com.callibrity.cryptoagility.wrappers.HybridWrapper;
import com.callibrity.cryptoagility.wrappers.MlKemWrapper;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;

import java.security.GeneralSecurityException;
import java.util.List;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.rewrap;
import static java.nio.charset.StandardCharsets.UTF_8;

/** Two ways an algorithm change goes wrong, made runnable. Everything here is in memory. */
final class PitfallsDemo {

    private PitfallsDemo() {}

    static void run() throws GeneralSecurityException {
        var rsa = new RsaWrapper();
        var mlkem = new MlKemWrapper();
        var hybrid = new HybridWrapper();

        noAlgorithmInTheEnvelope(rsa, mlkem, hybrid);
        retiringTooEarly(rsa, mlkem);
    }

    // Pitfall 1: ciphertext that doesn't say how it was encrypted.
    private static void noAlgorithmInTheEnvelope(KeyWrapper rsa, KeyWrapper mlkem, KeyWrapper hybrid)
            throws GeneralSecurityException {
        System.out.println("Pitfall 1: an envelope that doesn't say how it was wrapped\n");

        Envelope full = encrypt("customer record #1 (written last year)".getBytes(UTF_8), rsa);
        Envelope anonymous = new Envelope(null, full.nonce(), full.ciphertext(), full.wrappedDek());
        System.out.println("  Last year: wrapped with " + rsa.algId() + ", stored with no algorithm name.");
        System.out.println("  Today:     crypto.wrap = " + mlkem.algId() + ", so the reader assumes " + mlkem.algId() + ".");
        System.out.println("    -> " + open(anonymous, mlkem));

        System.out.println("\n  The only way back in is to guess, trying every algorithm you have ever used:");
        for (KeyWrapper guess : List.of(mlkem, hybrid, rsa)) {
            System.out.printf("    %-18s -> %s%n", guess.algId(), open(anonymous, guess));
        }
        System.out.println("\n  Guessing works only while you remember every algorithm you ever used.");
        System.out.println("  With the name in the envelope, it is one lookup.");
    }

    // Pitfall 2: retiring an algorithm while data still depends on it.
    private static void retiringTooEarly(KeyWrapper rsa, KeyWrapper mlkem) throws GeneralSecurityException {
        System.out.println("\nPitfall 2: retiring an algorithm before its data has moved\n");

        Envelope v1 = encrypt("customer record #1 (written last year)".getBytes(UTF_8), rsa);
        Envelope v2 = encrypt("customer record #2 (written today)".getBytes(UTF_8), mlkem);
        var both = new WrapperRegistry().register(rsa).register(mlkem);
        var rsaRetired = new WrapperRegistry().register(mlkem);

        System.out.println("  " + rsa.algId() + " removed from the registry while v1 still uses it:");
        System.out.println("    v1 -> " + open(v1, rsaRetired));
        System.out.println("    v2 -> " + open(v2, rsaRetired));

        System.out.println("\n  The right order is rewrap first, then retire:");
        Envelope moved = rewrap(v1, both, mlkem);
        System.out.println("    v1 re-wrapped " + v1.alg() + " -> " + moved.alg() + " while both were registered");
        System.out.println("    v1 -> " + open(moved, rsaRetired));

        System.out.println("\n  You can only retire an algorithm once nothing is still wrapped with it,");
        System.out.println("  and you can only know that if every envelope names its algorithm.");
    }

    private static String open(Envelope env, WrapperRegistry registry) {
        try {
            return new String(decrypt(env, registry), UTF_8);
        } catch (GeneralSecurityException e) {
            return "UNREADABLE: " + e.getMessage();
        }
    }

    // Opens an envelope by assuming an algorithm instead of reading it from the envelope.
    private static String open(Envelope env, KeyWrapper assumed) {
        Envelope labelled = new Envelope(assumed.algId(), env.nonce(), env.ciphertext(), env.wrappedDek());
        return open(labelled, new WrapperRegistry().register(assumed));
    }
}
