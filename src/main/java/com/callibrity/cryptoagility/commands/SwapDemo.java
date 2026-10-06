package com.callibrity.cryptoagility.commands;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import com.callibrity.cryptoagility.wrappers.MlKemWrapper;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;

import java.io.PrintWriter;
import java.security.GeneralSecurityException;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The demo from the talk, entirely in memory: encrypt under RSA, swap the wrap
 * algorithm to ML-KEM, encrypt again, and decrypt both.
 */
public final class SwapDemo {

    private SwapDemo() {}

    public static void run(PrintWriter out) throws GeneralSecurityException {
        var registry = new WrapperRegistry();

        // Today's config: classical RSA.
        var rsa = new RsaWrapper();
        registry.register(rsa);
        out.println("config: crypto.wrap = " + rsa.algId());
        Envelope v1 = encrypt("customer record #1 (written last year)".getBytes(UTF_8), rsa);
        out.println("  v1 envelope: " + v1.summary());

        // One-line config change: swap the wrap algorithm to post-quantum.
        var mlkem = new MlKemWrapper();
        registry.register(mlkem);
        out.println("\nconfig: crypto.wrap = " + mlkem.algId() + "   (one line)\n");
        Envelope v2 = encrypt("customer record #2 (written today)".getBytes(UTF_8), mlkem);
        out.println("  v2 envelope: " + v2.summary());

        // Decrypt both. No flag day: each envelope carries its own algorithm.
        out.println("\nDecrypt both, no migration window:");
        out.println("  v1 (" + v1.alg() + ")  -> " + new String(decrypt(v1, registry), UTF_8));
        out.println("  v2 (" + v2.alg() + ")       -> " + new String(decrypt(v2, registry), UTF_8));

        out.println("\nOld data still reads, new data is post-quantum, the code never changed.");
    }
}
