package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;
import com.callibrity.cryptoagility.wrappers.ToyRsaWrapper;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.NoSuchFileException;
import java.security.GeneralSecurityException;
import java.util.List;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Plays the attacker. It has the envelope and the public key, and never reads
 * a private key. For an envelope wrapped with the toy RSA key that is enough:
 * factor the modulus, rebuild the private key, unwrap the data key, read the data.
 *
 * This is a classical attack on a deliberately tiny key. It stands in for what
 * Shor's algorithm on a large quantum computer would do to real RSA.
 */
final class CrackCommand {

    private CrackCommand() {}

    static void run(String record) throws GeneralSecurityException, IOException {
        List<Stored> targets = StoreCommands.select(record);
        WrapperRegistry stolen = null;
        for (Stored target : targets) {
            Envelope env = target.envelope();
            System.out.printf("%s (%s)%n", target.id(), env.alg());
            if (!ToyRsaWrapper.ALG_ID.equals(env.alg())) {
                System.out.println("  not attempted: " + whyNot(env.alg()) + "\n");
                continue;
            }
            if (stolen == null) {
                stolen = new WrapperRegistry().register(new ToyRsaWrapper(recoverKeys()));
            }
            System.out.println("  data key unwrapped with the rebuilt private key");
            System.out.println("  plaintext -> " + new String(decrypt(env, stolen), UTF_8) + "\n");
        }
        if (stolen != null) {
            System.out.println("That was a classical attack on a deliberately tiny key. Real RSA-3072 is safe");
            System.out.println("from a laptop, but Shor's algorithm on a large quantum computer would do the same to it.");
        }
    }

    private static ToyRsaWrapper.Keys recoverKeys() throws IOException {
        ToyRsaWrapper.PublicKey publicKey = publicKey();
        BigInteger n = publicKey.modulus();
        System.out.printf("  public key: n = %s (%d bits), e = %s%n", n, n.bitLength(), publicKey.exponent());
        System.out.println("  factoring n with Pollard's rho, using only the public key...");
        long start = System.nanoTime();
        BigInteger p = Factoring.findFactor(n);
        double seconds = (System.nanoTime() - start) / 1e9;
        System.out.printf("  factored in %.1f s: n = %s x %s%n", seconds, p, n.divide(p));
        return ToyRsaWrapper.Keys.fromFactor(publicKey, p);
    }

    private static ToyRsaWrapper.PublicKey publicKey() throws IOException {
        try {
            return Workspace.toyRsaPublicKey();
        } catch (NoSuchFileException e) {
            Demo.fail("the toy public key is missing from data/keys, so there is nothing to factor");
            throw e;
        }
    }

    private static String whyNot(String alg) {
        if (RsaWrapper.ALG_ID.equals(alg)) {
            return "a 3072-bit modulus is far beyond a laptop. It is not beyond Shor's algorithm.";
        }
        return "this is not RSA, so there is no modulus to factor.";
    }
}
