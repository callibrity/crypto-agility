package com.callibrity.cryptoagility.envelope;

/**
 * An algorithm that can describe itself for a cryptographic inventory (a CBOM).
 *
 * Kept apart from KeyWrapper on purpose. The seam stays at three methods, and
 * the facts about an algorithm still live in the one class that implements it.
 */
public interface Inventoried {

    AlgorithmFacts facts();

    /**
     * The JCA provider that does the work, as resolved on this JVM. Usually one
     * that ships with the JDK, such as SunJCE, or BouncyCastle's BCPQC.
     */
    String provider();
}
