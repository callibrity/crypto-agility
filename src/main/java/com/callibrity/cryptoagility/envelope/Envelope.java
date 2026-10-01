package com.callibrity.cryptoagility.envelope;

import java.util.Base64;

/**
 * The stored envelope: the AES-256-GCM ciphertext, the wrapped data key, and
 * the name of the algorithm that wrapped it. The alg field is the load-bearing
 * part. kemCt and wrapNonce are only used by KEM-based wrappers.
 */
public record Envelope(String alg, byte[] nonce, byte[] ciphertext,
                       byte[] wrappedKey, byte[] kemCt, byte[] wrapNonce) {

    public WrappedDek wrappedDek() {
        return new WrappedDek(wrappedKey, kemCt, wrapNonce);
    }

    /** A one-line description for printing; the raw bytes are abbreviated. */
    public String summary() {
        String ct = Base64.getEncoder().encodeToString(ciphertext).substring(0, 16);
        return String.format("{alg=%s, ciphertext=%s..., wrappedKey=%d bytes%s}",
                alg, ct, wrappedKey.length, kemCt == null ? "" : ", kemCt=" + kemCt.length + " bytes");
    }
}
