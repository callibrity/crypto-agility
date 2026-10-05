package com.callibrity.cryptoagility.envelope;

import java.util.Base64;

/**
 * The stored envelope: the AES-256-GCM ciphertext, the wrapped data key, and
 * the name of the algorithm that wrapped it. The alg field is the load-bearing
 * part: it says which wrapper understands the fields of the wrapped key.
 */
public record Envelope(String alg, byte[] nonce, byte[] ciphertext, WrappedDek wrappedDek) {

    /** A one-line description for printing; the raw bytes are abbreviated. */
    public String summary() {
        var out = new StringBuilder("{alg=").append(alg)
                .append(", ciphertext=").append(Base64.getEncoder().encodeToString(ciphertext), 0, 16).append("...");
        wrappedDek.fields().forEach((name, value) ->
                out.append(", ").append(name).append('=').append(value.length).append(" bytes"));
        return out.append('}').toString();
    }
}
