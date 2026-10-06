package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.wrapper.WrappedDek;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * The stored envelope. Two layers, each named, using the same header names as
 * JWE (JSON Web Encryption):
 *
 * <ul>
 *   <li>alg and kid say how the data key was wrapped, and which KMS key opens it.
 *   <li>enc says which cipher encrypted the data with that data key.
 * </ul>
 *
 * <p>The names are what let old and new data live side by side: every envelope
 * says how to open itself, so nothing has to be migrated on the day the
 * algorithm changes.
 */
public record Envelope(String alg, String kid, String enc, byte[] nonce, byte[] ciphertext,
                       WrappedDek wrappedDek) {

    /** A one-line description for printing; the raw bytes are abbreviated. */
    public String summary() {
        var out = new StringBuilder("{alg=").append(alg)
                .append(", kid=").append(kid)
                .append(", enc=").append(enc)
                .append(", ciphertext=").append(Base64.getEncoder().encodeToString(ciphertext), 0, 16).append("...");
        wrappedDek.fields().forEach((name, value) ->
                out.append(", ").append(name).append('=').append(value.length).append(" bytes"));
        return out.append('}').toString();
    }

    // Records compare arrays by identity, so equality and hashing are spelled out to compare their bytes.
    @Override
    public boolean equals(Object other) {
        return other instanceof Envelope that
                && Objects.equals(alg, that.alg)
                && Objects.equals(kid, that.kid)
                && Objects.equals(enc, that.enc)
                && Arrays.equals(nonce, that.nonce)
                && Arrays.equals(ciphertext, that.ciphertext)
                && Objects.equals(wrappedDek, that.wrappedDek);
    }

    @Override
    public int hashCode() {
        return Objects.hash(alg, kid, enc, Arrays.hashCode(nonce), Arrays.hashCode(ciphertext), wrappedDek);
    }

    /** The names and sizes, never the bytes themselves. */
    @Override
    public String toString() {
        return "Envelope[alg=" + alg + ", kid=" + kid + ", enc=" + enc
                + ", nonce=" + size(nonce) + ", ciphertext=" + size(ciphertext) + ", wrappedDek=" + wrappedDek + "]";
    }

    private static String size(byte[] bytes) {
        return bytes == null ? "null" : bytes.length + " bytes";
    }
}
