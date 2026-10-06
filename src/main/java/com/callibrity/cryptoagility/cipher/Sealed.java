package com.callibrity.cryptoagility.cipher;

import java.util.Arrays;

/**
 * What an authenticated cipher produces: the nonce it used, and the ciphertext
 * with its tag. Two are equal when their bytes are, and toString shows sizes
 * rather than bytes.
 */
public record Sealed(byte[] nonce, byte[] ciphertext) {

    @Override
    public boolean equals(Object other) {
        return other instanceof Sealed that
                && Arrays.equals(nonce, that.nonce)
                && Arrays.equals(ciphertext, that.ciphertext);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(nonce) + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
        return "Sealed[nonce=" + size(nonce) + ", ciphertext=" + size(ciphertext) + "]";
    }

    private static String size(byte[] bytes) {
        return bytes == null ? "null" : bytes.length + " bytes";
    }
}
