package com.callibrity.cryptoagility.cipher;

/**
 * What kind of data key to generate: the JCA key algorithm and its size. A KMS
 * only needs this to produce the right number of random bytes; it never sees
 * the data, so it does not care which cipher will use the key.
 */
public record DataKeySpec(String algorithm, int bits) {

    public static final DataKeySpec AES_256 = new DataKeySpec("AES", 256);
    public static final DataKeySpec CHACHA20 = new DataKeySpec("ChaCha20", 256);

    public int bytes() {
        return bits / 8;
    }
}
