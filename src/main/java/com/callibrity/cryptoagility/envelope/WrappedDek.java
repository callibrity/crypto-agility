package com.callibrity.cryptoagility.envelope;

/**
 * A wrapped data key. kemCt and wrapNonce are only used by KEM-based wrappers;
 * RSA-OAEP wraps the key directly and leaves them null.
 */
public record WrappedDek(byte[] wrappedKey, byte[] kemCt, byte[] wrapNonce) {}
