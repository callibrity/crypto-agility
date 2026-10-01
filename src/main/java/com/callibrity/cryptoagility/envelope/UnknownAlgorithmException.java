package com.callibrity.cryptoagility.envelope;

import java.security.GeneralSecurityException;

/** Thrown when an envelope or the configuration names an algorithm nobody registered. */
public class UnknownAlgorithmException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    public UnknownAlgorithmException(String message) {
        super(message);
    }
}
