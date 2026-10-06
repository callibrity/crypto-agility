package com.callibrity.cryptoagility.kms;

import java.security.GeneralSecurityException;

/** Thrown when asked about a key the KMS does not have. */
public class UnknownKeyException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    public UnknownKeyException(String message) {
        super(message);
    }
}
