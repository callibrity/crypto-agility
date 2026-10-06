package com.callibrity.cryptoagility.kms;

import java.security.GeneralSecurityException;

/** Thrown when asked to use a key that has been disabled. The key still exists; it just will not work. */
public class KeyDisabledException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    public KeyDisabledException(String message) {
        super(message);
    }
}
