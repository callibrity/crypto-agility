package com.callibrity.cryptoagility.demos;

/** A command was given something it cannot work with. The message is shown to the person at the prompt. */
final class UsageException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    UsageException(String message) {
        super(message);
    }
}
