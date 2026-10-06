package com.callibrity.cryptoagility.command;

/** A command was given something it cannot work with. The message is shown to the person at the prompt. */
public final class UsageException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UsageException(String message) {
        super(message);
    }
}
