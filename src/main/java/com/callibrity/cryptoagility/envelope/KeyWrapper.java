package com.callibrity.cryptoagility.envelope;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

/**
 * The seam. Swap the implementation, never the call sites.
 *
 * Everything that depends on the choice of algorithm lives behind these three
 * methods. To support a new algorithm, write one more implementation and
 * register it; nothing that calls encrypt or decrypt has to change.
 */
public interface KeyWrapper {

    /** The name written into every envelope this wrapper produces. */
    String algId();

    WrappedDek wrap(SecretKey dek) throws GeneralSecurityException;

    SecretKey unwrap(WrappedDek w) throws GeneralSecurityException;
}
