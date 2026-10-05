package com.callibrity.cryptoagility.envelope;

import java.security.InvalidKeyException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A wrapped data key, as whatever named fields the wrapping algorithm needs.
 *
 * The envelope does not know or care what the fields are. RSA produces one
 * (the encrypted key). A KEM produces three. The next algorithm can produce
 * something else, and nothing that stores or carries envelopes has to change.
 * Only the wrapper that wrote the fields reads them back.
 */
public record WrappedDek(Map<String, byte[]> fields) {

    public WrappedDek {
        fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    public static WrappedDek of(String name, byte[] value) {
        return new WrappedDek(Map.of(name, value));
    }

    /** Returns a field the named algorithm cannot do without, or fails saying which one is missing. */
    public byte[] require(String name, String algId) throws InvalidKeyException {
        byte[] value = fields.get(name);
        if (value == null) {
            throw new InvalidKeyException("wrapped key has no " + name + " field, so it was not wrapped with " + algId);
        }
        return value;
    }
}
