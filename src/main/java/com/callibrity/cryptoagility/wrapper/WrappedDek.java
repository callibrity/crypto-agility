package com.callibrity.cryptoagility.wrapper;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;

/**
 * A wrapped data key, as whatever named fields the wrapping algorithm needs.
 *
 * <p>The envelope does not know or care what the fields are. RSA produces one
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

    // A map of arrays compares its values by identity, so equality and hashing are spelled out to compare bytes.
    @Override
    public boolean equals(Object other) {
        if (!(other instanceof WrappedDek that) || !fields.keySet().equals(that.fields.keySet())) {
            return false;
        }
        for (Map.Entry<String, byte[]> field : fields.entrySet()) {
            if (!Arrays.equals(field.getValue(), that.fields.get(field.getKey()))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        for (Map.Entry<String, byte[]> field : fields.entrySet()) {
            hash += field.getKey().hashCode() ^ Arrays.hashCode(field.getValue());
        }
        return hash;
    }

    /** The field names and their sizes, never the bytes themselves. */
    @Override
    public String toString() {
        var out = new StringJoiner(", ", "WrappedDek[", "]");
        fields.forEach((name, value) -> out.add(name + "=" + value.length + " bytes"));
        return out.toString();
    }
}
