package com.callibrity.cryptoagility.envelope;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Every algorithm this system can still read, keyed by the name envelopes
 * carry. Decryption looks the wrapper up here, so an algorithm stays readable
 * for exactly as long as it stays registered.
 */
public final class WrapperRegistry {

    private final Map<String, KeyWrapper> wrappers = new LinkedHashMap<>();

    public WrapperRegistry register(KeyWrapper wrapper) {
        wrappers.put(wrapper.algId(), wrapper);
        return this;
    }

    public KeyWrapper get(String algId) throws UnknownAlgorithmException {
        KeyWrapper wrapper = wrappers.get(algId);
        if (wrapper == null) {
            throw new UnknownAlgorithmException(
                    "no wrapper registered for " + algId + " (registered: " + wrappers.keySet() + ")");
        }
        return wrapper;
    }

    /**
     * Stops reading an algorithm. Anything still wrapped with it becomes
     * unreadable, which is why you rewrap first and retire second.
     */
    public KeyWrapper retire(String algId) throws UnknownAlgorithmException {
        KeyWrapper wrapper = get(algId);
        wrappers.remove(algId);
        return wrapper;
    }

    public Set<String> algIds() {
        return Collections.unmodifiableSet(wrappers.keySet());
    }
}
