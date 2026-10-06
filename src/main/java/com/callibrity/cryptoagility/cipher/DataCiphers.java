package com.callibrity.cryptoagility.cipher;

import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Every data cipher this system can read, keyed by the name envelopes carry. */
public final class DataCiphers {

    /** What new data is encrypted with unless asked otherwise. */
    public static final DataCipher DEFAULT = AesGcm.INSTANCE;

    private static final Map<String, DataCipher> CIPHERS = new LinkedHashMap<>();

    static {
        register(AesGcm.INSTANCE);
        register(ChaCha20Poly1305.INSTANCE);
    }

    private DataCiphers() {}

    private static void register(DataCipher cipher) {
        CIPHERS.put(cipher.algId(), cipher);
    }

    public static boolean contains(String algId) {
        return CIPHERS.containsKey(algId);
    }

    public static DataCipher get(String algId) throws UnknownAlgorithmException {
        DataCipher cipher = CIPHERS.get(algId);
        if (cipher == null) {
            throw new UnknownAlgorithmException("no data cipher called " + algId + " (known: " + CIPHERS.keySet() + ")");
        }
        return cipher;
    }

    public static List<DataCipher> all() {
        return List.copyOf(CIPHERS.values());
    }
}
