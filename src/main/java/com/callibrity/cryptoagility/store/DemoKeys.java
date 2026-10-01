package com.callibrity.cryptoagility.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Key pairs kept in plain files so that envelopes written by one run can be
 * read by the next.
 *
 * DEMO ONLY. This stands in for a KMS or HSM. Private keys sit unencrypted on
 * disk here, which is exactly what you must never do with real keys.
 */
public final class DemoKeys {

    /** Creates a key pair the first time a name is asked for. */
    @FunctionalInterface
    public interface Generator {
        KeyPair generate() throws GeneralSecurityException;
    }

    private final Path dir;

    public DemoKeys(Path dir) {
        this.dir = dir;
    }

    /** Loads the named key pair, generating and saving it first if it does not exist yet. */
    public KeyPair keyPair(String name, Generator generator) throws GeneralSecurityException, IOException {
        Path file = dir.resolve(name + ".keypair");
        if (Files.exists(file)) {
            Map<String, String> fields = KeyValueFile.read(file);
            var kf = KeyFactory.getInstance(fields.get("algorithm"));
            return new KeyPair(
                    kf.generatePublic(new X509EncodedKeySpec(KeyValueFile.decode(file, "public", fields.get("public")))),
                    kf.generatePrivate(new PKCS8EncodedKeySpec(KeyValueFile.decode(file, "private", fields.get("private")))));
        }
        KeyPair kp = generator.generate();
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("algorithm", kp.getPublic().getAlgorithm());
        fields.put("public", KeyValueFile.encode(kp.getPublic().getEncoded()));
        fields.put("private", KeyValueFile.encode(kp.getPrivate().getEncoded()));
        KeyValueFile.write(file, fields);
        return kp;
    }
}
