package com.callibrity.cryptoagility.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.stream.Stream;

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
    private final List<String> touched = new ArrayList<>();

    public DemoKeys(Path dir) {
        this.dir = dir;
    }

    /** Loads the named key pair, generating and saving it first if it does not exist yet. */
    public KeyPair keyPair(String name, Generator generator) throws GeneralSecurityException, IOException {
        Path file = dir.resolve(name + ".keypair");
        touched.add(file.getFileName().toString());
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

    /**
     * Loads a key kept as plain named fields, generating and saving it first if
     * it does not exist yet. For keys the JDK has no encoding for.
     */
    public Map<String, String> fields(String fileName, Supplier<Map<String, String>> generator) throws IOException {
        Path file = dir.resolve(fileName);
        touched.add(fileName);
        if (!Files.exists(file)) {
            KeyValueFile.write(file, generator.get());
        }
        return KeyValueFile.read(file);
    }

    /** Every key file and its fields, by file name. Empty before any key has been generated. */
    public Map<String, Map<String, String>> all() throws IOException {
        Map<String, Map<String, String>> files = new TreeMap<>();
        if (Files.isDirectory(dir)) {
            try (Stream<Path> paths = Files.list(dir)) {
                for (Path file : paths.toList()) {
                    files.put(file.getFileName().toString(), KeyValueFile.read(file));
                }
            }
        }
        return files;
    }

    /** Reads a file of named fields that must already exist. */
    public Map<String, String> read(String fileName) throws IOException {
        return KeyValueFile.read(dir.resolve(fileName));
    }

    /** Writes a file of named fields, replacing what was there. */
    public void write(String fileName, Map<String, String> fields) throws IOException {
        touched.add(fileName);
        KeyValueFile.write(dir.resolve(fileName), fields);
    }

    /**
     * The key files loaded or written since the last call. Calling this after
     * building each wrapper tells you which files belong to which algorithm.
     */
    public List<String> takeTouched() {
        List<String> files = List.copyOf(touched);
        touched.clear();
        return files;
    }
}
