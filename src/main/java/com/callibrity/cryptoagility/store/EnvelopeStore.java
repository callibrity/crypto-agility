package com.callibrity.cryptoagility.store;

import com.callibrity.cryptoagility.envelope.Envelope;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Envelopes on disk, one small text file each. Open one: the first line is the
 * algorithm that wrapped it, stored right next to the data it protects.
 */
public final class EnvelopeStore {

    private static final String SUFFIX = ".envelope";

    /** An envelope together with the id it is stored under. */
    public record Stored(String id, Envelope envelope) {}

    private final Path dir;

    public EnvelopeStore(Path dir) {
        this.dir = dir;
    }

    /** Stores a new envelope and returns the id it was given. */
    public String add(Envelope envelope) throws IOException {
        int next = ids().size() + 1;
        while (Files.exists(dir.resolve(idOf(next) + SUFFIX))) {
            next++;
        }
        String id = idOf(next);
        put(id, envelope);
        return id;
    }

    /** Writes an envelope under an existing id, replacing what was there. */
    public void put(String id, Envelope envelope) throws IOException {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("alg", envelope.alg());
        fields.put("nonce", KeyValueFile.encode(envelope.nonce()));
        fields.put("ciphertext", KeyValueFile.encode(envelope.ciphertext()));
        fields.put("wrappedKey", KeyValueFile.encode(envelope.wrappedKey()));
        if (envelope.kemCt() != null) {
            fields.put("kemCt", KeyValueFile.encode(envelope.kemCt()));
        }
        if (envelope.wrapNonce() != null) {
            fields.put("wrapNonce", KeyValueFile.encode(envelope.wrapNonce()));
        }
        KeyValueFile.write(dir.resolve(id + SUFFIX), fields);
    }

    /** Every stored envelope, oldest first. */
    public List<Stored> all() throws IOException {
        List<Stored> stored = new ArrayList<>();
        for (String id : ids()) {
            stored.add(new Stored(id, load(dir.resolve(id + SUFFIX))));
        }
        return stored;
    }

    private static String idOf(int number) {
        return String.format("record-%04d", number);
    }

    private List<String> ids() throws IOException {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.map(file -> file.getFileName().toString())
                    .filter(name -> name.endsWith(SUFFIX))
                    .map(name -> name.substring(0, name.length() - SUFFIX.length()))
                    .sorted()
                    .toList();
        }
    }

    /** Reads one envelope file, wherever it is. A copied envelope is as good as the original. */
    public static Envelope load(Path file) throws IOException {
        Map<String, String> fields = KeyValueFile.read(file);
        return new Envelope(
                fields.get("alg"),
                KeyValueFile.decode(file, "nonce", fields.get("nonce")),
                KeyValueFile.decode(file, "ciphertext", fields.get("ciphertext")),
                KeyValueFile.decode(file, "wrappedKey", fields.get("wrappedKey")),
                optional(file, "kemCt", fields),
                optional(file, "wrapNonce", fields));
    }

    private static byte[] optional(Path file, String field, Map<String, String> fields) throws IOException {
        return fields.containsKey(field) ? KeyValueFile.decode(file, field, fields.get(field)) : null;
    }
}
