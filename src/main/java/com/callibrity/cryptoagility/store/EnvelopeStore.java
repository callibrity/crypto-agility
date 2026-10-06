package com.callibrity.cryptoagility.store;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.WrappedDek;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Envelopes on disk, one small text file each. Open one: the first line is the
 * algorithm that wrapped it, stored right next to the data it protects. After
 * the nonce and ciphertext come the fields of the wrapped key, which differ
 * from one algorithm to the next.
 */
public final class EnvelopeStore {

    private static final String SUFFIX = ".envelope";
    private static final String ALG = "alg";
    private static final String NONCE = "nonce";
    private static final String CIPHERTEXT = "ciphertext";
    private static final Set<String> RESERVED = Set.of(ALG, NONCE, CIPHERTEXT);

    /**
     * An envelope together with the id it is stored under. A file that can no
     * longer be parsed has no envelope, only a problem saying what is wrong.
     */
    public record Stored(String id, Envelope envelope, String problem) {

        public Stored(String id, Envelope envelope) {
            this(id, envelope, null);
        }

        public boolean damaged() {
            return envelope == null;
        }
    }

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
        fields.put(ALG, envelope.alg());
        fields.put(NONCE, KeyValueFile.encode(envelope.nonce()));
        fields.put(CIPHERTEXT, KeyValueFile.encode(envelope.ciphertext()));
        // Whatever the wrapper produced is stored as it comes. The store never needs to know the names.
        envelope.wrappedDek().fields().forEach((name, value) -> {
            if (RESERVED.contains(name)) {
                throw new IllegalArgumentException("a wrapped key cannot have a field called " + name);
            }
            fields.put(name, KeyValueFile.encode(value));
        });
        KeyValueFile.write(dir.resolve(id + SUFFIX), fields);
    }

    /** Every stored envelope, oldest first. */
    // One damaged file is reported as damaged; it does not stop the rest from loading.
    public List<Stored> all() throws IOException {
        List<Stored> stored = new ArrayList<>();
        for (String id : ids()) {
            try {
                stored.add(new Stored(id, load(dir.resolve(id + SUFFIX))));
            } catch (IOException e) {
                stored.add(new Stored(id, null, e.getMessage()));
            }
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
        Map<String, byte[]> wrapFields = new LinkedHashMap<>();
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (!RESERVED.contains(field.getKey())) {
                wrapFields.put(field.getKey(), KeyValueFile.decode(file, field.getKey(), field.getValue()));
            }
        }
        return new Envelope(
                fields.get(ALG),
                KeyValueFile.decode(file, NONCE, fields.get(NONCE)),
                KeyValueFile.decode(file, CIPHERTEXT, fields.get(CIPHERTEXT)),
                new WrappedDek(wrapFields));
    }
}
