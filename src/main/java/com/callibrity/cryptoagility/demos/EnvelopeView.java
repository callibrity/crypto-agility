package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.Envelope;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

/**
 * Draws an envelope as a box in the terminal. It only looks at what is stored;
 * nothing is decrypted, and no key is needed to see which algorithm was used.
 */
final class EnvelopeView {

    private static final int GCM_TAG_BYTES = 16;
    private static final String KEY_TITLE = "wrapped data key (the algorithm-dependent part)";
    private static final String DATA_TITLE = "data (always AES-256-GCM)";

    private EnvelopeView() {}

    static String render(String id, Envelope env) {
        List<String> key = new ArrayList<>();
        if (env.kemCt() != null) {
            key.add(row("kemCt", env.kemCt(), "KEM ciphertext, recovers the wrapping key"));
        }
        if (env.wrapNonce() != null) {
            key.add(row("wrapNonce", env.wrapNonce(), "nonce for the key wrap"));
        }
        key.add(row("wrappedKey", env.wrappedKey(), "the AES-256 data key, encrypted"));

        List<String> data = List.of(
                row("nonce", env.nonce(), "nonce for the data"),
                row("ciphertext", env.ciphertext(),
                        (env.ciphertext().length - GCM_TAG_BYTES) + " bytes of data + " + GCM_TAG_BYTES + "-byte tag"));

        String alg = String.format("%-11s %-22s %s", "alg", env.alg() == null ? "(none)" : env.alg(),
                "in the clear, says how to open the key");

        // Wide enough for the longest row, and for each title plus a little rule after it.
        int width = Stream.concat(
                        Stream.concat(Stream.of(alg), Stream.concat(key.stream(), data.stream())).map(String::length),
                        Stream.of(id, KEY_TITLE, DATA_TITLE).map(title -> title.length() + 2))
                .mapToInt(Integer::intValue).max().orElseThrow();

        var out = new StringBuilder();
        out.append(rule('┌', id, '┐', width));
        out.append(content(alg, width));
        out.append(rule('├', KEY_TITLE, '┤', width));
        key.forEach(line -> out.append(content(line, width)));
        out.append(rule('├', DATA_TITLE, '┤', width));
        data.forEach(line -> out.append(content(line, width)));
        out.append(rule('└', "", '┘', width));
        return out.toString();
    }

    private static String row(String name, byte[] bytes, String note) {
        String start = Base64.getEncoder().encodeToString(bytes);
        start = start.length() > 8 ? start.substring(0, 8) + "…" : start;
        return String.format("%-11s %5d bytes  %-9s %s", name, bytes.length, start, note);
    }

    private static String content(String line, int width) {
        return "│ " + line + " ".repeat(width - line.length()) + " │\n";
    }

    private static String rule(char left, String title, char right, int width) {
        String label = title.isEmpty() ? "" : "─ " + title + " ";
        return left + label + "─".repeat(width + 2 - label.length()) + right + "\n";
    }
}
