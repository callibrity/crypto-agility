package com.callibrity.cryptoagility.commands;

import com.callibrity.cryptoagility.envelope.Envelope;

import java.util.Base64;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * Draws an envelope in the terminal: the algorithm name on the outside, then
 * the wrapped data key, then the data that key opens. The bars compare field
 * sizes. It only looks at what is stored; nothing is decrypted, and no key is
 * needed to see which algorithm was used.
 */
public final class EnvelopeView {

    private static final int GCM_TAG_BYTES = 16;
    private static final int BYTES_PER_BLOCK = 64;
    private static final int BAR_WIDTH = 26;
    private static final int PREVIEW_WIDTH = 9;
    private static final String PARTIAL_BLOCKS = " ▏▎▍▌▋▊▉";
    private static final String ALG_NOTE = "in the clear, no key needed";
    private static final String ARROW = "▼ yields the AES-256 data key";
    private static final int MAX_ALG_WIDTH = 24;

    private EnvelopeView() {}

    static String render(String id, Envelope env) {
        Map<String, byte[]> wrap = env.wrappedDek().fields();
        String alg = env.alg() == null ? "(none)" : fit(env.alg(), MAX_ALG_WIDTH);

        int nameWidth = wrap.keySet().stream().mapToInt(String::length).max().orElse(0);
        nameWidth = Math.max(nameWidth, "ciphertext".length() + 2);
        int rowWidth = nameWidth + 1 + "00000 bytes".length() + 2 + BAR_WIDTH + 2 + PREVIEW_WIDTH;
        int boxWidth = rowWidth + 6;                             // an inner box: border, two spaces, row, two spaces, border
        int width = boxWidth + 4;                                // the envelope: border, space, inner box, space, border

        int stored = env.nonce().length + env.ciphertext().length
                + wrap.values().stream().mapToInt(value -> value.length).sum();
        String total = stored + " bytes";

        var out = new StringBuilder();
        out.append(Paint.bold(id)).append(" ".repeat(width - id.length() - total.length())).append(total).append('\n');
        out.append("╭─ envelope ").append("─".repeat(width - 13)).append("╮\n");

        String algLine = "  alg  " + alg;
        out.append("│").append("  alg  ").append(Paint.bold(alg))
                .append(" ".repeat(Math.max(1, width - 4 - algLine.length() - ALG_NOTE.length())))
                .append(Paint.faint(ALG_NOTE)).append("  │\n");
        out.append(envelopeLine("", width, text -> text));

        // The wrap fields are drawn as they come. Only the wrapper named by alg knows what they mean.
        String opener = env.alg() == null ? "the envelope does not say what opens this" : "opened by the " + alg + " key";
        out.append(envelopeLine(boxTop("wrapped data key", opener, boxWidth), width, Paint::yellow));
        for (Map.Entry<String, byte[]> field : wrap.entrySet()) {
            out.append(row(field.getKey(), field.getValue(), nameWidth, width, Paint::yellow));
        }
        int arrowAt = boxWidth / 2;
        out.append(envelopeLine("└" + "─".repeat(arrowAt - 1) + "┬" + "─".repeat(boxWidth - arrowAt - 2) + "┘",
                width, Paint::yellow));
        out.append(envelopeLine(" ".repeat(arrowAt) + ARROW, width, text -> text));

        out.append(envelopeLine(boxTop("data", "always AES-256-GCM", boxWidth), width, Paint::cyan));
        out.append(row("nonce", env.nonce(), nameWidth, width, Paint::cyan));
        out.append(row("ciphertext", env.ciphertext(), nameWidth, width, Paint::cyan));
        String sizes = (env.ciphertext().length - GCM_TAG_BYTES) + " bytes of data + " + GCM_TAG_BYTES + "-byte tag";
        String note = " ".repeat(nameWidth + 1) + sizes;
        out.append("│ ").append(Paint.cyan("│")).append("  ").append(Paint.faint(note))
                .append(" ".repeat(rowWidth - note.length())).append("  ").append(Paint.cyan("│")).append(" │\n");
        out.append(envelopeLine("└" + "─".repeat(boxWidth - 2) + "┘", width, Paint::cyan));

        out.append("╰").append("─".repeat(width - 2)).append("╯\n");
        return out.toString();
    }

    /** One field: its name, its size, a bar in proportion to the size, and its first few bytes. */
    private static String row(String name, byte[] value, int nameWidth, int width, UnaryOperator<String> colour) {
        String bar = bar(value.length);
        String preview = preview(value);
        return "│ " + colour.apply("│") + "  "
                + String.format("%-" + nameWidth + "s %5d bytes  ", name, value.length)
                + colour.apply(bar) + " ".repeat(BAR_WIDTH - bar.length()) + "  "
                + Paint.faint(preview) + " ".repeat(PREVIEW_WIDTH - preview.length())
                + "  " + colour.apply("│") + " │\n";
    }

    /** One full block per 64 bytes, in eighths, and never empty. A + marks a bar too long to draw. */
    private static String bar(int bytes) {
        int eighths = Math.max(1, Math.round(bytes * 8f / BYTES_PER_BLOCK));
        if (eighths > BAR_WIDTH * 8) {
            return "█".repeat(BAR_WIDTH - 1) + "+";
        }
        String partial = eighths % 8 == 0 ? "" : String.valueOf(PARTIAL_BLOCKS.charAt(eighths % 8));
        return "█".repeat(eighths / 8) + partial;
    }

    private static String preview(byte[] value) {
        String start = Base64.getEncoder().encodeToString(value);
        return start.length() > PREVIEW_WIDTH - 1 ? start.substring(0, PREVIEW_WIDTH - 1) + "…" : start;
    }

    private static String boxTop(String title, String note, int boxWidth) {
        String left = "┌─ " + title + " ";
        String right = " " + note + " ─┐";
        return left + "─".repeat(Math.max(1, boxWidth - left.length() - right.length())) + right;
    }

    /** A line of the envelope's interior, padded to the envelope's width and closed with its border. */
    private static String envelopeLine(String content, int width, UnaryOperator<String> colour) {
        return "│ " + colour.apply(content) + " ".repeat(width - 3 - content.length()) + "│\n";
    }

    // A hand-edited algorithm name can be any length; shorten it rather than break the box.
    private static String fit(String text, int width) {
        return text.length() <= width ? text : text.substring(0, width - 1) + "…";
    }
}
