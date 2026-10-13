/*
 * Copyright © 2026 Callibrity, Inc. (contactus@callibrity.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.envelope.Envelope;
import java.util.Base64;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * Draws an envelope in the terminal: the algorithm name on the outside, then the wrapped data key,
 * then the data that key opens. The bars compare field sizes. It only looks at what is stored;
 * nothing is decrypted, and no key is needed to see which algorithm was used.
 */
public final class EnvelopeView {

  private static final int TAG_BYTES = 16; // both AES-GCM and ChaCha20-Poly1305 add 16
  private static final int BYTES_PER_BLOCK = 64;
  private static final int BAR_WIDTH = 26;
  private static final int PREVIEW_WIDTH = 9;
  private static final String PARTIAL_BLOCKS = " ▏▎▍▌▋▊▉";
  private static final String ARROW = "▼ the KMS unwraps the data key";
  private static final int MAX_ALG_WIDTH = 24;

  private EnvelopeView() {}

  static String render(String id, Envelope env) {
    Map<String, byte[]> wrap = env.wrappedDek().fields();
    String alg = env.alg() == null ? "(none)" : fit(env.alg(), MAX_ALG_WIDTH);

    int nameWidth = wrap.keySet().stream().mapToInt(String::length).max().orElse(0);
    nameWidth = Math.max(nameWidth, "ciphertext".length() + 2);
    int rowWidth = nameWidth + 1 + "00000 bytes".length() + 2 + BAR_WIDTH + 2 + PREVIEW_WIDTH;
    int boxWidth = rowWidth + 6; // an inner box: border, two spaces, row, two spaces, border
    int width = boxWidth + 4; // the envelope: border, space, inner box, space, border

    int stored =
        env.nonce().length
            + env.ciphertext().length
            + wrap.values().stream().mapToInt(value -> value.length).sum();
    String total = stored + " bytes";

    var out = new StringBuilder();
    out.append(Paint.bold(id))
        .append(" ".repeat(width - id.length() - total.length()))
        .append(total)
        .append('\n');
    out.append("╭─ envelope ").append("─".repeat(width - 13)).append("╮\n");

    // The header, in the clear: enough to know how to open the envelope without opening it.
    out.append(header("alg", alg, "how the data key is wrapped", width));
    out.append(header("kid", orNone(env.kid()), "which KMS key unwraps it", width));
    out.append(
        header("enc", fit(orNone(env.enc()), MAX_ALG_WIDTH), "how the data is encrypted", width));
    out.append(envelopeLine("", width, text -> text));

    // The wrap fields are drawn as they come. Only the wrapper named by alg knows what they mean.
    String opener =
        env.alg() == null
            ? "the envelope does not say what opens this"
            : "opened by the " + alg + " key";
    out.append(envelopeLine(boxTop("wrapped data key", opener, boxWidth), width, Paint::yellow));
    for (Map.Entry<String, byte[]> field : wrap.entrySet()) {
      out.append(row(field.getKey(), field.getValue(), nameWidth, Paint::yellow));
    }
    int arrowAt = boxWidth / 2;
    out.append(
        envelopeLine(
            "└" + "─".repeat(arrowAt - 1) + "┬" + "─".repeat(boxWidth - arrowAt - 2) + "┘",
            width,
            Paint::yellow));
    out.append(envelopeLine(" ".repeat(arrowAt) + ARROW, width, text -> text));

    out.append(
        envelopeLine(
            boxTop("data", "encrypted with " + fit(orNone(env.enc()), MAX_ALG_WIDTH), boxWidth),
            width,
            Paint::cyan));
    out.append(row("nonce", env.nonce(), nameWidth, Paint::cyan));
    out.append(row("ciphertext", env.ciphertext(), nameWidth, Paint::cyan));
    String sizes =
        (env.ciphertext().length - TAG_BYTES) + " bytes of data + " + TAG_BYTES + "-byte tag";
    String note = " ".repeat(nameWidth + 1) + sizes;
    out.append("│ ")
        .append(Paint.cyan("│"))
        .append("  ")
        .append(Paint.faint(note))
        .append(" ".repeat(rowWidth - note.length()))
        .append("  ")
        .append(Paint.cyan("│"))
        .append(" │\n");
    out.append(envelopeLine("└" + "─".repeat(boxWidth - 2) + "┘", width, Paint::cyan));

    out.append("╰").append("─".repeat(width - 2)).append("╯\n");
    return out.toString();
  }

  /** One field: its name, its size, a bar in proportion to the size, and its first few bytes. */
  private static String row(
      String name, byte[] value, int nameWidth, UnaryOperator<String> colour) {
    String bar = bar(value.length);
    String preview = preview(value);
    return "│ "
        + colour.apply("│")
        + "  "
        + name
        + " ".repeat(nameWidth - name.length())
        + String.format(" %5d bytes  ", value.length)
        + colour.apply(bar)
        + " ".repeat(BAR_WIDTH - bar.length())
        + "  "
        + Paint.faint(preview)
        + " ".repeat(PREVIEW_WIDTH - preview.length())
        + "  "
        + colour.apply("│")
        + " │\n";
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

  /**
   * A line of the envelope's interior, padded to the envelope's width and closed with its border.
   */
  private static String envelopeLine(String content, int width, UnaryOperator<String> colour) {
    return "│ " + colour.apply(content) + " ".repeat(width - 3 - content.length()) + "│\n";
  }

  // A hand-edited algorithm name can be any length; shorten it rather than break the box.
  private static String fit(String text, int width) {
    return text.length() <= width ? text : text.substring(0, width - 1) + "…";
  }

  private static String header(String name, String value, String note, int width) {
    String plain = String.format("  %-8s %s", name, value);
    return "│"
        + String.format("  %-8s ", name)
        + Paint.bold(value)
        + " ".repeat(Math.max(1, width - 4 - plain.length() - note.length()))
        + Paint.faint(note)
        + "  │\n";
  }

  private static String orNone(String value) {
    return value == null ? "(none)" : value;
  }
}
