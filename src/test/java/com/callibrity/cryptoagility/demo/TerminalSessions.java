package com.callibrity.cryptoagility.demo;

import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * In-memory terminals for driving the prompt and the scripted player in tests:
 * typed input in, screen out. Native terminal support is switched off, so JLine
 * works on the streams directly instead of opening a real pseudo-terminal.
 */
final class TerminalSessions {

    private TerminalSessions() {}

    /** A plain terminal with no cursor control, like an IDE's run window. */
    static Terminal dumb(String typed, ByteArrayOutputStream screen) throws IOException {
        return TerminalBuilder.builder()
                .system(false)
                .ffm(false)
                .jni(false)
                .streams(new ByteArrayInputStream(typed.getBytes(UTF_8)), screen)
                .type(Terminal.TYPE_DUMB)
                .build();
    }

    /**
     * A full terminal, like a real one on stage, with a presenter at the
     * keyboard who presses each key only once the next prompt is showing.
     */
    static Terminal full(String keys, ByteArrayOutputStream screen) throws IOException {
        return TerminalBuilder.builder()
                .system(false)
                .ffm(false)
                .jni(false)
                .streams(new Presenter(keys, screen), screen)
                .type("xterm")
                .build();
    }

    // Presses key n only after the screen shows its n-th prompt, then runs out.
    private static final class Presenter extends InputStream {

        private static final String PROMPT = "] > ";
        private static final long PATIENCE_MILLIS = 10_000;

        private final String keys;
        private final ByteArrayOutputStream screen;
        private int pressed;

        Presenter(String keys, ByteArrayOutputStream screen) {
            this.keys = keys;
            this.screen = screen;
        }

        @Override
        public int read() throws IOException {
            if (pressed >= keys.length()) {
                return -1;
            }
            long deadline = System.currentTimeMillis() + PATIENCE_MILLIS;
            while (prompts() <= pressed) {
                if (System.currentTimeMillis() > deadline) {
                    throw new IOException("no prompt appeared for key " + (pressed + 1));
                }
                pause();
            }
            return keys.charAt(pressed++);
        }

        private int prompts() {
            String shown = text(screen);
            return shown.split(Pattern.quote(PROMPT), -1).length - 1;
        }

        private static void pause() throws IOException {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while waiting for a prompt", e);
            }
        }
    }

    static String text(ByteArrayOutputStream screen) {
        return screen.toString(UTF_8);
    }
}
