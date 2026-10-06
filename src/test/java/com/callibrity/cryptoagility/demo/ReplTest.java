package com.callibrity.cryptoagility.demo;

import com.callibrity.cryptoagility.command.Workspace;
import org.jline.terminal.Terminal;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ReplTest {

    @TempDir
    Path dataDir;

    private String session(String typed) throws IOException {
        var screen = new ByteArrayOutputStream();
        try (Terminal terminal = TerminalSessions.dumb(typed, screen)) {
            Repl.run(new Workspace(dataDir), terminal);
        }
        return TerminalSessions.text(screen);
    }

    @Nested
    class In_a_session {

        @Test
        void greets_and_shows_the_current_algorithm_in_the_prompt() throws IOException {
            String screen = session("exit\n");

            assertTrue(screen.contains("Crypto agility demo"));
            assertTrue(screen.contains("[RSA-OAEP-3072] > "));
        }

        @Test
        void the_prompt_follows_use() throws IOException {
            String screen = session("use ML-KEM-768\nexit\n");

            assertTrue(screen.contains("[ML-KEM-768] > "));
        }

        @Test
        void commands_run_and_their_output_reaches_the_screen() throws IOException {
            String screen = session("write customer record #1\nread\nexit\n");

            assertTrue(screen.contains("saved record-0001"));
            assertTrue(screen.contains("record-0001 (RSA-OAEP-3072) -> customer record #1"));
        }

        @Test
        void text_is_taken_as_typed() throws IOException {
            String screen = session("write don't panic! \\o/\nread\nexit\n");

            assertTrue(screen.contains("-> don't panic! \\o/"));
        }
    }

    @Nested
    class Leaving {

        @Test
        void ends_at_the_end_of_input_without_exit() throws IOException {
            String screen = session("write customer record #1\n");

            assertTrue(screen.contains("saved record-0001"));
        }

        @Test
        void exit_stops_before_later_lines_run() throws IOException {
            String screen = session("exit\nwrite never written\n");

            assertEquals(-1, screen.indexOf("saved"));
        }
    }
}
