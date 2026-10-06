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
package com.callibrity.cryptoagility.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.callibrity.cryptoagility.command.Workspace;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jline.terminal.Terminal;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ScriptedReplTest {

  private static final String SCRIPT =
      """
            # Comments explain each step and are never run.

            write customer record #1
            use ML-KEM-768
            read
            """;

  @TempDir Path dir;

  private Path script(String text) throws IOException {
    return Files.writeString(dir.resolve("talk.demo"), text);
  }

  private String play(Terminal terminal, ByteArrayOutputStream screen, String text, boolean typing)
      throws IOException {
    ScriptedRepl.run(new Workspace(dir.resolve("data")), script(text), terminal, typing, 1000);
    terminal.close();
    return TerminalSessions.text(screen);
  }

  @Nested
  class In_a_plain_terminal {

    @Test
    void each_enter_runs_the_next_command() throws IOException {
      var screen = new ByteArrayOutputStream();

      String shown = play(TerminalSessions.dumb("\n\n\n", screen), screen, SCRIPT, false);

      assertTrue(shown.contains("write customer record #1"));
      assertTrue(shown.contains("saved record-0001"));
      assertTrue(shown.contains("[ML-KEM-768] > "));
      assertTrue(shown.contains("record-0001 (RSA-OAEP-3072) -> customer record #1"));
    }

    @Test
    void comments_and_blank_lines_are_not_run() throws IOException {
      var screen = new ByteArrayOutputStream();

      String shown = play(TerminalSessions.dumb("\n\n\n", screen), screen, SCRIPT, false);

      assertFalse(shown.contains("Comments explain"));
      assertFalse(shown.contains("unknown command"));
    }

    @Test
    void stops_when_input_runs_out() throws IOException {
      var screen = new ByteArrayOutputStream();

      String shown = play(TerminalSessions.dumb("\n", screen), screen, SCRIPT, false);

      assertTrue(shown.contains("saved record-0001"));
      assertFalse(shown.contains("new data keys will be wrapped"));
    }

    @Test
    void exit_in_the_script_ends_it() throws IOException {
      var screen = new ByteArrayOutputStream();

      String shown =
          play(TerminalSessions.dumb("\n\n\n", screen), screen, "exit\nwrite never\n", false);

      assertEquals(-1, shown.indexOf("saved"));
    }
  }

  @Nested
  class In_a_full_terminal {

    @Test
    void one_keypress_runs_the_next_command_and_the_typing_effect_shows_it() throws IOException {
      var screen = new ByteArrayOutputStream();

      String shown = play(TerminalSessions.full("xxx", screen), screen, SCRIPT, true);

      assertTrue(shown.contains("write customer record #1"));
      assertTrue(shown.contains("record-0001 (RSA-OAEP-3072) -> customer record #1"));
    }

    @Test
    void ctrl_d_stops_the_demo() throws IOException {
      var screen = new ByteArrayOutputStream();

      String shown = play(TerminalSessions.full("\u0004", screen), screen, SCRIPT, false);

      assertEquals(-1, shown.indexOf("saved"));
    }
  }
}
