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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.regex.Pattern;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

/**
 * In-memory terminals for driving the prompt and the scripted player in tests: typed input in,
 * screen out. Native terminal support is switched off, so JLine works on the streams directly
 * instead of opening a real pseudo-terminal.
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
   * A full terminal, like a real one, with someone at the keyboard who presses each key only once
   * the next prompt is showing.
   */
  static Terminal full(String keys, ByteArrayOutputStream screen) throws IOException {
    var watched = new WatchedScreen(screen);
    return TerminalBuilder.builder()
        .system(false)
        .ffm(false)
        .jni(false)
        .streams(new Typist(keys, watched), watched)
        .type("xterm")
        .build();
  }

  // Passes everything drawn through to the screen, and wakes anyone waiting to see it.
  private static final class WatchedScreen extends OutputStream {

    private final ByteArrayOutputStream screen;

    WatchedScreen(ByteArrayOutputStream screen) {
      this.screen = screen;
    }

    @Override
    public synchronized void write(int b) {
      screen.write(b);
      notifyAll();
    }

    @Override
    public synchronized void write(byte[] b, int off, int len) {
      screen.write(b, off, len);
      notifyAll();
    }

    synchronized String text() {
      return TerminalSessions.text(screen);
    }
  }

  // Presses key n only after the screen shows its n-th prompt, then runs out.
  private static final class Typist extends InputStream {

    private static final String PROMPT = "] > ";
    private static final long PATIENCE_MILLIS = 10_000;

    private final String keys;
    private final WatchedScreen screen;
    private int pressed;

    Typist(String keys, WatchedScreen screen) {
      this.keys = keys;
      this.screen = screen;
    }

    @Override
    public int read() throws IOException {
      if (pressed >= keys.length()) {
        return -1;
      }
      long deadline = System.currentTimeMillis() + PATIENCE_MILLIS;
      synchronized (screen) {
        while (prompts() <= pressed) {
          long left = deadline - System.currentTimeMillis();
          if (left <= 0) {
            throw new IOException("no prompt appeared for key " + (pressed + 1));
          }
          awaitDrawing(left);
        }
      }
      return keys.charAt(pressed++);
    }

    private int prompts() {
      return screen.text().split(Pattern.quote(PROMPT), -1).length - 1;
    }

    // Waits, holding the screen's lock, until something more is drawn or the time is up.
    private void awaitDrawing(long millis) throws IOException {
      try {
        screen.wait(millis);
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
