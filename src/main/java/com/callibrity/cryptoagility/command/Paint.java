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

/**
 * Colour for terminal output. Off by default, so anything piped to a file or checked in a test is
 * plain text; Demo turns it on when it is talking to a real terminal.
 */
public final class Paint {

  private static final String RESET = "\u001b[0m";

  private static boolean enabled;

  private Paint() {}

  public static void enable(boolean on) {
    enabled = on;
  }

  /** Something went wrong, or something was exposed. */
  public static String red(String text) {
    return paint("31", text);
  }

  /** Something worked. */
  public static String green(String text) {
    return paint("32", text);
  }

  /** The part of an envelope that depends on the algorithm. */
  public static String yellow(String text) {
    return paint("33", text);
  }

  /** The part of an envelope that never changes. */
  public static String cyan(String text) {
    return paint("36", text);
  }

  public static String bold(String text) {
    return paint("1", text);
  }

  /** Detail that is there to be glanced at, such as the first few bytes of a field. */
  public static String faint(String text) {
    return paint("2", text);
  }

  private static String paint(String code, String text) {
    return enabled ? "\u001b[" + code + "m" + text + RESET : text;
  }
}
