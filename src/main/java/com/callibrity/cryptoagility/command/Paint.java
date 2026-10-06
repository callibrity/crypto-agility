package com.callibrity.cryptoagility.command;

/**
 * Colour for terminal output. Off by default, so anything piped to a file or
 * checked in a test is plain text; Demo turns it on when it is talking to a
 * real terminal.
 */
public final class Paint {

    private static final String RESET = "\u001b[0m";

    private static boolean enabled;

    private Paint() {}

    public static void enable(boolean on) {
        enabled = on;
    }

    /** Something went wrong, or something was exposed. */
    public static String red(String text) { return paint("31", text); }

    /** Something worked. */
    public static String green(String text) { return paint("32", text); }

    /** The part of an envelope that depends on the algorithm. */
    public static String yellow(String text) { return paint("33", text); }

    /** The part of an envelope that never changes. */
    public static String cyan(String text) { return paint("36", text); }

    public static String bold(String text) { return paint("1", text); }

    /** Detail that is there to be glanced at, such as the first few bytes of a field. */
    public static String faint(String text) { return paint("2", text); }

    private static String paint(String code, String text) {
        return enabled ? "\u001b[" + code + "m" + text + RESET : text;
    }
}
