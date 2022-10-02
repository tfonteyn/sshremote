package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;

import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;

public final class Globber {
    private Globber() {
    }

    /**
     * Unescape the given path for '?', '*' and '\'.
     *
     * @param path to unescape
     *
     * @return processed path
     */
    @NonNull
    public static String unescapePath(@NonNull final CharSequence path) {
        final StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < path.length()) {
            final char c = path.charAt(i);
            if (c != '\\') {
                out.append(c);
            } else if (i + 1 < path.length() && path.charAt(i + 1) == '\\') {
                // double backslash becomes a single backslash
                out.append(c);
                i++;
            }
            i++;
        }
        return out.toString();
    }

    /**
     * Escape the given path for '?', '*' and '\'.
     *
     * @param path to escape
     *
     * @return processed path
     */
    @NonNull
    public static String escapePath(@NonNull final CharSequence path) {
        final StringBuilder out = new StringBuilder();
        path.chars().forEach(i -> {
            if ((i == '\\') || (i == '?') || (i == '*')) {
                out.append('\\');
            }
            out.append((char) i);
        });
        return out.toString();
    }

    /**
     * Pattern matching function which returns {@code true} if the specified pattern
     * matches the specified name.
     * <p>
     * Hidden files (UNIX '.' files) will return {@code false}
     * if the pattern did NOT start with a '.'
     * <p>
     * Uses optimised file-system dependent code from the JDK.
     *
     * @return {@code true} if pattern matches name
     */
    public static boolean globLocalPath(@NonNull final String pattern,
                                        @NonNull final String name) {

        // backwards compatibility...
        if (name.startsWith(".")) {
            if (pattern.startsWith(".")) {
                if (pattern.length() == 2 && pattern.charAt(1) == '*') {
                    // name started with '.' and the pattern is exactly ".*"
                    // -> matches everything
                    return true;
                }
                // both name and pattern started with a '.'
                final PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher(
                        "glob:" + pattern.substring(1));
                return pathMatcher.matches(Path.of(name.substring(1)));
            }
            // The name started with '.', but the pattern did not
            // We have a 'hidden' file; report no-match to keep it hidden.
            return false;
        }

        final PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher("glob:" + pattern);
        return pathMatcher.matches(Path.of(name));
    }

    /**
     * Pattern matching function which returns {@code true} if the specified pattern
     * matches the specified name.
     * <p>
     * Hidden files (UNIX '.' files) will return {@code false}
     * if the pattern did NOT start with a '.'
     *
     * @return {@code true} if pattern matches name
     */
    public static boolean globRemotePath(@NonNull final String pattern,
                                         @NonNull final String filename) {

        if (filename.startsWith(".")) {
            if (".*".equals(pattern)) {
                // name started with '.' and the pattern is exactly ".*"
                // -> matches everything
                return true;

            } else if (pattern.startsWith(".")) {
                // both name and pattern started with a '.'
                return globRemotePath(pattern.getBytes(StandardCharsets.UTF_8), 1,
                                      filename.getBytes(StandardCharsets.UTF_8), 1);
            } else {
                // The name started with '.', but the pattern did not
                // We have a 'hidden' file; report no-match to keep it hidden.
                return false;
            }
        } else {
            return globRemotePath(pattern.getBytes(StandardCharsets.UTF_8), 0,
                                  filename.getBytes(StandardCharsets.UTF_8), 0);
        }
    }

    /**
     * Pattern matching function which returns {@code true} if the specified pattern
     * matches the specified name starting from specified pattern index and
     * name index.
     *
     * @param pattern  must be in UTF-8 byte[] format.
     * @param filename must be in UTF-8 byte[] format.
     *
     * @return {@code true} if pattern matches name from given indexes
     */
    private static boolean globRemotePath(@NonNull final byte[] pattern,
                                          final int patternIndex,
                                          @NonNull final byte[] filename,
                                          final int nameIndex) {

        if (pattern.length == 0) {
            return false;
        }

        int p = patternIndex;
        int n = nameIndex;

        while (p < pattern.length && n < filename.length) {
            if (pattern[p] == '\\') {
                if (p + 1 == pattern.length) {
                    return false;
                }
                p++;
                if (pattern[p] != filename[n]) {
                    return false;
                }
                p += skipUTF8Char(pattern[p]);
                n += skipUTF8Char(filename[n]);
                continue;
            }

            if (pattern[p] == '*') {
                while (p < pattern.length && pattern[p] == '*') {
                    p++;
                }

                if (pattern.length == p) {
                    return true;
                }

                byte c = pattern[p];
                if (c == '?') {
                    while (n < filename.length) {
                        if (globRemotePath(pattern, p, filename, n)) {
                            return true;
                        }
                        n += skipUTF8Char(filename[n]);
                    }
                    return false;

                } else if (c == '\\') {
                    if (p + 1 == pattern.length) {
                        return false;
                    }
                    p++;
                    c = pattern[p];

                    while (n < filename.length) {
                        if (c == filename[n]) {
                            if (globRemotePath(pattern, p + skipUTF8Char(c),
                                               filename, n + skipUTF8Char(filename[n]))) {
                                return true;
                            }
                        }
                        n += skipUTF8Char(filename[n]);
                    }
                    return false;
                }

                while (n < filename.length) {
                    if (c == filename[n]) {
                        if (globRemotePath(pattern, p, filename, n)) {
                            return true;
                        }
                    }
                    n += skipUTF8Char(filename[n]);
                }
                return false;
            }

            if (pattern[p] == '?') {
                p++;
                n += skipUTF8Char(filename[n]);
                continue;
            }

            if (pattern[p] != filename[n]) {
                return false;
            }

            p += skipUTF8Char(pattern[p]);
            n += skipUTF8Char(filename[n]);

            if (!(n < filename.length)) {
                if (!(p < pattern.length)) {
                    return true;
                }
                if (pattern[p] == '*') {
                    break;
                }
            }
        }

        if (p == pattern.length && n == filename.length) {
            return true;
        }

        if (!(n < filename.length) && pattern[p] == '*') {
            boolean ok = true;
            while (p < pattern.length) {
                if (pattern[p++] != '*') {
                    ok = false;
                    break;
                }
            }
            return ok;
        }

        return false;
    }

    private static int skipUTF8Char(final byte b) {
        if ((byte) (b & 0x80) == 0) {
            return 1;
        } else if ((byte) (b & 0xe0) == (byte) 0xc0) {
            return 2;
        } else if ((byte) (b & 0xf0) == (byte) 0xe0) {
            return 3;
        } else {
            return 1;
        }
    }
}
