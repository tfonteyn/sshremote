package com.hardbacknutter.sshclient.utils;

import org.jspecify.annotations.NonNull;

public final class Util {

    private Util() {
    }

    @NonNull
    public static String checkTilde(@NonNull final String filename) {
        if (filename.startsWith("~")) {
            try {
                return System.getProperty("user.home") + filename.substring(1);
            } catch (final SecurityException ignore) {
            }
        }
        return filename;
    }
}
