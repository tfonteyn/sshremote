package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;

public final class Util {

    private Util() {
    }

    @NonNull
    public static String checkTilde(@NonNull final String filename) {
        if (filename.startsWith("~")) {
            try {
                return filename.replace("~", System.getProperty("user.home"));
            } catch (final SecurityException ignore) {
            }
        }
        return filename;
    }

    /**
     * Replacement for {@code Arrays.equals(a,b);}
     * <p>
     * The need for speed (might) matters for MAC.
     */
    public static boolean arraysEquals(@NonNull final byte[] a,
                                       @NonNull final byte[] b) {

        if (a.length != b.length) {
            return false;
        }
        int res = 0;
        for (int i = 0; i < a.length; i++) {
            res |= a[i] ^ b[i];
        }
        return res == 0;
    }
}
