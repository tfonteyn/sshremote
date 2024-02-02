package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;

import java.util.function.Supplier;

public interface Logger {

    int NONE = 0;
    int FATAL = 1;
    int ERROR = 2;
    int WARN = 3;
    int INFO = 4;
    int DEBUG = 5;

    /**
     * Check if the given log level is enabled.
     *
     * @param level to check
     *
     * @return {@code true} if enabled
     */
    boolean isEnabled(int level);

    /**
     * Unconditionally log the given message.
     *
     * @param level   to log at
     * @param message to log
     */
    void log(int level,
             @NonNull String message);

    /**
     * Log the given message <strong>if</strong> the given log level is enabled.
     *
     * @param level   to log at
     * @param message to log
     */
    default void log(final int level,
                     @NonNull final Supplier<String> message) {
        if (isEnabled(level)) {
            log(level, message.get());
        }
    }

    /**
     * Log the given message <strong>if</strong> the given log level is enabled.
     *
     * @param level   to log at
     * @param message to log
     */
    default void log(final int level,
                     @NonNull final Throwable e,
                     @NonNull final Supplier<String> message) {
        log(level, () -> message.get() + "|" + e.getMessage());
    }
}
