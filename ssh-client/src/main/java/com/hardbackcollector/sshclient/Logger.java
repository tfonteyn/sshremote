package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

import java.util.function.Supplier;

public interface Logger {

    int NONE = 0;
    int FATAL = 1;
    int ERROR = 2;
    int WARN = 3;
    int INFO = 4;
    int DEBUG = 5;

    boolean isEnabled(int level);

    void log(int level,
             @NonNull Supplier<String> message);

    default void log(final int level,
                     @NonNull final Throwable e,
                     @NonNull final Supplier<String> message) {
        log(level, () -> message.get() + "|" + e.getMessage());
    }
}
