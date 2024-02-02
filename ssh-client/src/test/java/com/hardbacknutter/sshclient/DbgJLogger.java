package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;

import java.util.function.Supplier;

public class DbgJLogger
        implements com.hardbacknutter.sshclient.Logger {

    @Override
    public boolean isEnabled(final int level) {
        return true;
    }

    @Override
    public void log(final int level,
                    @NonNull final String message) {
        System.out.println("SshClientDbg" + level + ": " + message);
    }

    @Override
    public void log(final int level,
                    @NonNull final Throwable e,
                    @NonNull final Supplier<String> message) {
        System.out.println("SshClientDbg" + level + ": " + message.get() + "\n");
        //noinspection CallToPrintStackTrace
        e.printStackTrace();
    }
}
