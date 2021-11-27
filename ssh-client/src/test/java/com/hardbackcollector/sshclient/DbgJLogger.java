package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

public class DbgJLogger
        implements com.hardbackcollector.sshclient.Logger {

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
                    @NonNull final String message,
                    @NonNull final Throwable e) {
        System.out.println("SshClientDbg" + level + ": " + message + "\n");
        //noinspection CallToPrintStackTrace
        e.printStackTrace();
    }
}
