package com.hardbacknutter.sshremote.ssh;

import android.util.Log;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Logger;

public class LogCatLogger
        implements com.hardbacknutter.sshclient.Logger {

    @IntRange(from = Logger.NONE, to = Logger.DEBUG)
    private final int level;

    LogCatLogger(@IntRange(from = Logger.NONE, to = Logger.DEBUG) final int logLevel) {
        level = logLevel;
    }

    @Override
    public boolean isEnabled(final int level) {
        return level >= this.level;
    }

    @Override
    public void log(final int level,
                    @NonNull final String message) {
        Log.d("SSH" + level, message);
    }
}
