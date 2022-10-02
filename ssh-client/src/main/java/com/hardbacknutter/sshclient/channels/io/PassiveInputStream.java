package com.hardbacknutter.sshclient.channels.io;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.PipedOutputStream;

public class PassiveInputStream
        extends MyPipedInputStream {

    @Nullable
    private PipedOutputStream os;

    public PassiveInputStream(@NonNull final PipedOutputStream out,
                              final int size)
            throws IOException {
        super(out, size);
        os = out;
    }

    public void close()
            throws IOException {
        if (os != null) {
            os.close();
        }
        os = null;
    }
}
