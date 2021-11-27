package com.hardbackcollector.sshclient.channels.io;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public final class PassiveOutputStream
        extends PipedOutputStream {

    private MyPipedInputStream sink;

    public PassiveOutputStream(@NonNull final PipedInputStream in,
                               final boolean resizable)
            throws IOException {
        super(in);
        if (resizable && (in instanceof MyPipedInputStream)) {
            this.sink = (MyPipedInputStream) in;
        }
    }

    @Override
    public void write(final int b)
            throws IOException {
        if (sink != null) {
            sink.checkSpace(1);
        }
        super.write(b);
    }

    @Override
    public void write(@NonNull final byte[] buf,
                      final int offset,
                      final int length)
            throws IOException {
        if (sink != null) {
            sink.checkSpace(length);
        }
        super.write(buf, offset, length);
    }
}
