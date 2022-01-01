package com.hardbackcollector.sshclient.channels.io;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

// This class needs a better name...
public class MyPipedInputStream
        extends PipedInputStream {

    private final int minPipeSize;
    private final int maxPipeSize;

    public MyPipedInputStream(final int minPipeSize,
                              final int maxPipeSize) {
        super();
        this.minPipeSize = minPipeSize;
        this.maxPipeSize = maxPipeSize;
        buffer = new byte[minPipeSize];
    }

    public MyPipedInputStream(@NonNull final PipedOutputStream out,
                              final int minPipeSize)
            throws IOException {
        super(out);
        this.minPipeSize = minPipeSize;
        this.maxPipeSize = minPipeSize;
        buffer = new byte[minPipeSize];
    }

    /*
     * TODO: We should have our own Piped[I/O]Stream implementation.
     * Before accepting data, JDK's PipedInputStream will check the existence of
     * reader thread, and if it is not alive, the stream will be closed.
     * That behavior may cause the problem if multiple threads make access to it.
     */
    public synchronized void updateReadSide()
            throws IOException {
        if (available() != 0) {
            // not empty
            return;
        }
        in = 0;
        out = 0;
        buffer[in++] = 0;
        read();
    }

    private int calcFreeSpace() {
        if (out < in) {
            return buffer.length - in;
        } else if (in < out) {
            if (in == -1) {
                return buffer.length;
            } else {
                return out - in;
            }
        }
        return 0;
    }

    synchronized void checkSpace(final int needed) {
        final int freeSpace = calcFreeSpace();

        if (freeSpace < needed) {
            // expand the buffer

            final int dataSize = buffer.length - freeSpace;
            int length = buffer.length;
            // double until we have enough
            while ((length - dataSize) < needed) {
                length *= 2;
            }
            // but don't overflow the maximum size.
            if (length > maxPipeSize) {
                length = maxPipeSize;
            }
            // still not enough ? To bad... return
            if ((length - dataSize) < needed) {
                return;
            }

            // expand
            final byte[] tmp = new byte[length];
            if (out < in) {
                System.arraycopy(buffer, 0, tmp, 0, buffer.length);

            } else if (in < out) {
                if (in != -1) {
                    System.arraycopy(buffer, 0, tmp, 0, in);
                    System.arraycopy(buffer, out,
                                     tmp, tmp.length - (buffer.length - out),
                                     (buffer.length - out));
                    out = tmp.length - (buffer.length - out);
                }
            } else {
                System.arraycopy(buffer, 0, tmp, 0, buffer.length);
                in = buffer.length;
            }
            buffer = tmp;

        } else if (buffer.length == freeSpace && freeSpace > minPipeSize) {
            // buffer is empty, and expanded -> shrink it.
            //TODO: what about 'needed' > minPipeSize ?
            int i = freeSpace / 2;
            if (i < minPipeSize) {
                i = minPipeSize;
            }
            buffer = new byte[i];
        }
    }
}
