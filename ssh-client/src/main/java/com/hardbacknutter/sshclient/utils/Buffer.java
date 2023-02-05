package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;

import java.util.Arrays;


public class Buffer
        extends ABuffer<Buffer> {

    /**
     * Create a Buffer with a default size. The buffer MAY expand when needed.
     */
    public Buffer() {
        super();
    }

    /**
     * Create a Buffer with a FIXED size.
     */
    public Buffer(final int size) {
        super(size, true);
    }

    /**
     * Create a Buffer using the given array as backing store. The buffer size is FIXED.
     */
    public Buffer(@NonNull final byte[] data) {
        super(data);
    }

    /**
     * Read the content of the buffer between the start of the buffer, and the write offset.
     * i.e. the data which was written to the buffer.
     *
     * @return a NEW (copied) byte array.
     */
    public byte[] getPayload() {
        return Arrays.copyOfRange(data, 0, getWriteOffset());
    }
}
