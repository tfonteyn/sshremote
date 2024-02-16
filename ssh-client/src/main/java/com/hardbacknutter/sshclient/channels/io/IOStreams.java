package com.hardbacknutter.sshclient.channels.io;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.hardbacknutter.sshclient.utils.SshConstants;

/**
 * Bundles the 3 streams used by a Channel.
 */
public class IOStreams {

    @Nullable
    private InputStream in;
    @Nullable
    private OutputStream out;
    @Nullable
    private OutputStream out_ext;

    private boolean in_do_not_close;
    private boolean out_do_not_close;
    private boolean out_ext_do_not_close;

    public boolean hasInputStream() {
        return in != null;
    }

    public void setInputStream(@NonNull final InputStream in,
                               final boolean do_not_close) {
        this.in = in;
        this.in_do_not_close = do_not_close;
    }

    public void setOutputStream(@NonNull final OutputStream out,
                                final boolean do_not_close) {
        this.out = out;
        this.out_do_not_close = do_not_close;
    }

    public void setExtOutputStream(@NonNull final OutputStream out,
                                   final boolean do_not_close) {
        this.out_ext = out;
        this.out_ext_do_not_close = do_not_close;
    }

    public int read(@NonNull final byte[] bytes,
                    @SuppressWarnings("SameParameterValue") final int offset,
                    final int length)
            throws IOException {
        //noinspection DataFlowIssue
        return in.read(bytes, offset, length);
    }

    /**
     * For writing {@link SshConstants#SSH_MSG_CHANNEL_DATA}
     */
    public void write(@NonNull final byte[] bytes,
                      final int offset,
                      final int length)
            throws IOException {
        //noinspection DataFlowIssue
        out.write(bytes, offset, length);
        out.flush();
    }

    /**
     * For writing {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA}
     * <p>
     * If the stream is not open, the write is ignored.
     */
    public void writeExt(@NonNull final byte[] bytes,
                         final int offset,
                         final int length)
            throws IOException {
        if (out_ext != null) {
            out_ext.write(bytes, offset, length);
            out_ext.flush();
        }
    }

    /**
     * Close all open streams if allowed.
     */
    public void close() {
        try {
            if (in != null && !in_do_not_close) {
                in.close();
            }
            in = null;
        } catch (final Exception ignore) {
        }

        closeOutputStream();

        try {
            if (out_ext != null && !out_ext_do_not_close) {
                out_ext.close();
            }
            out_ext = null;
        } catch (final Exception ignore) {
        }
    }

    /**
     * Close the stdout if allowed.
     */
    public void closeOutputStream() {
        try {
            if (out != null && !out_do_not_close) {
                out.close();
            }
            out = null;
        } catch (final Exception ignore) {
        }
    }
}
