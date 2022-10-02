package com.hardbacknutter.sshclient.compression;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.transport.Packet;

import java.io.IOException;

public interface SshInflater {

    /**
     * Initializes the decompression engine.
     *
     * @throws IOException on any error
     */
    void init()
            throws IOException;

    /**
     * Uncompress the payload of a {@link Packet}.
     *
     * @param packet the Packet buffer containing the compressed data.
     *               The internal data buffer <strong>may</strong> be replaced with a new one.
     *
     * @throws IOException on any error
     */
    void decompress(@NonNull Packet packet)
            throws IOException;
}
