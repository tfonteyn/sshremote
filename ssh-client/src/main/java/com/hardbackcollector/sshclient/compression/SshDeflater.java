package com.hardbackcollector.sshclient.compression;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.transport.Packet;

import java.io.IOException;

public interface SshDeflater {

    /** Levels go from 0 (no compression) to 9 (max, slow). */
    int DEFAULT_LEVEL = 6;

    /**
     * Initializes the compression engine.
     *
     * @param level the compression level.
     *
     * @throws IOException on any error
     */
    void init(int level)
            throws IOException;

    /**
     * Compress the payload of a {@link Packet}.
     *
     * @param packet the Packet buffer containing the uncompressed data.
     *               The internal data buffer <strong>may</strong> be replaced with a new one.
     *
     * @throws IOException on any error
     */
    void compress(@NonNull Packet packet)
            throws IOException;
}
