package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;

/**
 * Handle the response to a {@link SftpConstants#SSH_FXP_INIT} request.
 *
 * The response is a {@link SftpConstants#SSH_FXP_VERSION} packet.
 *
 * <p>
 * 10. Changes from previous protocol versions
 * The SSH File Transfer Protocol has changed over time, before it's
 * standardization.  The following is a description of the incompatible
 * changes between different versions.
 * <p>
 * 10.1 Changes between versions 3 and 2
 * o  The SSH_FXP_READLINK and SSH_FXP_SYMLINK messages were added.
 * o  The SSH_FXP_EXTENDED and SSH_FXP_EXTENDED_REPLY messages were added.
 * o  The SSH_FXP_STATUS message was changed to include fields `error
 * message' and `language tag'.
 * <p>
 * 10.2 Changes between versions 2 and 1
 * o  The SSH_FXP_RENAME message was added.
 * <p>
 * 10.3 Changes between versions 1 and 0
 * o  Implementation changes, no actual protocol changes.
 * <p>
 * Given that SFTP v3 is 20+ years old, the minimum supported version is 3.
 */
class FxpVersionPacket {

    private static final String ERROR_SERVER_MUST_BE_V3 =
            "The server must be at least version 3";

    @NonNull
    private final FxpBuffer fxpBuffer;
    @NonNull
    private final HashMap<String, String> extensions = new HashMap<>();
    private int server_version;

    /**
     * Constructor.
     *
     * @param remoteMaxPacketSize the maximum size of the packet as defined by the server.
     */
    FxpVersionPacket(final int remoteMaxPacketSize) {
        fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
    }

    void decode(@NonNull final InputStream inputStream)
            throws IOException, SftpException {
        fxpBuffer.readHeader(inputStream);

        // there is no FXP request id, but the first int from the payload
        // which we previously read as the request-id is in fact the server version.
        server_version = fxpBuffer.getRequestId();
        if (server_version < 3) {
            throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED, ERROR_SERVER_MUST_BE_V3);
        }

        int payloadLength = fxpBuffer.getFxpLength();
        if (payloadLength > 0) {
            // we have extension data, read it
            fxpBuffer.readPayload(inputStream);

            String name;
            String value;
            while (payloadLength > 0) {
                name = fxpBuffer.getJString();
                payloadLength -= 4 + name.length();

                value = fxpBuffer.getJString();
                payloadLength -= 4 + value.length();

                extensions.put(name, value);
            }
        }
    }

    /**
     * Get the server version.
     * <p>
     * {@link #decode(InputStream)} MUST already have been called.
     *
     * @return version
     */
    int getVersion() {
        return server_version;
    }

    /**
     * Get the extensions.
     * <p>
     * {@link #decode(InputStream)} MUST already have been called.
     *
     * @return map
     */
    @NonNull
    HashMap<String, String> getExtensions() {
        return extensions;
    }
}
