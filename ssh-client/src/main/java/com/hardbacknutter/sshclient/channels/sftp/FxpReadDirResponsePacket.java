package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;


/**
 * Handle the response to a {@link SftpConstants#SSH_FXP_READDIR} request.
 * <p>
 * The response is a {@link SftpConstants#SSH_FXP_NAME} packet with a directory listing.
 */
class FxpReadDirResponsePacket {

    private static final String ERROR_INVALID_TYPE_s = "Invalid type: ";
    @NonNull
    private final FxpBuffer fxpBuffer;
    private final int serverVersion;

    private int nrOfEntries;

    /**
     * The number of LS entries might be very large.
     * We'll use the packet length + its data length to read blobs
     * from the input stream without creating OutOfMemoryError's.
     */
    private int length;

    /**
     * Constructor.
     *
     * @param remoteMaxPacketSize the maximum size of the packet as defined by the server.
     */
    FxpReadDirResponsePacket(final int remoteMaxPacketSize,
                             final int serverVersion) {
        fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
        this.serverVersion = serverVersion;
    }

    private void decodeHeader(@NonNull final InputStream inputStream)
            throws IOException, SftpException {

        fxpBuffer.readHeader(inputStream);

        // a status packet is a valid response
        if (fxpBuffer.getFxpType() == SftpConstants.SSH_FXP_STATUS) {
            fxpBuffer.readPayload(inputStream);
            final int status = fxpBuffer.getInt();
            if (status == SftpConstants.SSH_FX_EOF) {
                // no more files in the directory
                nrOfEntries = 0;
                // nothing else to read
                length = 0;
                return;
            }

            String message;
            try {
                message = fxpBuffer.getJString();
            } catch (final IOException e) {
                message = e.getMessage();
            }
            throw new SftpException(status, message);
        }

        // but if we did not get a status or name packet, we have a problem
        if (fxpBuffer.getFxpType() != SftpConstants.SSH_FXP_NAME) {
            throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                                    ERROR_INVALID_TYPE_s + fxpBuffer.getFxpType());
        }

        nrOfEntries = fxpBuffer.readInt(inputStream);
        if (nrOfEntries == 0) {
            // nothing else to read
            length = 0;
            return;
        }

        length = fxpBuffer.getFxpLength() - 4;

        fxpBuffer.reset();
    }

    /**
     * Read the number of entries found.
     *
     * @return number of entries
     */
    int readNrOfEntries(@NonNull final InputStream inputStream)
            throws SftpException, IOException {
        decodeHeader(inputStream);
        return nrOfEntries;
    }

    /**
     * Read one <strong>raw</strong> LS entry:
     * <pre>
     *      string     filename
     *      string     longname
     *      ATTRS      attrs
     * </pre>
     *
     * @return the raw LS record
     */
    @NonNull
    LSStruct readRawEntry(@NonNull final InputStream inputStream)
            throws IOException {
        // Fill the available space of the packet without expanding it.
        if (length > 0) {
            fxpBuffer.shiftBuffer();
            final int bytesRead = fxpBuffer.readAppending(
                    inputStream, Math.min(fxpBuffer.spaceLeft(), length));
            length -= bytesRead;
        }

        if (serverVersion <= 3) {
            return new LSStruct(
                    fxpBuffer.getString(),
                    fxpBuffer.getString(),
                    SftpATTRS.getATTR(fxpBuffer));
        } else {
            return new LSStruct(
                    fxpBuffer.getString(),
                    // longname no longer exists in v4+
                    null,
                    SftpATTRS.getATTR(fxpBuffer));
        }
    }

    static class LSStruct {
        @NonNull
        final byte[] filename;
        @Nullable
        final byte[] longname;
        @NonNull
        final SftpATTRS attr;

        LSStruct(@NonNull final byte[] filename,
                 @Nullable final byte[] longname,
                 @NonNull final SftpATTRS attr) {
            this.filename = filename;
            this.longname = longname;
            this.attr = attr;
        }
    }
}
