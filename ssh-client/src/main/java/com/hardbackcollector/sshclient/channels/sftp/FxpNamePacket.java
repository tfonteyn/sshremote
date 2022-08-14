package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;


class FxpNamePacket {

    private static final String ERROR_INVALID_TYPE_s = "Invalid type: ";
    @NonNull
    private final FxpBuffer fxpBuffer;

    private int nrOfEntries;

    /**
     * The number of LS entries might be very large.
     * We'll use the packet length + its data length to read blobs
     * from the input stream without creating OutOfMemoryError's.
     *
     * @see #fillBuffer(InputStream)
     */
    private int length;

    /**
     * Constructor.
     *
     * @param remoteMaxPacketSize the maximum size of the packet as defined by the server.
     */
    FxpNamePacket(final int remoteMaxPacketSize) {
        fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
    }

    // byte       SSH_FXP_NAME
    // uint32     request-id
    // ==> mpIn is positioned here.
    // uint32     count
    // repeats count times:
    //     string     filename
    //     string     longname   (server version 1-3 only; not present in 4+)
    //     ATTRS      attrs
    void decodeHeader(@NonNull final InputStream inputStream)
            throws IOException, SftpException {

        // not using #receive(byte expectedType) as we need to allow for SSH_FX_EOF
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
     * Fill the available space of the packet without expanding it.
     *
     * @param inputStream to read from
     */
    void fillBuffer(@NonNull final InputStream inputStream)
            throws IOException {
        if (length > 0) {
            //
            fxpBuffer.shiftBuffer();
            final int bytesRead = fxpBuffer.readAppending(
                    inputStream, Math.min(fxpBuffer.spaceLeft(), length));
            length -= bytesRead;
        }
    }

    /**
     * Get the number of entries found.
     * <p>
     * {@link #decodeHeader(InputStream)} (InputStream)} MUST already have been called.
     *
     * @return number of entries
     */
    int getNrOfEntries() {
        return nrOfEntries;
    }


    @NonNull
    byte[] readString()
            throws IOException {
        return fxpBuffer.getString();
    }

    @NonNull
    SftpATTRS readATTRS() throws
                          IOException {

        return SftpATTRS.getATTR(fxpBuffer);
    }
}
