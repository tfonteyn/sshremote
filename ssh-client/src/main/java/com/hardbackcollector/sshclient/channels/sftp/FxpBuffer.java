package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.utils.ABuffer;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Extends a {@link ABuffer} (NOT a Packet);
 * This class provides easier READING of the payload of SSH_FXP_* packets.
 *
 * <pre>
 *    All packets transmitted over the secure connection are of the
 *    following format:
 *
 *         uint32             length
 *         byte               type
 *         byte[length - 1]   data payload
 *
 *    That is, they are just data preceded by 32-bit length and 8-bit type
 *    fields.  The `length' is the length of the data area, and does not
 *    include the `length' field itself.  The format and interpretation of
 *    the data area depends on the packet type.
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-3">
 * SSH File Transfer Protocol, section 3: General Packet Format</a>
 */
class FxpBuffer
        extends ABuffer<FxpBuffer> {

    private int length;
    private byte type;
    // Not actually part of the header, but all packets handled here have it.
    // Notable exception: SSH_FXP_VERSION (the response to SSH_FXP_INIT).
    private int requestId;

    /**
     * Constructor.
     *
     * @param remoteMaxPacketSize size of packet
     */
    FxpBuffer(final int remoteMaxPacketSize) {
        super(remoteMaxPacketSize, false);
    }

    /**
     * Read the first 9 bytes of the channel payload data,
     * and extract length, type(fxp command) and requestId.
     * <p>
     * We subtract 5 from the length for the data already read: type+requestId.
     *
     * @param inputStream to read from
     */
    void readHeader(@NonNull final InputStream inputStream)
            throws IOException {
        // 9 bytes: the channel payload data length + type + requestId
        reset();
        read(inputStream, 0, 9);

        // normally '-1' for the type, but we also read the requestId here
        this.length = getInt() - 5;
        this.type = getByte();

        this.requestId = getInt();
    }

    /**
     * Read 4 bytes from the input stream into the start of the buffer,
     * and return them as an int.
     *
     * @param inputStream to read from
     *
     * @return the int
     */
    int readInt(@NonNull final InputStream inputStream)
            throws IOException {
        reset();
        read(inputStream, 0, 4);
        return getInt();
    }

    /**
     * Read the Sftp payload into the data buffer, <strong>starting at position ZERO</strong>.
     * <p>
     * After this call, the buffer is just a data blob with the payload.
     *
     * @param inputStream to read from
     *
     * @throws IndexOutOfBoundsException if the number of bytes is larger then the buffer.
     */
    void readPayload(@NonNull final InputStream inputStream)
            throws IOException, IndexOutOfBoundsException {
        reset();
        read(inputStream, 0, length);
    }

    /**
     * Read 'len' bytes from the input stream into the buffer.
     * They will be appended to the data already there.
     *
     * @param inputStream to read from
     * @param len         number of bytes to read.
     *
     * @return total amount of bytes <strong>actually</strong> read.
     *
     * @throws IndexOutOfBoundsException if the number of bytes is larger then the buffer.
     */
    int readAppending(@NonNull final InputStream inputStream,
                      final int len)
            throws IOException, IndexOutOfBoundsException {
        return read(inputStream, writeOffset, len);
    }

    /**
     * Read data from the input stream at the given offset and length.
     * Data is written into the packet starting at position 0.
     * <p>
     * The internal write-offset is updated to point to the position AFTER the
     * last byte put into the buffer. The internal read-offset is NOT changed.
     *
     * @param inputStream to read from
     * @param offset      in the inputStream from where to start reading
     * @param length      how many bytes to read
     *
     * @return total amount of bytes <strong>actually</strong> read.
     *
     * @throws IndexOutOfBoundsException if the number of bytes is larger then the buffer.
     */
    private int read(@NonNull final InputStream inputStream,
                     int offset,
                     int length)
            throws IOException, IndexOutOfBoundsException {
        int bytesRead;
        final int start = offset;
        while (length > 0) {
            bytesRead = inputStream.read(data, offset, length);
            if (bytesRead <= 0) {
                throw new EOFException();
            }
            offset += bytesRead;
            length -= bytesRead;
        }
        final int total = offset - start;
        moveWritePosition(total);
        return total;

    }

    int getFxpLength() {
        return length;
    }

    byte getFxpType() {
        return type;
    }

    int getRequestId() {
        return requestId;
    }
}
