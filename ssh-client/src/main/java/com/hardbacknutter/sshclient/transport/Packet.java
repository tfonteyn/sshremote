package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Random;
import com.hardbacknutter.sshclient.utils.ABuffer;
import com.hardbacknutter.sshclient.utils.Buffer;

/**
 * A single packet to be sent to or received from the remote side.
 * The packet class handles padding of a {@link Buffer}.
 * <pre>
 *      uint32    packet_length
 *      byte      padding_length
 *      byte[n1]  payload; n1 = packet_length - padding_length - 1
 *      byte[n2]  random padding; n2 = padding_length
 *      byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 *
 *       packet_length
 *          The length of the packet in bytes, not including 'mac' or the
 *          'packet_length' field itself.
 *
 *       padding_length
 *          Length of 'random padding' (bytes).
 *
 *       payload
 *          The useful contents of the packet.  If compression has been
 *          negotiated, this field is compressed.  Initially, compression
 *          MUST be "none".
 *
 *       random padding
 *          Arbitrary-length padding, such that the total length of
 *          (packet_length || padding_length || payload || random padding)
 *          is a multiple of the cipher block size or 8, whichever is
 *          larger.  There MUST be at least four bytes of padding.  The
 *          padding SHOULD consist of random bytes.  The maximum amount of
 *          padding is 255 bytes.
 *
 *       mac
 *          Message Authentication Code.  If message authentication has
 *          been negotiated, this field contains the MAC bytes.  Initially,
 *          the MAC algorithm MUST be "none".
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6">
 * RFC 4253 SSH Transport Layer Protocol, section 6. Binary Packet Protocol</a>
 */
public class Packet
        extends ABuffer<Packet> {

    public static final int HEADER_LEN = 5;
    /**
     * Maximum block size for the MAC's.
     * This is an exact value; i.e. SHA-512
     * Used where fixed-size packets are used.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int MAX_MAC_SIZE = 64;
    /**
     * Maximum padding length.
     * Used where fixed-size packets are used.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int MAX_PAD_SIZE = 32;
    /**
     * Margin for deflater; compressing can in rare circumstances actually inflate data.
     * This is an safe estimate only.
     * Used where fixed-size packets are used.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int DEFLATER_MARGIN = 32;

    /**
     * Safety margin where fixed-size packets are used.
     */
    public static final int SAFE_MARGIN = MAX_MAC_SIZE + MAX_PAD_SIZE + DEFLATER_MARGIN;

    /**
     * The absolute maximum packet size we allow: 128kb.
     * <pre>
     *    All implementations MUST be able to process packets with an
     *    uncompressed payload length of 32768 bytes or less and a total packet
     *    size of 35000 bytes or less (including 'packet_length',
     *    'padding_length', 'payload', 'random padding', and 'mac').  The
     *    maximum of 35000 bytes is an arbitrarily chosen value that is larger
     *    than the uncompressed length noted above.  Implementations SHOULD
     *    support longer packets, where they might be needed.
     * </pre>
     * Take 35000, rounded up to 64k and doubled... 128kb.
     * TODO: should be configurable.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.1">
     * RFC 4253 SSH Transport Layer Protocol, section 6.1. Maximum Packet Length</a>
     */
    public static final int MAX_SIZE = 0x2_0000;

    /**
     * Constructor.
     * <p>
     * Create a Packet with a default size. The buffer MAY expand when needed.
     */
    public Packet() {
        super();
    }

    /**
     * Constructor.
     * <p>
     * Create a packet with a FIXED size.
     *
     * @see #SAFE_MARGIN
     */
    public Packet(final int size) {
        super(size, true);
    }

    /**
     * Constructor.
     * <p>
     * Create a Packet with a default size. The buffer MAY expand when needed.
     * Put the given command byte in the buffer,
     * and set the buffer's WRITE-position to the start of the payload.
     */
    public Packet(final byte command) {
        super();
        writeOffset = HEADER_LEN;
        putByte(command);
    }

    /**
     * Copy constructor.
     *
     * @param other to copy from
     */
    public Packet(@NonNull final Packet other) {
        super(other);
    }

    /**
     * Put the given command byte in the buffer,
     * and set the buffer's WRITE-position to the start of the payload
     * (i.e. AFTER the command byte).
     */
    public Packet startCommand(final byte command) {
        writeOffset = HEADER_LEN;
        putByte(command);
        return this;
    }

    /**
     * Set the buffer's READ-position to the start of the payload.
     */
    public void startReadingPayload() {
        setReadOffSet(HEADER_LEN);
    }

    /**
     * Last step in creating the Packet is calculating and setting the final length,
     * and add padding as needed.
     */
    void finish(final int blockSize,
                final boolean includePacketLength,
                @NonNull final Random random) {

        int packetLen = writeOffset;
        if (!includePacketLength) {
            packetLen -= 4;
        }

        int paddingLength = (-packetLen) & (blockSize - 1);
        if (paddingLength < blockSize) {
            paddingLength += blockSize;
        }

        packetLen = packetLen + paddingLength;
        if (includePacketLength) {
            packetLen -= 4;
        }

        // store the new packet length into the first 4 bytes of the packet
        data[0] = (byte) (packetLen >>> 24);
        data[1] = (byte) (packetLen >>> 16);
        data[2] = (byte) (packetLen >>> 8);
        data[3] = (byte) (packetLen);
        // put the length of the padding in the 5th byte.
        data[4] = (byte) paddingLength;
        // finally add random data as the actual padding at the end of the packet
        putBytes(random.nextBytes(paddingLength));
    }

    /**
     * Read the actual length of the payload from the first 4 bytes of the buffer.
     *
     * @return The length of the packet in bytes, not including 'mac' or the
     * 'packet_length' field itself.
     */
    int getPacketLength() {
        return data[0] << 24 & 0xff000000 |
                data[1] << 16 & 0x00ff0000 |
                data[2] << 8 & 0x0000ff00 |
                data[3] & 0x000000ff;
    }

    /**
     * Read the length of the padding.
     *
     * @return 0..255
     */
    public int getPaddingLength() {
        return data[4];
    }

    /**
     * Read the command, i.e. the byte identifying the type of an SSH packet.
     * This is the first byte of the payload, i.e. the byte with index 5.
     * <p>
     * <strong>The read/write offsets are NOT modified</strong>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6">
     * RFC 4253 SSH Transport Layer Protocol, section 6. Binary Packet Protocol</a>
     */
    public byte getCommand() {
        return data[HEADER_LEN];
    }

    @Override
    @NonNull
    public String toString() {
        return "Packet{" +
                super.toString() +
                ", packet size=" + getPacketLength() +
                ", command=" + data[HEADER_LEN] +
                ", padding=" + data[4] +
                '}';
    }
}
