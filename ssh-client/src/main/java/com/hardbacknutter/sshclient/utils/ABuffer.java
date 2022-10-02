package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.transport.Packet;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * A chunk of bytes together with methods to access them.
 * This implements the low-level protocol elements used by the
 * different layers of the SSH protocol.
 * <p>
 * The Buffer maintains a {@link #writeOffset} (from where on the put methods
 * write, updating it on the way) and a {@linkplain #getReadOffSet readOffset}.
 * The readOffset is used by the get methods to read (and they update the
 * readOffset, too).
 * <p>
 * If a buffer is used for both reading and writing, the
 * {@link #writeOffset} should normally be bigger than the {@link #readOffset}.
 * Initially both are 0.
 * </p>
 *
 * @see <a href="http://datatracker.ietf.org/doc/html/rfc4251#section-5">
 * RFC 4251 SSH Protocol Architecture,
 * section 5. Data Type Representations Used in the SSH Protocols</a>
 */
public abstract class ABuffer<T extends ABuffer<T>> {

    private static final String ERROR_PACKET_SIZE_EXCEEDED_INT_MAX =
            "Packet size exceeded Integer.MAX_VALUE";

    /** The default size for the buffer. */
    private static final int DEFAULT_SIZE = 256;

    private final boolean fixedSize;

    @NonNull
    public byte[] data;

    /** The position where the next PUT operation will put data. */
    public int writeOffset;
    /** The position from which the next GET operation will read. */
    private int readOffset;

    /**
     * Create a buffer with a default size. The buffer MAY expand when needed.
     */
    protected ABuffer() {
        this(DEFAULT_SIZE, false);
    }

    /**
     * Create a buffer.
     *
     * @param size  to use
     * @param fixed {@code true}: fix the size; the buffer will never expand.
     *              {@code false}: the buffer MAY expand when needed.
     */
    protected ABuffer(final int size,
                      final boolean fixed) {
        this.fixedSize = fixed;
        if (fixed) {
            data = new byte[size];
        } else {
            data = new byte[getNextPowerOf2(size)];
        }
    }

    /**
     * Create a buffer using the given array as backing store. The buffer size is fixed.
     */
    ABuffer(@NonNull final byte[] data) {
        this.fixedSize = true;
        this.data = data;
    }

    /**
     * Copy constructor.
     *
     * @param other to copy from
     */
    protected ABuffer(@NonNull final ABuffer<T> other) {
        this.fixedSize = other.fixedSize;
        this.readOffset = other.readOffset;
        this.writeOffset = other.writeOffset;
        this.data = Arrays.copyOf(other.data, other.data.length);
    }

    private static int getNextPowerOf2(final int v) {
        int j = 1;
        while (j < v) {
            j <<= 1;
            if (j <= 0) {
                throw new IllegalArgumentException(
                        "Cannot get next power of 2; " + v + " is too large");
            }
        }
        return j;
    }

    /**
     * Clears the entire internal buffer by setting all values to 0
     * and sets read/write positions to the start of the buffer.
     */
    public void zero() {
        reset();
        Arrays.fill(data, (byte) 0);
    }

    /**
     * reset both the read and write position to the start of the buffer.
     */
    @NonNull
    public T reset() {
        writeOffset = 0;
        readOffset = 0;
        //noinspection unchecked
        return (T) this;
    }

    /**
     * returns the current absolute position for the next read.
     */
    public int getReadOffSet() {
        return readOffset;
    }

    /**
     * Set the absolute position for the next read.
     *
     * @param offset the new offset.
     */
    public void setReadOffSet(final int offset) {
        readOffset = offset;
    }

    /**
     * Set the absolute position for the next write.
     *
     * @param offset the new offset.
     */
    @NonNull
    public T setWriteOffSet(final int offset) {
        writeOffset = offset;
        //noinspection unchecked
        return (T) this;
    }

    /**
     * Move the write position forward by the given number of bytes.
     * (or backwards if the number is negative);
     */
    @NonNull
    public T moveWritePosition(final int n) {
        if (n > 0) {
            ensureCapacity(n);
        } else if (n + writeOffset < 0) {
            throw new IllegalArgumentException("writeOffset=" + writeOffset + ", n=" + n);
        }
        writeOffset += n;
        //noinspection unchecked
        return (T) this;
    }


    /**
     * Shifts the contents between {@link #readOffset} and  {@link #writeOffset}
     * back to the start of the buffer, and adjusts those two values accordingly.
     */
    public void shiftBuffer() {
        if (readOffset == 0) {
            return;
        }
        System.arraycopy(data, readOffset, data, 0, writeOffset - readOffset);
        writeOffset = writeOffset - readOffset;
        readOffset = 0;
    }

    /**
     * Get the amount of bytes available to read.
     *
     * @return the difference between the {@link #readOffset} and  {@link #writeOffset}
     */
    public int availableToRead() {
        return writeOffset - readOffset;
    }

    /**
     * Get the amount of bytes available to write before the buffer will expand.
     *
     * @return the difference between the buffer length and the {@link #writeOffset}
     */
    public int spaceLeft() {
        return data.length - writeOffset;
    }

    /**
     * Puts one byte into the buffer.
     */
    @NonNull
    public T putByte(final byte b) {
        ensureCapacity(1);
        data[writeOffset++] = b;
        //noinspection unchecked
        return (T) this;
    }

    /**
     * Puts all bytes from the given byte array in the buffer.
     */
    @NonNull
    public T putBytes(@NonNull final byte[] bytes) {
        ensureCapacity(bytes.length);
        System.arraycopy(bytes, 0, data, writeOffset, bytes.length);
        writeOffset += bytes.length;
        //noinspection unchecked
        return (T) this;
    }

    /**
     * Puts a subsequence of the given byte array in the buffer.
     */
    @NonNull
    public T putBytes(@NonNull final byte[] bytes,
                      final int offset,
                      final int length) {
        ensureCapacity(length);
        System.arraycopy(bytes, offset, data, writeOffset, length);
        writeOffset += length;
        //noinspection unchecked
        return (T) this;
    }

    @NonNull
    public T putBoolean(final boolean bool) {
        return putByte((byte) (bool ? 1 : 0));
    }

    /**
     * Puts a 32-bit number as 4 bytes (network byte order) into the buffer.
     */
    @NonNull
    public T putInt(final int val) {
        ensureCapacity(4);
        data[writeOffset++] = (byte) (val >>> 24);
        data[writeOffset++] = (byte) (val >>> 16);
        data[writeOffset++] = (byte) (val >>> 8);
        data[writeOffset++] = (byte) (val);
        //noinspection unchecked
        return (T) this;
    }

    /**
     * Puts a 64-bit number as 8 bytes (network byte order) into the buffer.
     */
    @NonNull
    public T putLong(final long val) {
        ensureCapacity(8);
        data[writeOffset++] = (byte) (val >>> 56);
        data[writeOffset++] = (byte) (val >>> 48);
        data[writeOffset++] = (byte) (val >>> 40);
        data[writeOffset++] = (byte) (val >>> 32);
        data[writeOffset++] = (byte) (val >>> 24);
        data[writeOffset++] = (byte) (val >>> 16);
        data[writeOffset++] = (byte) (val >>> 8);
        data[writeOffset++] = (byte) (val);
        //noinspection unchecked
        return (T) this;
    }

    /**
     * Puts a byte[] as an unsigned multiple precision integer (mpint).
     * This consists of first the number of bytes as a
     * {@linkplain #putInt 32-bit integer}, then the bytes of the number
     * themselves.
     *
     * <pre>
     *    mpint
     *
     *       Represents multiple precision integers in two's complement format,
     *       stored as a string, 8 bits per byte, MSB first.  Negative numbers
     *       have the value 1 as the most significant bit of the first byte of
     *       the data partition.  If the most significant bit would be set for
     *       a positive number, the number MUST be preceded by a zero byte.
     *       Unnecessary leading bytes with the value 0 or 255 MUST NOT be
     *       included.  The value zero MUST be stored as a string with zero
     *       bytes of data.
     * </pre>
     *
     * @see #getMPInt()
     * @see #getBigInteger()
     */
    @NonNull
    public T putMPInt(@NonNull final byte[] bytes) {
        int i = bytes.length;
        if ((bytes[0] & 0x80) == 0) {
            putInt(i);
        } else {
            i++;
            putInt(i);
            putByte((byte) 0);
        }
        return putBytes(bytes);
    }

    public T putBigInteger(@NonNull final BigInteger val) {
        //TODO: or use putMPInt?
        return putMPInt(val.toByteArray());
    }

    /**
     * Put a Java String formatted as a SSH string into the buffer.
     */
    @NonNull
    public T putString(@NonNull final String str) {
        return putString(str.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Put a byte sequence formatted as a SSH string into the buffer.
     *
     * @see #putString(byte[], int, int)
     */
    @NonNull
    public T putString(@NonNull final byte[] bytes) {
        return putString(bytes, 0, bytes.length);
    }

    /**
     * Put a byte sequence formatted as a SSH string into the buffer.
     * <p>
     * A SSH string consists of first a (big-endian) 32-bit number indicating
     * the length of the string (number of bytes), then the bytes themselves.
     *
     * @param bytes  the array from which we take the data.
     * @param offset the start of the data in the array.
     * @param length how many bytes to put.
     */
    @NonNull
    public T putString(@NonNull final byte[] bytes,
                       final int offset,
                       final int length) {
        return putInt(length).putBytes(bytes, offset, length);
    }

    /**
     * Ensures that at least {@code n} <strong>more</strong> bytes can be
     * put into the packet (i.e. current size PLUS 'n')
     *
     * @throws IllegalStateException if the buffer has a fixed size and is full
     */
    public void ensureCapacity(final int n) {
        if (data.length - writeOffset < n) {
            if (fixedSize) {
                throw new IllegalStateException(
                        "Buffer size is fixed at: " + data.length
                                + ", but " + n + " more bytes are needed");
            }
            final byte[] tmpBuffer = new byte[getNextPowerOf2(writeOffset + n)];
            System.arraycopy(data, 0, tmpBuffer, 0, data.length);
            data = tmpBuffer;
        }
    }

    /**
     * Reads a single (unsigned) byte from the buffer.
     */
    public byte getByte() {
        return data[readOffset++];
    }

    /**
     * Reads a byte array from the buffer starting at the current {@link #readOffset}.
     *
     * @param dest the array to put the bytes to. This array will
     *             be filled, i.e. we read dest.length bytes from the buffer.
     */
    public void getBytes(@NonNull final byte[] dest) {
        System.arraycopy(data, readOffset, dest, 0, dest.length);
        readOffset += dest.length;
    }

    /**
     * reads a byte array from the buffer starting at the current {@link #readOffset}.
     *
     * @param dest   the array to put the bytes to.
     * @param offset the start index in the destination array.
     * @param length the number of bytes to read.
     */
    private void getBytes(@NonNull final byte[] dest,
                          @SuppressWarnings("SameParameterValue") final int offset,
                          final int length) {
        System.arraycopy(data, readOffset, dest, offset, length);
        readOffset += length;
    }

    public boolean getBoolean() {
        return (getByte() != 0);
    }

    /**
     * reads a 64-bit number from the buffer.
     */
    public long getLong() {
        return ((getInt() & 0xffffffffL) << 32) | ((getInt() & 0xffffffffL));
    }

    /**
     * reads a signed 32-bit number from the buffer.
     */
    public int getInt() {
        return ((data[readOffset++] & 0xff) << 24)
                | ((data[readOffset++] & 0xff) << 16)
                | ((data[readOffset++] & 0xff) << 8)
                | ((data[readOffset++] & 0xff));
    }

    /**
     * reads an unsigned 32-bit number from the buffer.
     */
    public long getUInt() {
        return (((long) (data[readOffset++] & 0xff)) << 24)
                | (((long) (data[readOffset++] & 0xff)) << 16)
                | (((long) (data[readOffset++] & 0xff)) << 8)
                | ((long) (data[readOffset++] & 0xff));
    }


    /**
     * Length-prefixed..
     * <p>
     * Get a Java String (converted from an SSH String).
     *
     * @return String
     *
     * @throws IOException for illegal sizes
     */
    @NonNull
    public String getJString()
            throws IOException {
        final byte[] buf = getString();
        return new String(buf, 0, buf.length, StandardCharsets.UTF_8);
    }

    /**
     * Length-prefixed..
     * <p>
     * reads an SSH String, which is a byte[]
     *
     * @return a new byte[] with the contents of the string.
     *
     * @throws IOException for illegal sizes
     * @see #putString
     */
    @NonNull
    public byte[] getString()
            throws IOException {
        // uint32 but we can't have out-of-memory
        final int len = getInt();
        if (len < 0) {
            throw new IOException(ERROR_PACKET_SIZE_EXCEEDED_INT_MAX);
        } else if (len > Packet.MAX_SIZE) {
            // avoid out-of-memory...
            throw new IOException("Packet size exceeded len=" + len);
        }
        final byte[] dest = new byte[len];
        getBytes(dest, 0, len);
        return dest;
    }

    /**
     * Length-prefixed..
     * <p>
     * reads an SSH String, and ignores/skips it.
     */
    public void skipString() {
        final int len = getInt();
        readOffset += len;
    }

    public void skip(final int n) {
        readOffset += n;
    }

    @NonNull
    public BigInteger getBigInteger()
            throws IOException {
        return new BigInteger(1, getMPInt());
    }

    /**
     * Length-prefixed.
     * <p>
     * reads a multiple-precision (signed) integer.
     *
     * @see #putMPInt(byte[])
     */
    @NonNull
    public byte[] getMPInt()
            throws IOException {
        // uint32 but we can't have out-of-memory
        final int len = getInt();
        if (len < 0) {
            throw new IOException(ERROR_PACKET_SIZE_EXCEEDED_INT_MAX);
        } else if (len > Packet.MAX_SIZE) {
            // avoid out-of-memory...
            throw new IOException("Packet size exceeded len=" + len);
        }
        final byte[] dest = new byte[len];
        getBytes(dest, 0, len);
        return dest;
    }

    /**
     * Length-prefixed..
     * <p>
     * reads a multiple precision signed integer as unsigned.
     * i.e. the highest-order bit is guaranteed to be 0.
     */
    @NonNull
    public byte[] getMPIntBits() {
        final int bits = getInt();
        final int len = (bits + 7) / 8;

        byte[] dest = new byte[len];
        getBytes(dest, 0, len);
        if ((dest[0] & 0x80) != 0) {
            final byte[] tmpBytes = new byte[dest.length + 1];
            tmpBytes[0] = 0; // ??
            System.arraycopy(dest, 0, tmpBytes, 1, dest.length);
            dest = tmpBytes;
        }
        return dest;
    }

    @Override
    @NonNull
    public String toString() {
        return "ABuffer{"
                + "fixedSize=" + fixedSize
                + ", data.length=" + data.length
                + ", writeOffset=" + writeOffset
                + ", readOffset=" + readOffset
                + '}';
    }
}
