package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;

/**
 * Random number generator.
 * <p>
 * This is used to:
 * <ul>
 * <li>create key pairs</li>
 * <li>salt the known hosts entries in the hashed format</li>
 * <li>random padding of a packet before encrypting</li>
 * <li>create the random session cookie</li>
 * </ul>
 * The library will choose the implementation class by the configuration
 * option {@link #RANDOM}, and instantiate it using the no-argument constructor.
 * <p>
 * The library includes a default implementation, based on a {@link java.security.SecureRandom}.
 * </p>
 * <p>
 * An application might implement this interface to provide an alternative
 * random number generator, maybe based on some hardware device.
 * </p>
 */
public interface Random {

    String RANDOM = "random";

    /**
     * Convenience method.
     * <p>
     * Creates and fills a byte array with random bits.
     *
     * @param length the length of the segment to be filled with random data,
     *               in bytes. There will be {@code 8 * length} random bits generated.
     *
     * @return a <strong>new</strong> byte array with random data
     */
    @NonNull
    default byte[] nextBytes(final int length) {
        final byte[] buf = new byte[length];
        fill(buf, 0, buf.length);
        return buf;
    }

    /**
     * Fills a segment of a byte array with random bits.
     * Implementations <strong>must</strong> be thread safe.
     *
     * @param buf    the array to put the random data into.
     * @param start  the position in the array from where on the random data
     *               should be put.
     * @param length the length of the segment to be filled with random data,
     *               in bytes. There will be {@code 8 * length} random bits generated.
     */
    void fill(@NonNull byte[] buf,
              int start,
              int length);
}
