package com.hardbackcollector.sshclient.keypair;


import androidx.annotation.NonNull;

import java.math.BigInteger;

/**
 * An elliptic curve point used to specify keys as defined by RFC 8032.
 * These points are distinct from the points represented by {@code ECPoint},
 * and they are intended for use with algorithms based on RFC 8032
 * such as the EdDSA {@code Signature} algorithm.
 * <p>
 * An EdEC point is specified by its y-coordinate value and a boolean that
 * indicates whether the x-coordinate is odd. The y-coordinate is an
 * element of the field of integers modulo some value p that is determined by
 * the algorithm parameters. This field element is represented by a
 * {@code BigInteger}, and implementations that consume objects of this class
 * may reject integer values which are not in the range [0, p).
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8032">
 * RFC 8032 Edwards-Curve Digital Signature Algorithm (EdDSA)</a>
 */

final class EdECPoint {

    private final boolean xOdd;
    @NonNull
    private final BigInteger y;

    /**
     * Constructor.
     */
    EdECPoint(@NonNull final byte[] encodedPoint) {
        final byte msb = encodedPoint[encodedPoint.length - 1];
        encodedPoint[encodedPoint.length - 1] =
                (byte) (encodedPoint[encodedPoint.length - 1] & (byte) 0x7F);
        xOdd = (msb & 0x80) != 0;
        reverse(encodedPoint);
        y = new BigInteger(1, encodedPoint);
    }

    /**
     * Get whether the x-coordinate of the point is odd.
     *
     * @return a boolean indicating whether the x-coordinate is odd.
     */
    boolean isXOdd() {
        return xOdd;
    }

    /**
     * Get the y-coordinate of the point.
     *
     * @return the y-coordinate, represented using a {@code BigInteger}.
     */
    @NonNull
    BigInteger getY() {
        return y;
    }

    private void reverse(@NonNull final byte[] arr) {
        int i = 0;
        int j = arr.length - 1;

        while (i < j) {
            final byte tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
            i++;
            j--;
        }
    }
}
