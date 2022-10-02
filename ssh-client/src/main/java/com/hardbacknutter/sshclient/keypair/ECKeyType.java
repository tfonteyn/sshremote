package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.util.Arrays;

public enum ECKeyType {

    ECDSA_SHA2_NISTP256(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256,
                        "secp256r1",
                        "nistp256",
                        256,
                        SECObjectIdentifiers.secp256r1),

    ECDSA_SHA2_NISTP384(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384,
                        "secp384r1",
                        "nistp384",
                        384,
                        SECObjectIdentifiers.secp384r1),

    ECDSA_SHA2_NISTP521(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521,
                        "secp521r1",
                        "nistp521",
                        521,
                        SECObjectIdentifiers.secp521r1);

    /**
     * Flag: (un)compressed.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc5480#section-2.2">
     * rfc5480, section 2.2, second bullet</a>
     */
    private static final int POINT_CONVERSION_UNCOMPRESSED = 0x04;
    @NonNull
    public final String hostKeyAlgorithm;
    @NonNull
    public final String curveName;
    @NonNull
    public final String nistName;
    public final int keySize;
    @NonNull
    public final ASN1ObjectIdentifier keyOid;

    ECKeyType(@NonNull final String hostKeyAlgorithm,
              @NonNull final String curveName,
              @NonNull final String nistName,
              final int keySize,
              @NonNull final ASN1ObjectIdentifier keyOid) {

        this.hostKeyAlgorithm = hostKeyAlgorithm;
        this.curveName = curveName;
        this.nistName = nistName;
        this.keySize = keySize;
        this.keyOid = keyOid;
    }

    @NonNull
    public static ECKeyType getByHostKeyAlgorithm(@NonNull final String hostKeyAlgorithm)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.hostKeyAlgorithm.equalsIgnoreCase(hostKeyAlgorithm))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static ECKeyType getByCurveName(@NonNull final String curveName)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.curveName.equalsIgnoreCase(curveName))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static ECKeyType getByNistName(@NonNull final String nistName)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.nistName.equalsIgnoreCase(nistName))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static ECKeyType getByKeySize(final int keySize)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.keySize == keySize)
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static ECKeyType getByOid(@NonNull final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.keyOid.equals(oid))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static ECKeyType getByECPoint(@NonNull final ECPoint point)
            throws NoSuchAlgorithmException {
        final int keySize = point.getAffineX().toByteArray().length;
        if (keySize >= 64) {
            return ECDSA_SHA2_NISTP521;
        } else if (keySize >= 48) {
            return ECDSA_SHA2_NISTP384;
        } else if (keySize >= 32) {
            return ECDSA_SHA2_NISTP256;
        } else {
            throw new NoSuchAlgorithmException();
        }
    }

    @NonNull
    public static ECPoint decodePoint(@NonNull final byte[] encodedPoint)
            throws IOException {

        if ((encodedPoint.length == 0) || (encodedPoint[0] != POINT_CONVERSION_UNCOMPRESSED)) {
            throw new IOException("Only uncompressed point format supported");
        }

        final int n = (encodedPoint.length - 1) / 2;
        final byte[] xb = Arrays.copyOfRange(encodedPoint, 1, 1 + n);
        final byte[] yb = Arrays.copyOfRange(encodedPoint, n + 1, n + 1 + n);

        return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
    }

    @NonNull
    private static byte[] trimZeroes(@NonNull final byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        if (i == 0) {
            return b;
        }

        return Arrays.copyOfRange(b, i, b.length);
    }

    /**
     * Encode a {@link ECPoint} to a byte array using the correct key size for this type.
     */
    @NonNull
    public byte[] encodePoint(@NonNull final ECPoint w) {
        // bits: 256(32)/384(48)/521(66)
        // get field size in bytes (rounding up)
        final int n = (keySize + 7) >> 3;

        final byte[] xb = trimZeroes(w.getAffineX().toByteArray());
        final byte[] yb = trimZeroes(w.getAffineY().toByteArray());
        if ((xb.length > n) || (yb.length > n)) {
            throw new RuntimeException("Point coordinates do not match field size");
        }

        final byte[] b = new byte[1 + (n << 1)];
        b[0] = POINT_CONVERSION_UNCOMPRESSED;
        System.arraycopy(xb, 0, b, n - xb.length + 1, xb.length);
        System.arraycopy(yb, 0, b, b.length - yb.length, yb.length);
        return b;
    }
}
