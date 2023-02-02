package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

public enum EdKeyType {
    Ed25519(HostKeyAlgorithm.SSH_ED25519,
            EdDSAParameterSpec.Ed25519,
            Ed25519PublicKeyParameters.KEY_SIZE,
            EdECObjectIdentifiers.id_Ed25519,
            "302a300506032b6570032100"),

    Ed448(HostKeyAlgorithm.SSH_ED448,
          EdDSAParameterSpec.Ed448,
          Ed448PublicKeyParameters.KEY_SIZE,
          EdECObjectIdentifiers.id_Ed448,
          "3043300506032b6571033a00");

    @NonNull
    public final String hostKeyAlgorithm;
    @NonNull
    public final String curveName;

    public final int keySize;
    @NonNull
    final ASN1ObjectIdentifier keyOid;

    /**
     * @see KeyPairEdDSA#setSshPublicKeyBlob(byte[])
     * @see org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi
     */
    private final byte[] prefix;

    EdKeyType(@NonNull final String hostKeyAlgorithm,
              @NonNull final String curveName,
              final int keySize,
              @NonNull final ASN1ObjectIdentifier keyOid,
              @NonNull final String prefix) {

        this.hostKeyAlgorithm = hostKeyAlgorithm;
        this.curveName = curveName;
        this.keySize = keySize;
        this.keyOid = keyOid;
        this.prefix = Hex.decode(prefix);
    }

    @NonNull
    public static EdKeyType getByHostKeyAlgorithm(@NonNull final String hostKeyAlgorithm)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.hostKeyAlgorithm.equalsIgnoreCase(hostKeyAlgorithm))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    private static byte[] rotate(@NonNull final byte[] in,
                                 final int keyLength) {
        final int len = in.length;
        final byte[] out = new byte[len];

        for (int i = 0; i < len; i++) {
            out[i] = in[len - i - 1];
        }

        return Arrays.copyOf(out, keyLength);
    }

    /**
     * Compare the whole of the first array with the start of the second one.
     *
     * @param shortest the shortest of the two arrays to compare
     * @param longer   the other array must be at least the same length as the first
     *
     * @return bool
     *
     * @see com.hardbacknutter.sshclient.utils.Util#arraysEquals(byte[], byte[])
     */
    private static boolean arraysRangeEquals(@NonNull final byte[] shortest,
                                             @NonNull final byte[] longer) {
        if (shortest.length > longer.length) {
            throw new IllegalArgumentException(
                    "first argument MUST be shorter or equal in length than the second");
        }

        int res = 0;
        for (int i = 0; i < shortest.length; i++) {
            res |= shortest[i] ^ longer[i];
        }
        return res == 0;
    }

    @NonNull
    byte[] extractPubArray(@NonNull final EdDSAPublicKey pubKey) {
        final EdECPoint point = new EdECPoint(pubKey.getPointEncoding());
        final byte[] blob = rotate(point.getY().toByteArray(), keySize);
        if (point.isXOdd()) {
            final int pos = blob.length - 1;
            blob[pos] = (byte) (blob[pos] | 0x80);
        }
        return blob;
    }

    @NonNull
    Optional<byte[]> stripPrefix(@NonNull final byte[] publicKeyBlob) {
        // When we get a public key blob coming from openssl, it will be 44 bytes long
        // I can't say I fully understand WHY... RFC 8032 does talk about a prefix,
        // but I'm not sure that's the same thing.
        // The next lines of code were inspired by
        // org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi
        // Ed25519Prefix = Hex.decode("302a300506032b6570032100"); (and Ed448...)
        // We just cut the prefix, and take the remainder 32 bytes. It works.

        if (publicKeyBlob.length == prefix.length + keySize) {
            if (arraysRangeEquals(prefix, publicKeyBlob)) {
                final byte[] pub_array = new byte[keySize];
                System.arraycopy(publicKeyBlob, prefix.length, pub_array, 0, keySize);
                return Optional.of(pub_array);
            }
        } else if (publicKeyBlob.length == keySize) {
            return Optional.of(publicKeyBlob);
        }

        return Optional.empty();
    }
}
