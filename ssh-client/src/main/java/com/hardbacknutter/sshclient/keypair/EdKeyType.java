package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public enum EdKeyType {
    Ed25519(HostKeyAlgorithm.SSH_ED25519,
            "Ed25519",
            32,
            EdECObjectIdentifiers.id_Ed25519),

    Ed448(HostKeyAlgorithm.SSH_ED448,
          "Ed448",
          57,
          EdECObjectIdentifiers.id_Ed448);

    @NonNull
    public final String hostKeyAlgorithm;
    @NonNull
    public final String curveName;

    public final int keySize;
    @NonNull
    public final ASN1ObjectIdentifier keyOid;

    EdKeyType(@NonNull final String hostKeyAlgorithm,
              @NonNull final String curveName,
              final int keySize,
              @NonNull final ASN1ObjectIdentifier keyOid) {

        this.hostKeyAlgorithm = hostKeyAlgorithm;
        this.curveName = curveName;
        this.keySize = keySize;
        this.keyOid = keyOid;
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
    public static EdKeyType getByCurveName(@NonNull final String curveName)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.curveName.equalsIgnoreCase(curveName))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static EdKeyType getByKeySize(final int keySize)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.keySize == keySize)
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    public static EdKeyType getByOid(@NonNull final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.keyOid.equals(oid))
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

    @NonNull
    public byte[] extractPubArray(@NonNull final EdDSAPublicKey pubKey) {
        final EdECPoint point = new EdECPoint(pubKey.getPointEncoding());
        final byte[] blob = rotate(point.getY().toByteArray(), keySize);
        if (point.isXOdd()) {
            final int pos = blob.length - 1;
            blob[pos] = (byte) (blob[pos] | 0x80);
        }
        return blob;
    }
}
