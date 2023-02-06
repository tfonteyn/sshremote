package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.security.NoSuchAlgorithmException;

public final class KeyPairBuilderFactory {

    private KeyPairBuilderFactory() {
    }

    // we could merge this with byHostKeyAlgorithm, but lets keep it clean
    @NonNull
    public static KeyPairBuilder byPemHeader(@NonNull final SshClientConfig config,
                                             @NonNull final String pemHeader)
            throws UnsupportedAlgorithmException, NoSuchAlgorithmException {
        switch (pemHeader) {
            case "RSA PRIVATE KEY": {
                return new KeyPairRSA.Builder(config);
            }
            case "DSA PRIVATE KEY": {
                return new KeyPairDSA.Builder(config);
            }
            case "EC PRIVATE KEY": {
                return new KeyPairECDSA.Builder(config, null);
            }
            default:
                throw new UnsupportedAlgorithmException(pemHeader);
        }
    }

    @NonNull
    public static KeyPairBuilder byHostKeyAlgorithm(@NonNull final SshClientConfig config,
                                                    @NonNull final String hostKeyAlgorithm)
            throws UnsupportedAlgorithmException, NoSuchAlgorithmException {
        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA:
                return new KeyPairRSA.Builder(config);

            case HostKeyAlgorithm.SSH_DSS:
                return new KeyPairDSA.Builder(config);

            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
                return new KeyPairECDSA.Builder(config, hostKeyAlgorithm);

            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448:
                return new KeyPairEdDSA.Builder(config, hostKeyAlgorithm);

            default:
                throw new UnsupportedAlgorithmException(hostKeyAlgorithm);
        }
    }

    @SuppressWarnings("WeakerAccess")
    @NonNull
    public static KeyPairBuilder byOID(@NonNull final SshClientConfig config,
                                       @NonNull final ASN1ObjectIdentifier prvKeyAlgOID)
            throws UnsupportedAlgorithmException, NoSuchAlgorithmException {
        if (PKCSObjectIdentifiers.rsaEncryption.equals(prvKeyAlgOID)) {
            return new KeyPairRSA.Builder(config);

        } else if (X9ObjectIdentifiers.id_dsa.equals(prvKeyAlgOID)) {
            return new KeyPairDSA.Builder(config);

        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(prvKeyAlgOID)) {
            return new KeyPairECDSA.Builder(config, null);

        } else if (EdECObjectIdentifiers.id_Ed25519.equals(prvKeyAlgOID)
                || EdECObjectIdentifiers.id_Ed448.equals(prvKeyAlgOID)) {
            return new KeyPairEdDSA.Builder(config, null);

        } else {
            throw new UnsupportedAlgorithmException(String.valueOf(prvKeyAlgOID));
        }
    }
}
