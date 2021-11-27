package com.hardbackcollector.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbackcollector.sshclient.keypair.KeyPairDSA;
import com.hardbackcollector.sshclient.keypair.KeyPairRSA;
import com.hardbackcollector.sshclient.keypair.SshKeyPair;
import com.hardbackcollector.sshclient.utils.Buffer;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.util.Base64;


/**
 * @see <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk">
 * PPK file format</a>
 * @see <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk-v2">
 * PPK version 2 file format</a>
 */
class PuttyReader {

    @NonNull
    private final SshClientConfig config;

    private final Base64.Decoder b64 = Base64.getDecoder();

    PuttyReader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Loads a key pair from a PuTTY file.
     *
     * @param reader MUST be a BufferedReader as we'll need to use mark/reset.
     * @return the new KeyPair.
     */
    @Nullable
    SshKeyPair parse(@NonNull final BufferedReader reader)
            throws IOException, GeneralSecurityException {

        reader.mark(32);

        Vendor privateKeyFormat = null;
        // First line identifies content and format version
        String line = reader.readLine();
        if (line != null) {
            if (line.startsWith("PuTTY-User-Key-File-2")) {
                privateKeyFormat = Vendor.PUTTY2;
            } else if (line.startsWith("PuTTY-User-Key-File-3")) {
                privateKeyFormat = Vendor.PUTTY3;
            } else {
                reader.reset();
                return null;
            }
        }

        String encryption = null;

        String publicKeyComment = "";

        byte[] prvKey = null;
        byte[] pubKey = null;

        while ((line = reader.readLine()) != null) {
            if (line.startsWith("Encryption: ")) {
                if (line.endsWith("none")) {
                    encryption = null;
                } else {
                    // "aes256-cbc"
                    encryption = line.substring(line.indexOf(':') + 2).strip();
                }

            } else if (line.startsWith("Comment: ")) {
                publicKeyComment = line.substring(line.indexOf(':') + 2).strip();

            } else if (line.startsWith("Public-Lines: ")) {
                pubKey = parseBase64(reader, line);

            } else if (line.startsWith("Private-Lines: ")) {
                prvKey = parseBase64(reader, line);
            }
        }

        if (pubKey == null || prvKey == null) {
            return null;
        }

        if (encryption != null && privateKeyFormat == Vendor.PUTTY3) {
            throw new KeyException("No support for PuTTY v3 Argon2 encrypted keys yet");
        }

        final Buffer buffer = new Buffer(pubKey);
        final String hostKeyAlgorithm = buffer.getJString();
        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA: {
                final BigInteger publicExponent = buffer.getBigInteger();
                final BigInteger modulus = buffer.getBigInteger();

                final KeyPairRSA.Builder builder =
                        new KeyPairRSA.Builder(config)
                                .setPublicExponent(publicExponent)
                                .setModulus(modulus);
                builder.setPrivateKeyBlob(prvKey, privateKeyFormat);

                if (encryption != null) {
                    builder.setPkeCipher(ImplementationFactory.getCipher(config, encryption));
                }

                final SshKeyPair keyPair = builder.build();
                keyPair.setPublicKeyComment(publicKeyComment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_DSS: {
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final BigInteger g = buffer.getBigInteger();
                final BigInteger y = buffer.getBigInteger();

                final KeyPairDSA.Builder builder =
                        new KeyPairDSA.Builder(config)
                                .setPQG(p, q, g)
                                .setY(y);

                builder.setPrivateKeyBlob(prvKey, privateKeyFormat);

                if (encryption != null) {
                    builder.setPkeCipher(ImplementationFactory.getCipher(config, encryption));
                }

                final SshKeyPair keyPair = builder.build();
                keyPair.setPublicKeyComment(publicKeyComment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521: {
                buffer.skipString(); // nist name

                throw new InvalidKeyException("Parsing PuTTY ECDSA keys is not supported");

                // final byte[] s = buffer.getString();

                // // ECPoint (encoded)
                // final byte[] point = buffer.getString();
                //
                //
                // final KeyPairECDSA.ECDSAKeyPairBuilder builder =
                //         new KeyPairECDSA.ECDSAKeyPairBuilder(config, ECUtils
                //                 .hostKeyAlgorithmToCurveName(hostKeyAlgorithm))
                //         .setPoint(point)
                //         .setS(s);
                //
                // if (encryption != null) {
                //     builder.setPkeCipher(SshCipher.getInstance(config, encryption));
                // }
                //
                // final SshKeyPair keyPair = builder.build();
                // keyPair.setPublicKeyComment(publicKeyComment);
                // return keyPair;
            }
            default:
                return null;
        }
    }

    @NonNull
    private byte[] parseBase64(@NonNull final BufferedReader br,
                               @NonNull String line)
            throws IOException, InvalidKeyException {
        final int lines = Integer.parseInt(line.substring(line.indexOf(':') + 2).strip());
        final StringBuilder bs = new StringBuilder();
        for (int i = 0; i < lines; i++) {
            line = br.readLine();
            if (line == null) {
                throw new InvalidKeyException("Not enough lines");
            }
            bs.append(line);
        }
        return b64.decode(bs.toString());
    }
}
