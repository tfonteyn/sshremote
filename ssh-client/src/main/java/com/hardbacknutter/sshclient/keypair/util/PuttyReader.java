package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.pbkdf.PBKDF2Argon;
import com.hardbacknutter.sshclient.pbkdf.PBKDFPutty2;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Base64;


/**
 * @see <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk">
 * PPK file format</a>
 * @see <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk-v2">
 * PPK version 2 file format</a>
 */
class PuttyReader {

    private static final byte[] Z_BYTE_ARRAY = new byte[0];

    @NonNull
    private final SshClientConfig config;

    private final Base64.Decoder b64 = Base64.getDecoder();

    /**
     * Constructor.
     */
    PuttyReader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Loads a key pair from a PuTTY file.
     *
     * @param reader MUST be a BufferedReader as we'll need to use mark/reset.
     *
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
        String argonKeyDerivation = null;
        String argonMemory = null;
        String argonPasses = null;
        String argonParallelism = null;
        String argonSalt = null;

        String publicKeyComment = "";

        byte[] prvKey = null;
        byte[] pubKey = null;

        while ((line = reader.readLine()) != null) {
            final String value = line.substring(line.indexOf(':') + 2).trim();

            if (line.startsWith("Encryption: ")) {
                if ("none".equals(value)) {
                    encryption = null;
                } else if ("aes256-cbc".equals(value)) {
                    encryption = value;
                }

            } else if (line.startsWith("Comment: ")) {
                publicKeyComment = value;

            } else if (line.startsWith("Public-Lines: ")) {
                pubKey = parseBase64(reader, line);

            } else if (line.startsWith("Private-Lines: ")) {
                prvKey = parseBase64(reader, line);

            } else if (line.startsWith("Key-Derivation: ")) {
                argonKeyDerivation = value;
            } else if (line.startsWith("Argon2-Memory: ")) {
                argonMemory = value;
            } else if (line.startsWith("Argon2-Passes: ")) {
                argonPasses = value;
            } else if (line.startsWith("Argon2-Parallelism: ")) {
                argonParallelism = value;
            } else if (line.startsWith("Argon2-Salt: ")) {
                argonSalt = value;
            }
        }

        if (pubKey == null || prvKey == null) {
            return null;
        }

        SshCipher cipher = null;
        PBKDF pbkdf = null;
        if (encryption != null) {
            if (privateKeyFormat == Vendor.PUTTY3) {
                pbkdf = new PBKDF2Argon(argonKeyDerivation,
                                        argonMemory, argonPasses, argonParallelism,
                                        argonSalt,
                                        //  a secret key, and some ‘associated data’.
                                        //  In PPK's use of Argon2, these are both set
                                        //  to the empty string.
                                        Z_BYTE_ARRAY, Z_BYTE_ARRAY);
            } else {
                pbkdf = new PBKDFPutty2();
            }

            cipher = ImplementationFactory.getCipher(config, encryption);
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

                builder.setPrivateKeyBlob(prvKey, privateKeyFormat, pbkdf);

                if (cipher != null) {
                    builder.setPkeCipher(cipher);
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

                builder.setPrivateKeyBlob(prvKey, privateKeyFormat, pbkdf);

                if (cipher != null) {
                    builder.setPkeCipher(cipher);
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
        final int lines = Integer.parseInt(line.substring(line.indexOf(':') + 2).trim());
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
