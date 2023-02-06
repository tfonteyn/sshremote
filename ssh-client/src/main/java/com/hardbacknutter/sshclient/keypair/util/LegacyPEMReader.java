package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.KeyPairBuilderFactory;
import com.hardbacknutter.sshclient.keypair.PrivateKeyEncoding;
import com.hardbacknutter.sshclient.keypair.PublicKeyEncoding;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPKCS5;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

class LegacyPEMReader {

    @NonNull
    private final SshClientConfig config;

    LegacyPEMReader(@NonNull final SshClientConfig config) {
        this.config = config;
    }


    @NonNull
    SshKeyPair parse(@NonNull final PemObject pem,
                     @Nullable final byte[] publicKeyBlob,
                     @Nullable final PublicKeyEncoding publicKeyEncoding)
            throws InvalidKeyException, GeneralSecurityException, IOException {

        return KeyPairBuilderFactory
                .byPemHeader(config, pem.getType())
                .setPrivateKey(pem.getContent(), PrivateKeyEncoding.ASN1)
                .setPublicKey(publicKeyBlob, publicKeyEncoding)
                .setDecryptor(createDecryptor(pem))
                .build();
    }

    @Nullable
    private PKDecryptor createDecryptor(@NonNull final PemObject pem)
            throws InvalidKeyException, NoSuchAlgorithmException {
        //noinspection unchecked
        for (final PemHeader header : (List<PemHeader>) pem.getHeaders()) {
            if ("DEK-Info".equals(header.getName())) {
                // DEK-Info: AES-128-CBC,D54228DB5838E32589695E83A22595C7
                // The cipher names are (of course) different from what we need.
                // The encryption algorithm name is as used by OpenSSL EVP_get_cipherbyname()
                // As this header type is (August 2021) ancient, we're not doing much effort here...
                final String[] values = header.getValue().split(",");
                if (values.length == 2) {
                    final SshCipher cipher = ImplementationFactory
                            .getCipher(config, getSshCipherName(values[0]));
                    final byte[] iv = createIV(values[1], cipher.getIVSize());
                    // uses the iv as the salt
                    final PKDecryptor decryptor = new DecryptPKCS5().init("MD5", iv);
                    decryptor.setCipher(cipher, iv);
                    return decryptor;
                }
            }
        }
        return null;
    }

    @NonNull
    private String getSshCipherName(@NonNull final String pemCipher)
            throws InvalidKeyException {
        switch (pemCipher) {
            case "AES-128-CBC":
                return "aes128-cbc";
            case "AES-192-CBC":
                return "aes192-cbc";
            case "AES-256-CBC":
                return "aes256-cbc";
            case "DES-EDE3-CBC":
                return "3des-cbc";
            default:
                throw new InvalidKeyException("Invalid Cipher");
        }
    }

    @NonNull
    private byte[] createIV(@NonNull final String pemIV,
                            final int ivSize) throws InvalidKeyException {
        final byte[] iv = new byte[ivSize];
        try {
            final byte[] bytes = pemIV.getBytes(StandardCharsets.UTF_8);
            int b = 0;
            for (int i = 0; i < iv.length; i++) {
                iv[i] = (byte) (((Character.digit(bytes[b++], 16) << 4) & 0xf0)
                        | Character.digit(bytes[b++], 16) & 0x0f);
            }
        } catch (final IllegalArgumentException e) {
            throw new InvalidKeyException("Invalid IV");
        }
        return iv;
    }
}
