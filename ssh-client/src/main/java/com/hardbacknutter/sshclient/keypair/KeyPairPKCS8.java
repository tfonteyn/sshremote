package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPKCS8;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 * A PKCS#8 KeyPair is a wrapper containing the actual KeyPair as {@link #delegate}.
 * <p>
 * The type / {@link #delegate} is available after a {@link #parsePrivateKey} when constructing.
 * Decrypting passphrase protected keys is as normal with {@link #decryptPrivateKey(byte[])}.
 * <p>
 * Keys are usually created with:
 * <pre>
 *      1. Create key pair
 *          openssl genrsa -out keypair.pem 2048
 *
 *      2. Extract public part
 *          openssl rsa -in keypair.pem -pubout -out publickey.crt
 *
 *      3. Extract private part (unencrypted)
 *          openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898#section-6.2>
 * RFC 2898 PKCS#5 Password-Based Cryptography Specification, section 6.2. PBES2</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5958">
 * RFC 5958 Asymmetric Key Packages</a> obsoletes 5208
 */
public final class KeyPairPKCS8
        extends DelegatingKeyPair {

    private static final ASN1ObjectIdentifier id_ed25519 = new ASN1ObjectIdentifier("1.3.101.112");
    private static final ASN1ObjectIdentifier id_ed448 = new ASN1ObjectIdentifier("1.3.101.113");


    /**
     * Constructor.
     */
    private KeyPairPKCS8(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, Vendor.PKCS8,
              false, new DecryptPKCS8(config));

        parse();
    }

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {

        if (delegate != null) {
            delegate.parsePrivateKey(encodedKey, keyFormat);
            return;
        }

        // Take a copy of these BEFORE we create the delegate.
        // We'll set them on the delegate after its creation
        final byte[] sshPublicKeyBlob = getSshPublicKeyBlob();
        final String publicKeyComment = getPublicKeyComment();

        // parse the wrapper, and create the delegate
        try {
            final ASN1Sequence root;
            try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                root = ASN1Sequence.getInstance(stream.readObject());
            }
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger()
                      .log(Logger.DEBUG, () -> "~~~ KeyPairPKCS8#parsePrivateKey ~~~\n" +
                              ASN1Dump.dumpAsString(root, true));
            }

            // DSA
            // Sequence                                         ==> 'root'
            //     Integer(0)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.2.840.10040.4.1)      ==> 'prvKeyAlgOID'
            //         Sequence                                 ==> attributes
            //             Integer(177451...                    ==> p
            //             Integer(131449...                    ==> q
            //             Integer(163872...                    ==> g
            //     DER Octet String[23]                         ==> 'privateKey'
            //         02150097...


            // RSA
            // Sequence                                         ==> 'root'
            //     Integer(0)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.2.840.113549.1.1.1)   ==> 'prvKeyAlgOID'
            //         NULL                                     ==> attributes, none for RSA
            //     DER Octet String[1193]                       ==> 'privateKey'
            //         308204a50...

            // ECDSA 256
            // Sequence                                         ==> 'root'
            //     Integer(0)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.2.840.10045.2.1)      ==> 'prvKeyAlgOID'
            //         ObjectIdentifier(1.2.840.10045.3.1.7)    ==> curve
            //     DER Octet String[109]                        ==> 'privateKey'
            //         306b02010...

            // Ed25519
            // Sequence                                         ==> 'root'
            //     Integer(1)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.3.101.112)            ==> 'prvKeyAlgOID'
            //     DER Octet String[34]                         ==> 'privateKey'
            //         0420031...
            //     Tagged [1] IMPLICIT
            //         DER Octet String[33]
            //             0031ae3...

            // Ed448
            // Sequence                                         ==> 'root'
            //     Integer(1)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.3.101.113)            ==> 'prvKeyAlgOID'
            //     DER Octet String[59]                         ==> 'privateKey'
            //         0439580...
            //     Tagged [1] IMPLICIT
            //         DER Octet String[58]
            //             00123

            final ASN1Integer version = ASN1Integer.getInstance(root.getObjectAt(0));
            //    Sequence
            final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
            //    DER Octet String[]
            final byte[] privateKeyBlob = ASN1OctetString.getInstance(root.getObjectAt(2))
                                                         .getOctets();

            //        ObjectIdentifier privateKeyAlgorithm
            final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier
                    .getInstance(subSeq.getObjectAt(0));
            //        attributes: see below depending on algorithm


            if (PKCSObjectIdentifiers.rsaEncryption.equals(prvKeyAlgOID)) {
                // RSA has no extra attributes
                delegate = (KeyPairBase) new KeyPairRSA.Builder(config)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(Vendor.ASN1)
                        .setDecryptor(decryptor)
                        .build();

            } else if (X9ObjectIdentifiers.id_dsa.equals(prvKeyAlgOID)) {
                // DSA attributes
                final ASN1Sequence attr = ASN1Sequence.getInstance(subSeq.getObjectAt(1));
                final BigInteger p = ASN1Integer.getInstance(attr.getObjectAt(0))
                                                .getPositiveValue();
                final BigInteger q = ASN1Integer.getInstance(attr.getObjectAt(1))
                                                .getPositiveValue();
                final BigInteger g = ASN1Integer.getInstance(attr.getObjectAt(2))
                                                .getPositiveValue();

                delegate = (KeyPairBase) new KeyPairDSA.Builder(config)
                        .setPQG(p, q, g)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(Vendor.RAW)
                        .setDecryptor(decryptor)
                        .build();

            } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(prvKeyAlgOID)) {
                // ECDSA attributes
                final ASN1ObjectIdentifier primeOid = ASN1ObjectIdentifier
                        .getInstance(subSeq.getObjectAt(1));

                delegate = (KeyPairBase) new KeyPairECDSA.Builder(config)
                        .setType(ECKeyType.getByOid(primeOid))
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(Vendor.ASN1)
                        .setDecryptor(decryptor)
                        .build();

            } else if (id_ed25519.equals(prvKeyAlgOID)) {
                delegate = (KeyPairBase) new KeyPairEdDSA.Builder(config)
                        .setType(EdKeyType.Ed25519)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(Vendor.ASN1)
                        .setDecryptor(decryptor)
                        .build();

            } else if (id_ed448.equals(prvKeyAlgOID)) {
                delegate = (KeyPairBase) new KeyPairEdDSA.Builder(config)
                        .setType(EdKeyType.Ed448)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(Vendor.ASN1)
                        .setDecryptor(decryptor)
                        .build();

            } else {
                throw new UnsupportedAlgorithmException(String.valueOf(prvKeyAlgOID));
            }

            // now set the previously store key/comment
            delegate.setSshPublicKeyBlob(sshPublicKeyBlob);
            delegate.setPublicKeyComment(publicKeyComment);

        } catch (@NonNull final GeneralSecurityException e) {
            // We have an actual error
            throw e;

        } catch (@NonNull final Exception e) {
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, e, () -> DEBUG_KEY_PARSING_FAILED);
            }
            // failed due to a key format decoding problem
            setPrivateKeyEncrypted(true);
            return;

        }
        // the wrapper is decrypted; the delegate might not be
        setPrivateKeyEncrypted(false);
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        private byte[] privateKeyBlob;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        /**
         * Set the private key blob.
         *
         * @param privateKeyBlob The byte[] with the private key
         */
        @NonNull
        public Builder setPrivateKey(@NonNull final byte[] privateKeyBlob) {
            this.privateKeyBlob = privateKeyBlob;
            return this;
        }

        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairPKCS8(config, this);
        }
    }
}
