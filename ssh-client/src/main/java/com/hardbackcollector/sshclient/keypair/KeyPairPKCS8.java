package com.hardbackcollector.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.keypair.util.Vendor;
import com.hardbackcollector.sshclient.signature.SshSignature;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * A PKCS#8 KeyPair is a wrapper containing the actual KeyPair as {@link #delegate}.
 * The type / {@link #delegate} is available after a {@link #parse} when constructing.
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
public class KeyPairPKCS8
        extends KeyPairBase {

    private static final String MUST_PARSE_FIRST = "Must call decrypt/parse first";

    /** The wrapped/actual KeyPair. */
    @Nullable
    private KeyPairBase delegate;

    /**
     * Constructor.
     *
     * @param privateKeyBlob to use
     */
    KeyPairPKCS8(@NonNull final SshClientConfig config,
                 @NonNull final PrivateKeyBlob privateKeyBlob)
            throws GeneralSecurityException {
        super(config, privateKeyBlob);

        parse();
    }

    /**
     * Constructor.
     */
    private KeyPairPKCS8(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob);

        parse();
    }

    @NonNull
    @Override
    public String getHostKeyAlgorithm()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getHostKeyAlgorithm();
    }

    @Override
    public int getKeySize() {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getKeySize();
    }

    @Nullable
    @Override
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException {
        return delegate == null ? null : delegate.getSshPublicKeyBlob();
    }

    @NonNull
    @Override
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getSignature(data, algorithm);
    }

    @NonNull
    @Override
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getVerifier(algorithm);
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).forSSHAgent();
    }

    @Override
    public boolean isPrivateKeyEncrypted() {
        return delegate == null || delegate.isPrivateKeyEncrypted();
    }

    @Override
    void parse(@NonNull final byte[] encodedKey,
               @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {

        try {
            final ASN1InputStream stream = new ASN1InputStream(encodedKey);
            final ASN1Sequence root = ASN1Sequence.getInstance(stream.readObject());
            SshClient.getLogger().log(Logger.DEBUG, () -> "~~~ KeyPairPKCS8#parse ~~~\n" +
                    ASN1Dump.dumpAsString(root, true));

            // DSA unencrypted:
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


            // RSA unencrypted:
            // Sequence                                         ==> 'root'
            //     Integer(0)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.2.840.113549.1.1.1)   ==> 'prvKeyAlgOID'
            //         NULL                                     ==> attributes, none for RSA
            //     DER Octet String[1193]                       ==> 'privateKey'
            //         308204a50...

            // ECDSA 256 unencrypted
            // Sequence                                         ==> 'root'
            //     Integer(0)                                   ==> version
            //     Sequence                                     ==> 'subSeq'
            //         ObjectIdentifier(1.2.840.10045.2.1)      ==> 'prvKeyAlgOID'
            //         ObjectIdentifier(1.2.840.10045.3.1.7)    ==> curve
            //     DER Octet String[109]                        ==> 'privateKey'
            //         306b02010...


            final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
            //        ObjectIdentifier privateKeyAlgorithm
            final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier
                    .getInstance(subSeq.getObjectAt(0));
            //        attributes: see below depending on algorithm

            //    DER Octet String[]
            final byte[] privateKey = ASN1OctetString.getInstance(root.getObjectAt(2))
                                                     .getOctets();

            final BaseKeyPairBuilder builder;

            if (PKCSObjectIdentifiers.rsaEncryption.equals(prvKeyAlgOID)) {
                // RSA has no extra attributes
                builder = new KeyPairRSA.Builder(config);

            } else if (X9ObjectIdentifiers.id_dsa.equals(prvKeyAlgOID)) {
                // DSA attributes
                final ASN1Sequence attr = ASN1Sequence.getInstance(subSeq.getObjectAt(1));
                final BigInteger p = ASN1Integer.getInstance(attr.getObjectAt(0))
                                                .getPositiveValue();
                final BigInteger q = ASN1Integer.getInstance(attr.getObjectAt(1))
                                                .getPositiveValue();
                final BigInteger g = ASN1Integer.getInstance(attr.getObjectAt(2))
                                                .getPositiveValue();

                builder = new KeyPairDSA.Builder(config)
                        .setPQG(p, q, g)
                        // the octet string is the 'x' value
                        .setXCalculateY(new BigInteger(1, privateKey));

            } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(prvKeyAlgOID)) {
                final ASN1ObjectIdentifier primeOid = ASN1ObjectIdentifier
                        .getInstance(subSeq.getObjectAt(1));

                builder = new KeyPairECDSA.Builder(config)
                        // the octet string is the 's' value
                        .setS(new BigInteger(1, privateKey))
                        .setOID(primeOid);

            } else {
                delegate = null;
                privateKeyBlob.setEncrypted(true);
                return;
            }

            builder.setPrivateKeyBlob(privateKey, keyFormat);

            if (privateKeyBlob.getCipher() != null && privateKeyBlob.getCipherIV() != null) {
                builder.setPkeCipher(privateKeyBlob.getCipher(),
                                     privateKeyBlob.getCipherIV());
            }

            delegate = (KeyPairBase) builder.build();
            delegate.setSshPublicKeyBlob(publicKeyBlob);
            delegate.setPublicKeyComment(publicKeyComment);

        } catch (final GeneralSecurityException e) {
            throw e;

        } catch (final Exception e) {
            SshClient.getLogger()
                     .log(Logger.DEBUG, () -> "Parsing failed, key is probably encrypted");

            privateKeyBlob.setEncrypted(true);
            return;
        }

        // mirror the setting for sanity
        privateKeyBlob.setEncrypted(delegate.isPrivateKeyEncrypted());
    }

    @Override
    public void dispose() {
        if (delegate != null) {
            delegate.dispose();
        }
        super.dispose();
    }


    @Override
    @NonNull
    public String getPublicKeyComment() {
        return delegate != null ? delegate.getPublicKeyComment() : publicKeyComment;
    }

    @Override
    @Nullable
    public String getFingerPrint()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint();
    }

    @Override
    @Nullable
    public String getFingerPrint(@NonNull final String algorithm)
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint(algorithm);
    }

    public static class Builder
            extends BaseKeyPairBuilder {

        public Builder(@NonNull final SshClientConfig config) {
            super(config);
        }

        @NonNull
        @Override
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairPKCS8(config, this);
        }
    }
}
