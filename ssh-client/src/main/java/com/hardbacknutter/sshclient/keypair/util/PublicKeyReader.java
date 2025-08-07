package com.hardbacknutter.sshclient.keypair.util;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.hardbacknutter.sshclient.keypair.PublicKeyEncoding;

import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;

class PublicKeyReader {

    private static final String INVALID_FORMAT = "Invalid format";

    @NonNull
    PublicKeyAndComment parse(@NonNull final BufferedReader pubKeyReader)
            throws IOException, InvalidKeyException {
        try (PemReader reader = new PemReader(pubKeyReader)) {
            reader.mark(32);
            final String line = reader.readLine();
            if (line != null) {
                reader.reset();
                if (line.startsWith("-----BEGIN PUBLIC KEY")) {
                    return parsePem(reader);
                } else {
                    return parseSingleLine(reader);
                }
            }
        }
        return new PublicKeyAndComment();
    }

    /**
     * Continue parsing for the public key in PEM format.
     *
     * @param reader to read from
     */
    @NonNull
    private PublicKeyAndComment parsePem(@NonNull final PemReader reader)
            throws IOException {

        final PemObject pem = reader.readPemObject();
        if (pem == null) {
            throw new IOException(INVALID_FORMAT);
        }

        //noinspection unchecked
        final String comment = ((List<PemHeader>) pem.getHeaders())
                .stream()
                .filter(h -> "Comment".equalsIgnoreCase(h.getName()))
                .map(PemHeader::getValue)
                .findFirst()
                .orElse("");

        return new PublicKeyAndComment(pem.getContent(), PublicKeyEncoding.X509, comment);
    }

    /**
     * Continue parsing for the public key in "type base64publickey comment" format.
     *
     * @param reader to read from
     */
    @NonNull
    private PublicKeyAndComment parseSingleLine(@NonNull final PemReader reader)
            throws IOException, InvalidKeyException {
        // skip blank lines and any comments
        String line;
        do {
            line = reader.readLine();
        } while (line != null && (line.isBlank() || line.trim().charAt(0) == '#'));

        byte[] blob = null;
        String comment = null;

        if (line != null) {
            final String[] parts = line.split(" ");
            if (parts.length > 1) {
                // part 0 is the type; don't need it - we get the type from the private key
                // part 1 is the base64 encoded public key
                try {
                    blob = Base64.getDecoder().decode(parts[1].trim());

                } catch (final IllegalArgumentException e) {
                    throw new InvalidKeyException("Invalid base64 data for public key", e);
                }
                // any subsequent parts are comment
                if (parts.length > 2) {
                    final StringJoiner sb = new StringJoiner(" ");
                    for (int i = 2; i < parts.length; i++) {
                        sb.add(parts[i]);
                    }
                    comment = sb.toString();
                }
            }
        }

        return new PublicKeyAndComment(blob, PublicKeyEncoding.OPENSSH_V1, comment);
    }


    static class PublicKeyAndComment {
        private final byte @Nullable [] blob;
        @NonNull
        private final String comment;

        @Nullable
        private final PublicKeyEncoding encoding;

        PublicKeyAndComment() {
            blob = null;
            encoding = null;
            comment = "";
        }

        PublicKeyAndComment(final byte @Nullable [] blob,
                            @Nullable final PublicKeyEncoding encoding,
                            @Nullable final String comment) {
            this.blob = blob;
            this.encoding = encoding;
            this.comment = comment != null ? comment : "";
        }

        public byte @Nullable [] getBlob() {
            return blob;
        }

        @Nullable
        public PublicKeyEncoding getEncoding() {
            return encoding;
        }

        @NonNull
        public String getComment() {
            return comment;
        }
    }
}
