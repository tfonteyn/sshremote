/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.hostkey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.hostconfig.HostConfig;
import com.hardbackcollector.sshclient.macs.SshMac;
import com.hardbackcollector.sshclient.userauth.UserInfo;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;
import com.hardbackcollector.sshclient.utils.Util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.ResourceBundle;
import java.util.StringJoiner;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The default implementation of {@link HostKeyRepository}, using
 * an optional local file to persist the keys.
 *
 * @see SshClient#setKnownHosts(String)
 * @see SshClient#setKnownHosts(InputStream)
 * @see <a href="http://manpages.ubuntu.com/manpages/impish/en/man8/sshd.8.html#ssh_known_hosts%20file%20format">
 * Ubuntu man page</a>
 */
public class KnownHosts
        implements HostKeyRepository {

    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("[ \t]");

    /**
     * The hash to use for hashing keys.
     */
    private static final String HASH = "hmac-sha1";

    private static final String REVOKED = "@revoked";

    @NonNull
    private final SshClientConfig config;
    private final List<HostKey> pool = new ArrayList<>();

    /**
     * Optional: if not set, we just keep all entries in memory.
     */
    @Nullable
    private String knownHostsFilename;

    @Nullable
    private SshMac mac;

    public KnownHosts(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    public void setKnownHosts(@NonNull final String filename)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {

        knownHostsFilename = filename;
        try {
            setKnownHosts(new FileInputStream(Util.checkTilde(filename)));
        } catch (final FileNotFoundException e) {
            // a non-existing file is allowed.
        }
    }

    public void setKnownHosts(@NonNull final InputStream is)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {

        pool.clear();

        //noinspection ImplicitDefaultCharsetUsage
        try (final InputStreamReader isr = new InputStreamReader(is);
             final BufferedReader fis = new BufferedReader(isr)) {

            String line;
            while ((line = fis.readLine()) != null) {
                line = line.strip();
                if (line.startsWith("#")) {
                    pool.add(HostKey.createUnknown(line));
                    continue;
                }

                // Each line in these files contains the following fields:
                //      markers (optional), hostnames, keytype, base64-encoded key, comment
                // The fields are separated by spaces.
                final String[] fields = WHITESPACE_PATTERN.split(line);
                if (fields.length < 3) {
                    pool.add(HostKey.createUnknown(line));
                    continue;
                }

                // The marker is optional, but if it is present then it must be one of
                // “@cert-authority”, to indicate that the line contains a CA key
                // “@revoked”, to indicate that the key contained on the line is revoked
                //              and must not ever be accepted.
                // Only one marker should be used on a key line.
                int fc = 0;
                final String marker;
                if (fields[fc].startsWith("@")) {
                    marker = fields[fc++];
                } else {
                    marker = "";
                }
                final String host = fields[fc++];
                final String type = fields[fc++];
                final String key = fields[fc++];

                final StringJoiner comment = new StringJoiner(" ");
                while (fc < fields.length) {
                    comment.add(fields[fc++]);
                }

                final byte[] keyBlob =
                        Base64.getDecoder().decode(key.getBytes(StandardCharsets.UTF_8));

                pool.add(new HashedHostKey(getMac(), marker, host, type, keyBlob,
                        comment.toString()));
            }
        }
    }

    @Override
    @Nullable
    public String getRepositoryID() {
        return knownHostsFilename;
    }

    @NonNull
    @Override
    public List<HostKey> getHostKeys(@Nullable final String host,
                                     @Nullable final String type) {
        synchronized (pool) {
            // Only consider valid keys (e.g. the ones which have a type set)
            final List<HostKey> list =
                    pool.stream()
                            .filter(hostKey -> {
                                        // if the host is null, add this one
                                        if (host == null) {
                                            return true;
                                        }
                                        // if the host does not match, skip this one.
                                        if (!hostKey.isMatching(host)) {
                                            return false;
                                        }
                                        // the host matches, the type must either be null
                                        if (type == null) {
                                            return true;
                                        }
                                        // or the types must also match
                                        try {
                                            return hostKey.getType()
                                                    .equals(HostKeyAlgorithm.parseType(type));
                                        } catch (final InvalidKeyException e) {
                                            // Shouldn't really happen, but if it does
                                            // pretend the type was null, and add this one.
                                            return true;
                                        }
                                    }
                            )
                            .collect(Collectors.toList());

            if (host != null && host.startsWith("[") && host.indexOf("]:") > 1) {
                list.addAll(getHostKeys(host.substring(1, host.indexOf("]:")), type));
            }
            return list;
        }
    }

    @NonNull
    @Override
    public KeyIs isKnown(@NonNull final String host,
                         @NonNull final String type,
                         @NonNull final byte[] key)
            throws InvalidKeyException {

        final HostKey hostToCheck = new HostKey(host, key);

        synchronized (pool) {
            for (final HostKey hostKey : pool) {
                // type + hostname MUST match
                if (hostKey.getType().equals(hostToCheck.getType())
                        && hostKey.isMatching(hostToCheck.getHostnames())) {

                    // the key MAY match
                    if (Arrays.equals(hostKey.getKey(), hostToCheck.getKey())) {

                        final String encKey = hostToCheck.getEncodedKey();
                        for (final HostKey k : getHostKeys(host, type)) {
                            if (k.getEncodedKey().equals(encKey)
                                    && REVOKED.equals(k.getMarker())) {
                                return KeyIs.Revoked;
                            }
                        }
                        return KeyIs.Accepted;

                    } else {
                        return KeyIs.Changed;
                    }
                }
            }
        }

        if (host.startsWith("[") && host.indexOf("]:") > 1) {
            return isKnown(host.substring(1, host.indexOf("]:")), type, key);
        }

        return KeyIs.Unknown;
    }

    @Override
    @NonNull
    public HostKey createHostKey(@NonNull final String host,
                                 @NonNull final byte[] key)
            throws GeneralSecurityException {

        if (config.getBooleanValue(HostConfig.HASH_KNOWN_HOSTS, false)) {
            final HashedHostKey hhk = new HashedHostKey(getMac(), host, key);
            hhk.hash(config.getRandom());
            return hhk;

        } else {
            return new HostKey(host, key);
        }
    }

    @Override
    public void add(@NonNull final HostKey hostKey,
                    @Nullable final UserInfo userinfo) {
        // in-memory
        pool.add(hostKey);

        // optional file
        if (knownHostsFilename != null) {
            boolean sync = true;
            File file = new File(Util.checkTilde(knownHostsFilename));
            if (!file.exists()) {
                sync = false;
                if (userinfo != null) {
                    final ResourceBundle rb = ResourceBundle.getBundle(SshClient.USER_MESSAGES);

                    sync = userinfo.promptYesNo(UserInfo.RC_CREATE_FILE, String.format(
                            rb.getString("CREATE_FILE"), knownHostsFilename));

                    file = file.getParentFile();
                    if (sync && file != null && !file.exists()) {

                        sync = userinfo.promptYesNo(UserInfo.RC_CREATE_DIRECTORY, String.format(
                                rb.getString("CREATE_DIR"), file.getName()));
                        if (sync) {
                            if (file.mkdirs()) {
                                userinfo.showMessage(String.format(
                                        rb.getString("FILE_CREATED"), file.getName()));
                            } else {
                                userinfo.showMessage(String.format(
                                        rb.getString("FILE_NOT_CREATED"), file.getName()));
                                sync = false;
                            }
                        }
                    }
                    if (file == null) {
                        sync = false;
                    }
                }
            }

            if (sync) {
                try {
                    writeToFile();
                } catch (final Exception e) {
                    if (SshClient.getLogger().isEnabled(Logger.ERROR)) {
                        SshClient.getLogger().log(Logger.ERROR, "sync " + knownHostsFilename, e);
                    }
                }
            }
        }
    }

    @Override
    public void remove(@NonNull final String host,
                       @Nullable final String type,
                       @Nullable final byte[] key) {

        boolean sync = false;
        synchronized (pool) {
            for (final HostKey hostKey : pool) {
                if (hostKey.isMatching(host)) {
                    if ((type == null)
                            || (hostKey.getType().equals(type)
                            && ((key == null) || Arrays.equals(key, hostKey.getKey())))) {

                        // exact match ? completely remove
                        if (hostKey.getHostnames().equals(host)
                                || hostKey instanceof HashedHostKey
                                && ((HashedHostKey) hostKey).isHashed()) {
                            pool.remove(hostKey);
                        } else {
                            // do NOT expand wildcards!
                            hostKey.setHosts(hostKey.getHosts()
                                    .stream()
                                    .filter(s -> !host.equals(s))
                                    .collect(Collectors.toList()));
                        }
                        sync = true;
                    }
                }
            }
        }

        if (sync) {
            try {
                writeToFile();
            } catch (final Exception e) {
                if (SshClient.getLogger().isEnabled(Logger.ERROR)) {
                    SshClient.getLogger().log(Logger.ERROR, "sync " + knownHostsFilename, e);
                }
            }
        }
    }

    private void writeToFile()
            throws IOException {
        if (knownHostsFilename != null) {
            synchronized (pool) {
                try (final Writer os = new FileWriter(Util.checkTilde(knownHostsFilename),
                        StandardCharsets.UTF_8)) {
                    for (final HostKey hostKey : pool) {
                        if (hostKey.getKey() != null) {
                            final String marker = hostKey.getMarker();
                            if (!marker.isBlank()) {
                                os.write(marker + ' ');
                            }
                            os.write(hostKey.getHostnames()
                                    + ' ' + hostKey.getType()
                                    + ' ' + hostKey.getEncodedKey());

                            final String comment = hostKey.getComment();
                            if (!comment.isBlank()) {
                                os.write(' ' + comment);
                            }
                        } else {
                            // a comment line
                            os.write(hostKey.getComment());
                        }
                        os.write('\n');
                    }
                }
            }
        }
    }

    @NonNull
    private SshMac getMac()
            throws NoSuchAlgorithmException {
        if (mac == null) {
            mac = ImplementationFactory.getMac(config, HASH);
        }
        return mac;
    }
}
