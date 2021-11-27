/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2013-2018 ymnk, JCraft,Inc. All rights reserved.

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
package com.hardbackcollector.sshclient.hostconfig;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.kex.KexProposal;
import com.hardbackcollector.sshclient.utils.Globber;
import com.hardbackcollector.sshclient.utils.Util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * This class implements ConfigRepository interface, and parses
 * OpenSSH's configuration file.
 * <p>
 * The following keywords will be recognized:
 * <ul>
 *   <li>Host               - {@link HostConfigRepository.HostConfig#HOST}</li>
 *
 *   <li>Ciphers            - {@link KexProposal#PROPOSAL_ENC_ALGS_CTOS}
 *                          + {@link KexProposal#PROPOSAL_ENC_ALGS_STOC}</li>
 *   <li>HostKeyAlgorithms  - {@link KexProposal#PROPOSAL_HOST_KEY_ALGS}</li>
 *   <li>KexAlgorithms      - {@link KexProposal#PROPOSAL_KEX_ALGS}</li>
 *   <li>MACs               - {@link KexProposal#PROPOSAL_MAC_ALGS_CTOS}
 *                          + {@link KexProposal#PROPOSAL_MAC_ALGS_STOC}</li>
 *
 *   <li>CompressionLevel   - {@link KexProposal#COMPRESSION_LEVEL}</li>
 *
 *   <li>ClearAllForwardings        - {@link HostConfig#CLEAR_ALL_FORWARDS}</li>
 *   <li>ConnectTimeout             - {@link HostConfig#CONNECT_TIMEOUT}</li>
 *   <li>FingerprintHash            - {@link HostConfig#FINGERPRINT_HASH}</li>
 *   <li>ForwardAgent               - {@link HostConfig#FORWARD_AGENT}</li>
 *   <li>ForwardX11                 - {@link HostConfig#FORWARD_X11}</li>
 *   <li>HashKnownHosts             - {@link HostConfig#HASH_KNOWN_HOSTS}</li>
 *   <li>HostKeyAlias               - {@link HostConfig#HOST_KEY_ALIAS}</li></li>
 *   <li>Hostname                   - {@link HostConfig#HOSTNAME}</li>
 *   <li>IdentityFile               - {@link HostConfig#IDENTITY_FILE}</li>
 *   <li>LocalForward               - {@link HostConfig#LOCAL_FORWARD}</li>
 *   <li>Port                       - {@link HostConfig#PORT}</li>
 *   <li>PreferredAuthentications   - {@link HostConfig#PREFERRED_AUTHENTICATIONS}</li>
 *   <li>PubkeyAcceptedAlgorithms   - {@link HostConfig#PUBKEY_ACCEPTED_ALGORITHMS}</li>
 *   <li>PubkeyAcceptedKeyTypes     - {@link HostConfig#PUBKEY_ACCEPTED_KEY_TYPES}</li>
 *   <li>RemoteForward              - {@link HostConfig#REMOTE_FORWARD}</li>
 *   <li>RequestTTY                 - {@link HostConfig#REQUEST_TTY}</li>
 *   <li>ServerAliveInterval        - {@link HostConfig#SERVER_ALIVE_INTERVAL}</li>
 *   <li>StrictHostKeyChecking      - {@link HostConfig#STRICT_HOST_KEY_CHECKING}</li>
 *   <li>User                       - {@link HostConfig#USER}</li>
 *   <li>UserKnownHostsFile         - {@link HostConfig#USER_KNOWN_HOSTS_FILE}</li>
 * </ul>
 * <p>
 * Not directly mapped: "Compression"
 * CLIENT: Specifies whether to use compression. yes enables compression.
 * SERVER: Specifies whether compression is allowed (yes), denied (no) or
 *          delayed until the user has authenticated successfully (delayed - default).
 * <p>
 * Instead we map it to
 * {@link KexProposal#PROPOSAL_COMP_ALGS_CTOS} + {@link KexProposal#PROPOSAL_COMP_ALGS_STOC}
 * with values {@link KexProposal#COMPRESSION_NONE}, {@link KexProposal#COMPRESSION_ZLIB},
 * {@link KexProposal#COMPRESSION_ZLIB_OPENSSH_COM}.
 * See {@link OpenSSHHostConfig#getString(String)}
 *
 * @see HostConfigRepository
 * @see <a href="https://man.openbsd.org/ssh_config">ssh_config</a>
 */
public final class OpenSSHHostConfigRepository
        implements HostConfigRepository {

    private static final Pattern SPLIT_PATTERN = Pattern.compile("[= \t]");

    private static final Map<String, String> keymap = new HashMap<>();

    static {
        keymap.put(KexProposal.PROPOSAL_ENC_ALGS_STOC, "Ciphers");
        keymap.put(KexProposal.PROPOSAL_ENC_ALGS_CTOS, "Ciphers");
        keymap.put(KexProposal.PROPOSAL_MAC_ALGS_CTOS, "Macs");
        keymap.put(KexProposal.PROPOSAL_MAC_ALGS_STOC, "Macs");
        keymap.put(KexProposal.PROPOSAL_COMP_ALGS_CTOS, "Compression");
        keymap.put(KexProposal.PROPOSAL_COMP_ALGS_STOC, "Compression");
    }

    private final Map<String, List<String[]>> allConfigs = new HashMap<>();

    private final List<String> allHosts = new ArrayList<>();

    private OpenSSHHostConfigRepository(@NonNull final Reader reader)
            throws IOException {
        parse(reader);
    }

    /**
     * Parses the given string, and returns an instance of OpenSSHConfig.
     *
     * @param s string, which includes OpenSSH's config
     * @return instance
     */
    @NonNull
    public static OpenSSHHostConfigRepository parse(@NonNull final String s)
            throws IOException {
        try (final Reader r = new StringReader(s)) {
            return new OpenSSHHostConfigRepository(r);
        }
    }

    /**
     * Parses the given file, and returns an instance of OpenSSHConfig.
     *
     * @param filename OpenSSH's config file
     * @return instance
     */
    @NonNull
    public static OpenSSHHostConfigRepository parseFile(@NonNull final String filename)
            throws IOException {
        try (final Reader r = new FileReader(Util.checkTilde(filename), StandardCharsets.UTF_8)) {
            return new OpenSSHHostConfigRepository(r);
        }
    }

    private void parse(@NonNull final Reader reader)
            throws IOException {
        final BufferedReader br = new BufferedReader(reader);

        String host = "";
        List<String[]> kv = new ArrayList<>();
        String line;

        while ((line = br.readLine()) != null) {
            line = line.strip();

            if (!line.isEmpty() && !line.startsWith("#")) {
                final String[] key_value = SPLIT_PATTERN.split(line, 2);

                for (int i = 0; i < key_value.length; i++) {
                    key_value[i] = key_value[i].strip();
                }

                if (key_value.length > 1) {
                    if (HostConfig.HOST.equalsIgnoreCase(key_value[0])) {
                        allConfigs.put(host, kv);
                        allHosts.add(host);
                        host = key_value[1];
                        kv = new ArrayList<>();
                    } else {
                        kv.add(key_value);
                    }
                }
            }
        }
        allConfigs.put(host, kv);
        allHosts.add(host);
    }

    @Override
    @NonNull
    public HostConfig getHostConfig(@NonNull final String host) {
        return new OpenSSHHostConfig(host, allConfigs, allHosts);
    }

    static final class OpenSSHHostConfig
            implements HostConfig {

        static final Map<String, String> fingerPrints = new HashMap<>();
        private static final Pattern WHITESPACE_PATTERN = Pattern.compile("[ \t]");

        static {
            fingerPrints.put("sha512", "SHA-512");
            fingerPrints.put("sha256", "SHA-256");
            fingerPrints.put("sha224", "SHA-224");

        }

        private final List<List<String[]>> allConfigs = new ArrayList<>();

        private OpenSSHHostConfig(@NonNull final String host,
                                  @NonNull final Map<String, List<String[]>> allConfigs,
                                  @NonNull final List<String> allHosts) {

            this.allConfigs.add(allConfigs.get(""));

            if (allHosts.size() > 1) {
                final byte[] _host = host.getBytes(StandardCharsets.UTF_8);

                for (int i = 1; i < allHosts.size(); i++) {
                    final String oneHost = allHosts.get(i);

                    for (final String pattern : WHITESPACE_PATTERN.split(oneHost)) {
                        final String pt = pattern.strip();
                        final byte[] _pt;
                        if (pt.startsWith("!")) {
                            _pt = pt.substring(1).strip().getBytes(StandardCharsets.UTF_8);
                            if (!Globber.glob(_pt, _host)) {
                                this.allConfigs.add(allConfigs.get(oneHost));
                            }
                        } else {
                            _pt = pt.getBytes(StandardCharsets.UTF_8);
                            if (Globber.glob(_pt, _host)) {
                                this.allConfigs.add(allConfigs.get(oneHost));
                            }
                        }
                    }
                }
            }
        }

        @Override
        @Nullable
        public String getString(@NonNull final String key) {
            final String value = find(key);
            switch (key) {
                case KexProposal.PROPOSAL_COMP_ALGS_STOC:
                case KexProposal.PROPOSAL_COMP_ALGS_CTOS: {
                    if (value == null || "no".equalsIgnoreCase(value)) {
                        return "none,zlib@openssh.com,zlib";
                    }
                    return "zlib@openssh.com,zlib,none";
                }
                case HostConfig.FINGERPRINT_HASH: {
                    if (value == null) {
                        return "SHA-256";
                    }
                    switch (value.toLowerCase(Locale.ENGLISH)) {
                        case "sha224":
                            return "SHA-224";
                        case "sha256":
                            return "SHA-256";
                        case "sha384":
                            return "SHA-384";
                        case "sha512":
                            return "SHA-512";
                        default:
                            return "MD5";
                    }
                }
                default:
                    return value;
            }
        }

        @Override
        @NonNull
        public List<String> getStringList(@NonNull final String key) {
            return multiFind(key);
        }

        @Nullable
        private String find(@NonNull String key) {
            if (keymap.get(key) != null) {
                key = keymap.get(key);
            }

            String value = null;

            for (final List<String[]> v : allConfigs) {
                for (final String[] kv : v) {
                    if (kv[0].equalsIgnoreCase(key)) {
                        value = kv[1];
                        break;
                    }
                }
                if (value != null) {
                    break;
                }
            }
            return value;
        }

        @NonNull
        private List<String> multiFind(@NonNull final String key) {
            final List<String> value = new ArrayList<>();
            for (final List<String[]> v : allConfigs) {
                for (final String[] kv : v) {
                    if (kv[0].equalsIgnoreCase(key)) {
                        final String foo = kv[1];
                        if (foo != null) {
                            value.remove(foo);
                            value.add(foo);
                        }
                    }
                }
            }
            return value;
        }
    }
}
