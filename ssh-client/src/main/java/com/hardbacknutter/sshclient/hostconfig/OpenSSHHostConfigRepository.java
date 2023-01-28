package com.hardbacknutter.sshclient.hostconfig;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.utils.Util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * This class implements ConfigRepository interface, and parses OpenSSH's configuration file.
 * <p>
 * The following keywords will be recognized:
 * <ul>
 *   <li>Host               - {@link HostConfig#HOST}</li>
 *
 *   <li>Ciphers            - {@link KexProposal#PROPOSAL_CIPHER_CTOS}
 *                          + {@link KexProposal#PROPOSAL_CIPHER_STOC}</li>
 *   <li>HostKeyAlgorithms  - {@link HostConfig#HOST_KEY_ALGS}</li>
 *   <li>KexAlgorithms      - {@link HostConfig#KEX_ALGS}</li>
 *   <li>MACs               - {@link KexProposal#PROPOSAL_MAC_CTOS}
 *                          + {@link KexProposal#PROPOSAL_MAC_STOC}</li>
 *
 *   <li>ClearAllForwardings        - {@link HostConfig#CLEAR_ALL_FORWARDS}</li>
 *   <li>CompressionLevel           - {@link KexProposal#COMPRESSION_LEVEL}</li>
 *   <li>ConnectTimeout             - {@link HostConfig#CONNECT_TIMEOUT}</li>
 *   <li>FingerprintHash            - {@link HostConfig#FINGERPRINT_HASH}</li>
 *   <li>ForwardAgent               - {@link HostConfig#FORWARD_AGENT}</li>
 *   <li>ForwardX11                 - {@link HostConfig#FORWARD_X11}</li>
 *   <li>HashKnownHosts             - {@link HostConfig#HASH_KNOWN_HOSTS}</li>
 *   <li>HostKeyAlias               - {@link HostConfig#HOST_KEY_ALIAS}</li></li>
 *   <li>Hostname                   - {@link HostConfig#HOSTNAME}</li>
 *   <li>IdentityFile               - {@link HostConfig#IDENTITY_FILE}</li>
 *   <li>LocalForward               - {@link HostConfig#LOCAL_FORWARD}</li>
 *   <li>NumberOfPasswordPrompts    - {@link HostConfig#NUMBER_OF_PASSWORD_PROMPTS}</li>
 *   <li>Port                       - {@link HostConfig#PORT}</li>
 *   <li>PreferredAuthentications   - {@link HostConfig#PREFERRED_AUTHENTICATIONS}</li>
 *   <li>PubkeyAcceptedAlgorithms   - {@link HostConfig#PUBLIC_KEY_ACCEPTED_ALGORITHMS}</li>
 *   <li>PubkeyAcceptedKeyTypes     - {@link HostConfig#PUBLIC_KEY_ACCEPTED_KEY_TYPES}</li>
 *   <li>RemoteForward              - {@link HostConfig#REMOTE_FORWARD}</li>
 *   <li>RequestTTY                 - {@link HostConfig#REQUEST_TTY}</li>
 *   <li>ServerAliveInterval        - {@link HostConfig#SERVER_ALIVE_INTERVAL}</li>
 *   <li>StrictHostKeyChecking      - {@link HostConfig#STRICT_HOST_KEY_CHECKING}</li>
 *   <li>User                       - {@link HostConfig#USER}</li>
 *   <li>UserKnownHostsFile         - {@link HostConfig#USER_KNOWN_HOSTS_FILE}</li>
 * </ul>
 *  Patterns are supported; tokens are not.
 * <p>
 * Not directly mapped: "Compression"
 * CLIENT: Specifies whether to use compression.
 *         {@code yes} enables compression; the default is disabled {@code no}
 * SERVER: Specifies whether compression is allowed {@code yes}, denied {@code no} or
 *          delayed {@code delayed} until the user has authenticated successfully (default).
 * <p>
 * Instead we map it to
 * {@link KexProposal#PROPOSAL_COMP_CTOS} + {@link KexProposal#PROPOSAL_COMP_STOC}
 * with values:
 * {@link KexProposal#COMPRESSION_NONE},
 * {@link KexProposal#COMPRESSION_ZLIB},
 * {@link KexProposal#COMPRESSION_ZLIB_OPENSSH_COM}.
 * See {@link OpenSSHHostConfig#getString(String)}
 *
 * @see HostConfigRepository
 * @see <a href="https://man.openbsd.org/ssh_config">ssh_config</a>
 */
public final class OpenSSHHostConfigRepository
        implements HostConfigRepository {

    private static final Pattern SPLIT_PATTERN = Pattern.compile("[= \t]+");

    /**
     * key: host(or alias); value: the name-value pairs.
     * <p>
     * Uses a LinkedHashMap to preserve the order of the ssh_config entries.
     */
    private final Map<String, List<String[]>> hosts = new LinkedHashMap<>();

    /**
     * Constructor.
     */
    private OpenSSHHostConfigRepository(@NonNull final Reader reader)
            throws IOException {
        parse(reader);
    }

    /**
     * Parses the given string, and returns an instance of OpenSSHConfig.
     *
     * @param s string, which includes OpenSSH's config
     *
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
     *
     * @return instance
     */
    @NonNull
    public static OpenSSHHostConfigRepository parseFile(@NonNull final String filename)
            throws IOException {
        //TODO: Android API 26 limitation
        // try (final Reader r = new FileReader(Util.checkTilde(filename),
        //                                      StandardCharsets.UTF_8)) {
        //noinspection ImplicitDefaultCharsetUsage
        try (final Reader r = new FileReader(Util.checkTilde(filename))) {
            return new OpenSSHHostConfigRepository(r);
        }
    }

    @NonNull
    static StringBuilder dbgDump(@NonNull final List<String[]> options) {
        final StringBuilder sb = new StringBuilder("\n{");
        for (final String[] sa : options) {
            sb.append("\n  ").append(Arrays.toString(sa));
        }
        return sb.append("\n}");
    }

    private void parse(@NonNull final Reader reader)
            throws IOException {

        // The "" entry will always contain the global settings.
        // i.e. all settings BEFORE the first "Host" entry.
        String host = "";
        List<String[]> kv = new ArrayList<>();

        final BufferedReader br = new BufferedReader(reader);
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {

                final String[] keyValuePair = SPLIT_PATTERN.split(line, 2);

                // sanity check
                if (keyValuePair.length > 1) {

                    // start of a new "Host" entry
                    if (HostConfig.HOST.equalsIgnoreCase(keyValuePair[0].trim())) {
                        // store the previously parsed section
                        hosts.put(host, kv);

                        // and start a new "Host" section
                        // "host" is a glob expression. See OpenSSH ssh_config docs.
                        host = keyValuePair[1].trim();
                        kv = new ArrayList<>();

                    } else {
                        // add to current Host
                        kv.add(keyValuePair);
                    }
                }
            }
        }
        // store the last section
        hosts.put(host, kv);
    }

    @Override
    @NonNull
    public HostConfig getHostConfig(@NonNull final String hostOrAlias) {
        return new OpenSSHHostConfig(hostOrAlias, hosts);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("OpenSSHHostConfigRepository{hosts=");
        hosts.forEach((host, options) -> sb
                .append("\n").append(host)
                .append(dbgDump(options)));
        return sb.toString();
    }
}
