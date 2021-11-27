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

import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.kex.KexProposal;

import java.util.List;
import java.util.stream.Collectors;

/**
 * A repository for host-specific configuration settings, retrievable by
 * host name (or an alias).
 * This can be implemented by an application and passed to
 * {@link SshClient#setHostConfigRepository(HostConfigRepository)}.
 */
public interface HostConfigRepository {

    /**
     * Returns the configuration for a specific host name (or host name alias).
     *
     * @param host The host name. When passing in {@code ""},
     *             the repository should return the global/default settings.
     */
    @NonNull
    HostConfig getHostConfig(@NonNull String host);

    /**
     * A configuration for connections to a remote host name (or alias).
     *
     * @see OpenSSHHostConfigRepository
     * @see <a href="https://man.openbsd.org/ssh_config">OpenSSH client configuration file</a>
     */
    interface HostConfig {

        /**
         * The KEY to lookup a specific host using
         * {@link HostConfigRepository#getHostConfig(String)}.
         */
        String HOST = "Host";

        /**
         * Specifies an alias that should be used instead of the real host name when
         * looking up or saving the host key in the host key database files
         * and when validating host certificates.
         */
        String HOST_KEY_ALIAS = "HostKeyAlias";

        /**
         * Specifies the real host name to log into.
         */
        String HOSTNAME = "Hostname";

        /**
         * Specifies the port number to connect on the remote host.
         */
        String PORT = "Port";
        String USER = "User";

        String CONNECT_TIMEOUT = "ConnectTimeout";
        String SERVER_ALIVE_INTERVAL = "ServerAliveInterval";

        /**
         * @see KexProposal.StrictHostKeyChecking
         */
        String STRICT_HOST_KEY_CHECKING = "StrictHostKeyChecking";

        /**
         * Boolean
         * {@code true}: new added server keys will be hashed.
         * {@code false}: new keys are added as-is
         */
        String HASH_KNOWN_HOSTS = "HashKnownHosts";
        String USER_KNOWN_HOSTS_FILE = "UserKnownHostsFile";
        String FINGERPRINT_HASH = "FingerprintHash";

        /**
         * int - password authentication.
         */
        String NUMBER_OF_PASSWORD_PROMPTS = "NumberOfPasswordPrompts";

        /**
         * Public key authentication.
         */
        String IDENTITY_FILE = "IdentityFile";

        String PUBKEY_ACCEPTED_ALGORITHMS = "PubkeyAcceptedAlgorithms";

        /**
         * Legacy key name for {@link #PUBKEY_ACCEPTED_ALGORITHMS}.
         *
         * @see #getPubkeyAcceptedAlgorithms()
         */
        @SuppressWarnings("DeprecatedIsStillUsed")
        @Deprecated
        String PUBKEY_ACCEPTED_KEY_TYPES = "PubkeyAcceptedKeyTypes";

        String PREFERRED_AUTHENTICATIONS = "PreferredAuthentications";

        /**
         * Boolean
         */
        String CLEAR_ALL_FORWARDS = "ClearAllForwardings";
        /**
         * CSV String.
         */
        String LOCAL_FORWARD = "LocalForward";
        /**
         * CSV String.
         */
        String REMOTE_FORWARD = "RemoteForward";

        /**
         * boolean - Channel.
         */
        String FORWARD_AGENT = "ForwardAgent";
        /**
         * boolean - Channel.
         */
        String FORWARD_X11 = "ForwardX11";
        /**
         * boolean - Channel.
         */
        String REQUEST_TTY = "RequestTTY";

        /**
         * The user name to use for connecting.
         *
         * @return the string value, or {@code null} if not set.
         */
        @Nullable
        default String getUser() {
            return getString(USER);
        }

        /**
         * The host name to use for connecting.
         *
         * @return the string value, or {@code null} if not set.
         */
        @Nullable
        default String getHostname() {
            return getString(HOSTNAME);
        }

        /**
         * The port number to use for connecting.
         *
         * @return the port value, or {@code -1} if not set.
         */
        default int getPort() {
            final Integer port = getIntegerValue(PORT);
            return port == null ? -1 : port;
        }

        /**
         * Specifies an alias that should be used instead of the real host name
         * when looking up or saving the host key in the host key database files
         * and when validating host certificates.
         *
         * @return the string value, or {@code null} if not set.
         */
        @Nullable
        default String getHostKeyAlias() {
            return getString(HOST_KEY_ALIAS);
        }

        /**
         * The list of identity files to use for public key authentication.
         *
         * @return the list, will be empty if not set.
         */
        @NonNull
        default List<String> getIdentityFiles() {
            return getStringList(IDENTITY_FILE);
        }

        /**
         * The list of algorithms we can accept for public key authentication.
         *
         * @return the list as a CSV String, or {@code ""} if not set.
         */
        @NonNull
        default String getPubkeyAcceptedAlgorithms() {
            final List<String> all = getStringList(PUBKEY_ACCEPTED_ALGORITHMS);
            final List<String> legacy = getStringList(PUBKEY_ACCEPTED_KEY_TYPES);
            if (!legacy.isEmpty()) {
                all.addAll(legacy);
            }

            return all.stream().distinct().collect(Collectors.joining(","));
        }

        /**
         * The list of local-forward connection strings..
         *
         * @return the list, will be empty if not set.
         */
        @NonNull
        default List<String> getLocalForwards() {
            return getStringList(LOCAL_FORWARD);
        }

        /**
         * The list of remote-forward connection strings..
         *
         * @return the list, will be empty if not set.
         */
        @NonNull
        default List<String> getRemoteForwards() {
            return getStringList(REMOTE_FORWARD);
        }

        /**
         * Get a configuration value for a generic named key, as a {@link Boolean} object.
         * <p>
         * A value is considered {@code true} when equal to "true" or "yes" (case-insensitive).
         * All other values are taken as {@code false}.
         *
         * @return the boolean value, or {@code null} if the key is not present.
         */
        @Nullable
        default Boolean getBooleanValue(@NonNull final String key) {
            final String value = getString(key);
            return value != null ? "yes".equalsIgnoreCase(value) || "true".equalsIgnoreCase(value)
                    : null;
        }

        /**
         * Get a configuration value for a generic named key, as an {@link Integer} object.
         *
         * @return the int value, or {@code null} if the key is not present.
         */
        @Nullable
        default Integer getIntegerValue(@NonNull final String key) {
            final String value = getString(key);
            if (value != null) {
                try {
                    return Integer.parseInt(value);
                } catch (final NumberFormatException ignore) {

                }
            }
            return null;
        }

        /**
         * A configuration value for a generic named key, as a string.
         *
         * @return the string value, or {@code null} if the key is not present.
         */
        @Nullable
        String getString(@NonNull String key);

        /**
         * A list of configuration values for a generic named key, as an List of strings.
         *
         * @return the list of string values, will be empty if the key is not present.
         */
        @NonNull
        List<String> getStringList(@NonNull String key);
    }
}
