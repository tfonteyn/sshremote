package com.hardbacknutter.sshclient.hostconfig;

import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.utils.BaseConfig;

/**
 * A configuration for connections to a remote host name (or alias).
 *
 * @see <a href="https://man.openbsd.org/ssh_config">OpenSSH client configuration file</a>
 * @see OpenSSHHostConfigRepository
 */
public interface HostConfig
        extends BaseConfig {

    /**
     * The KEY to lookup a specific host using
     * {@link HostConfigRepository#getHostConfig(String)}.
     */
    String HOST = "Host";


    /**
     * String - Specifies an alias that should be used instead of the real host name when
     * looking up or saving the host key in the host key database files
     * and when validating host certificates.
     */
    String HOST_KEY_ALIAS = "HostKeyAlias";

    /**
     * String - The actual host name for the remote host.
     */
    String HOSTNAME = "HostName";

    /**
     * int - The port number on the remote host to connect to.
     */
    String PORT = "Port";

    /**
     * String - Default user for this host.
     */
    String USER = "User";

    /**
     * String.
     */
    String BIND_ADDRESS = "BindAddress";

    /**
     * int
     */
    String CONNECT_TIMEOUT = "ConnectTimeout";

    /**
     * int
     */
    String SERVER_ALIVE_INTERVAL = "ServerAliveInterval";

    /**
     * @see KexProposal.StrictHostKeyChecking
     */
    String STRICT_HOST_KEY_CHECKING = "StrictHostKeyChecking";


    /**
     * Type: multi
     * Param: CSV String list
     * Support prefixes: {@code +-^}
     */
    String KEX_ALGS = "KexAlgorithms";
    /**
     * Type: multi
     * Param: CSV String list
     * Support prefixes: {@code +-^}
     */
    String HOST_KEY_ALGS = "HostKeyAlgorithms";

    /**
     * Type: multi
     * Param: CSV String list
     * Support prefixes: {@code +-^}
     */
    String CIPHERS = "Ciphers";

    /**
     * Type: multi
     * Param: CSV String list
     * Support prefixes: {@code +-^}
     */
    String MACS = "Macs";

    /**
     * boolean
     */
    String HASH_KNOWN_HOSTS = "HashKnownHosts";

    /**
     * Whitespace separated String list.
     */
    String USER_KNOWN_HOSTS_FILE = "UserKnownHostsFile";

    /**
     * Type: single
     * Param: String
     */
    String FINGERPRINT_HASH = "FingerprintHash";

    /**
     * int
     */
    String NUMBER_OF_PASSWORD_PROMPTS = "NumberOfPasswordPrompts";
    /**
     * Default value for {@link #NUMBER_OF_PASSWORD_PROMPTS}.
     */
    int DEFAULT_NUMBER_OF_PASSWORD_PROMPTS = 3;

    /**
     * boolean
     */
    String COMPRESSION = "Compression";

    /**
     * Type: multi
     * Param: ?? String or CSV String ??
     * Support prefixes: no, always adds to the list
     */
    String IDENTITY_FILE = "IdentityFile";

    /**
     * Type: multi
     * Param: CSV String list
     * Support prefixes: {@code +-^}
     */
    String PUBLIC_KEY_ACCEPTED_ALGORITHMS = "PubkeyAcceptedAlgorithms";

    /**
     * @deprecated use {@link #PUBLIC_KEY_ACCEPTED_ALGORITHMS} instead.
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    String PUBLIC_KEY_ACCEPTED_KEY_TYPES = "PubkeyAcceptedKeyTypes";

    /**
     * Type: single
     * Param: CSV String.
     */
    String PREFERRED_AUTHENTICATIONS = "PreferredAuthentications";

    /**
     * boolean
     */
    String CLEAR_ALL_FORWARDS = "ClearAllForwardings";

    /**
     * Type: multi
     * Param: port remote:rport
     */
    String LOCAL_FORWARD = "LocalForward";

    /**
     * Type: multi
     * Param: rport local:port
     */
    String REMOTE_FORWARD = "RemoteForward";

    /**
     * boolean
     */
    String FORWARD_AGENT = "ForwardAgent";
    /**
     * boolean
     */
    String FORWARD_X11 = "ForwardX11";
    /**
     * boolean
     */
    String REQUEST_TTY = "RequestTTY";

    /**
     * string
     */
    String LOG_LEVEL = "LogLevel";

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
        return getIntValue(PORT, -1);
    }
}
