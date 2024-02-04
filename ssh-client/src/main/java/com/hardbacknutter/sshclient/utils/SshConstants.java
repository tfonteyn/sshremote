package com.hardbacknutter.sshclient.utils;

/**
 * <a href="http://ietf.org/internet-drafts/draft-ietf-secsh-assignednumbers-01.txt">
 *     http://ietf.org/internet-drafts/draft-ietf-secsh-assignednumbers-01.txt</a>
 * <p>
 * Value 	Message ID 	Reference
 * 0	    Reserved
 * 1	    SSH_MSG_DISCONNECT	[RFC4253]
 * 2	    SSH_MSG_IGNORE	[RFC4253]
 * 3	    SSH_MSG_UNIMPLEMENTED	[RFC4253]
 * 4	    SSH_MSG_DEBUG	[RFC4253]
 * 5	    SSH_MSG_SERVICE_REQUEST	[RFC4253]
 * 6	    SSH_MSG_SERVICE_ACCEPT	[RFC4253]
 * 7	    SSH_MSG_EXT_INFO	[RFC8308]
 * 8	    SSH_MSG_NEWCOMPRESS	[RFC8308]
 * 9-19 	Unassigned (Transport layer generic)
 * <p>
 * 20	    SSH_MSG_KEXINIT	[RFC4253]
 * 21	    SSH_MSG_NEWKEYS	[RFC4253]
 * 22-29	Unassigned (Algorithm negotiation)
 * <p>
 * 30-49	Reserved (key exchange method specific)	[RFC4251]
 * <p>
 * 50	    SSH_MSG_USERAUTH_REQUEST	[RFC4252]
 * 51	    SSH_MSG_USERAUTH_FAILURE	[RFC4252]
 * 52	    SSH_MSG_USERAUTH_SUCCESS	[RFC4252]
 * 53	    SSH_MSG_USERAUTH_BANNER	[RFC4252]
 * 54-59	Unassigned (User authentication generic)
 * <p>
 * 60	    SSH_MSG_USERAUTH_INFO_REQUEST	[RFC4256]
 * 61	    SSH_MSG_USERAUTH_INFO_RESPONSE	[RFC4256]
 * 62-79	Reserved (User authentication method specific)	[RFC4251]
 * <p>
 * 80	    SSH_MSG_GLOBAL_REQUEST	[RFC4254]
 * 81	    SSH_MSG_REQUEST_SUCCESS	[RFC4254]
 * 82	    SSH_MSG_REQUEST_FAILURE	[RFC4254]
 * 83-89	Unassigned (Connection protocol generic)
 * <p>
 * 90	    SSH_MSG_CHANNEL_OPEN	[RFC4254]
 * 91	    SSH_MSG_CHANNEL_OPEN_CONFIRMATION	[RFC4254]
 * 92	    SSH_MSG_CHANNEL_OPEN_FAILURE	[RFC4254]
 * 93	    SSH_MSG_CHANNEL_WINDOW_ADJUST	[RFC4254]
 * 94	    SSH_MSG_CHANNEL_DATA	[RFC4254]
 * 95	    SSH_MSG_CHANNEL_EXTENDED_DATA	[RFC4254]
 * 96	    SSH_MSG_CHANNEL_EOF	[RFC4254]
 * 97	    SSH_MSG_CHANNEL_CLOSE	[RFC4254]
 * 98	    SSH_MSG_CHANNEL_REQUEST	[RFC4254]
 * 99	    SSH_MSG_CHANNEL_SUCCESS	[RFC4254]
 * 100	    SSH_MSG_CHANNEL_FAILURE	[RFC4254]
 * 101-127	Unassigned (Channel related messages)
 * <p>
 * 128-191	Reserved (for client protocols)
 * 192-255	Reserved for Private Use (local extensions)
 *
 * @see <a href="http://datatracker.ietf.org/doc/html/rfc4251">
 * RFC 4251 SSH Protocol Architecture</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252">
 * RFC 4252 SSH Authentication Protocol</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253">
 * RFC 4253 SSH Transport Layer Protocol</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254">
 * RFC 4254 SSH Connection Protocol</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4256">
 * RFC 4256 Generic Message Exchange Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8308">
 * RFC 8308 Extension Negotiation</a>
 */
@SuppressWarnings("WeakerAccess")
public final class SshConstants {

    /**
     * byte      SSH_MSG_DISCONNECT
     * uint32    reason code
     * string    description in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    public static final byte SSH_MSG_DISCONNECT = 1;

    /**
     * byte      SSH_MSG_IGNORE
     * string    data
     */
    public static final byte SSH_MSG_IGNORE = 2;

    /**
     * byte      SSH_MSG_UNIMPLEMENTED
     * uint32    packet sequence number of rejected message
     */
    public static final byte SSH_MSG_UNIMPLEMENTED = 3;

    /**
     * byte      SSH_MSG_DEBUG
     * boolean   always_display
     * string    message in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    public static final byte SSH_MSG_DEBUG = 4;

    /**
     * byte      SSH_MSG_SERVICE_REQUEST
     * string    service name
     * <p>
     * where service is one of: ssh-userauth,  ssh-connection
     */
    public static final byte SSH_MSG_SERVICE_REQUEST = 5;

    /**
     * byte      SSH_MSG_SERVICE_ACCEPT
     * string    service name
     */
    public static final byte SSH_MSG_SERVICE_ACCEPT = 6;

    /**
     * byte       SSH_MSG_EXT_INFO (value 7)
     * uint32     nr-extensions
     * repeat the following 2 fields "nr-extensions" times:
     * string   extension-name
     * string   extension-value (binary)
     * TODO: implement  RFC 8308 Extension Negotiation
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8308">
     * RFC 8308 Extension Negotiation</a>
     */
    public static final byte SSH_MSG_EXT_INFO = 7;

    /**
     * byte       SSH_MSG_NEWCOMPRESS (value 8)
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8308#section-3.2">
     * RFC 8308 Extension Negotiation</a>
     */
    public static final byte SSH_MSG_NEWCOMPRESS = 8;

    /**
     * byte         SSH_MSG_KEXINIT
     * byte[16]     cookie (random bytes)
     * name-list    kex_algorithms
     * name-list    server_host_key_algorithms
     * name-list    encryption_algorithms_client_to_server
     * name-list    encryption_algorithms_server_to_client
     * name-list    mac_algorithms_client_to_server
     * name-list    mac_algorithms_server_to_client
     * name-list    compression_algorithms_client_to_server
     * name-list    compression_algorithms_server_to_client
     * name-list    languages_client_to_server
     * name-list    languages_server_to_client
     * boolean      first_kex_packet_follows
     * uint32       0 (reserved for future extension)
     */
    public static final byte SSH_MSG_KEXINIT = 20;

    /**
     * byte      SSH_MSG_NEWKEYS
     */
    public static final byte SSH_MSG_NEWKEYS = 21;

    /**
     * byte      SSH_MSG_USERAUTH_REQUEST
     * string    user name in ISO-10646 UTF-8 encoding [RFC3629]
     * string    service name in US-ASCII
     * string    method name in US-ASCII
     * ....      method specific fields
     */
    public static final byte SSH_MSG_USERAUTH_REQUEST = 50;

    /**
     * byte         SSH_MSG_USERAUTH_FAILURE
     * name-list    authentications that can continue
     * boolean      partial success
     */
    public static final byte SSH_MSG_USERAUTH_FAILURE = 51;

    /**
     * byte         SSH_MSG_USERAUTH_SUCCESS
     */
    public static final byte SSH_MSG_USERAUTH_SUCCESS = 52;

    /**
     * byte      SSH_MSG_USERAUTH_BANNER
     * string    message in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    public static final byte SSH_MSG_USERAUTH_BANNER = 53;

    /**
     * byte      SSH_MSG_USERAUTH_INFO_REQUEST
     * string    name (ISO-10646 UTF-8)
     * string    instruction (ISO-10646 UTF-8)
     * string    language tag (as defined in [RFC-3066])
     * int       num-prompts
     * string    prompt[1] (ISO-10646 UTF-8)
     * boolean   echo[1]
     * ...
     * string    prompt[num-prompts] (ISO-10646 UTF-8)
     * boolean   echo[num-prompts]
     */
    public static final byte SSH_MSG_USERAUTH_INFO_REQUEST = 60;

    /**
     * byte      SSH_MSG_USERAUTH_INFO_RESPONSE
     * int       num-responses
     * string    response[1] (ISO-10646 UTF-8)
     * ...
     * string    response[num-responses] (ISO-10646 UTF-8)
     */
    public static final byte SSH_MSG_USERAUTH_INFO_RESPONSE = 61;

    /**
     * byte      SSH_MSG_GLOBAL_REQUEST
     * string    request name in US-ASCII only
     * boolean   want reply
     * ....      request-specific data follows
     */
    public static final byte SSH_MSG_GLOBAL_REQUEST = 80;

    /**
     * byte      SSH_MSG_REQUEST_SUCCESS
     * ....     response specific data
     */
    public static final byte SSH_MSG_REQUEST_SUCCESS = 81;

    /**
     * byte      SSH_MSG_REQUEST_FAILURE
     */
    public static final byte SSH_MSG_REQUEST_FAILURE = 82;

    /**
     * byte      SSH_MSG_CHANNEL_OPEN
     * string    channel type in US-ASCII only
     * uint32    sender channel
     * uint32    initial window size
     * uint32    maximum packet size
     * ....      channel type specific data follows
     */
    public static final byte SSH_MSG_CHANNEL_OPEN = 90;

    /**
     * byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
     * uint32    recipient channel
     * uint32    sender channel
     * uint32    initial window size
     * uint32    maximum packet size
     * ....      channel type specific data follows
     */
    public static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;

    /**
     * uint32    recipient channel
     * uint32    reason code
     * string    description in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    public static final byte SSH_MSG_CHANNEL_OPEN_FAILURE = 92;

    /**
     * byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
     * uint32    recipient channel
     * uint32    bytes to add
     */
    public static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;

    /**
     * byte      SSH_MSG_CHANNEL_DATA
     * uint32    recipient channel
     * string    data
     */
    public static final byte SSH_MSG_CHANNEL_DATA = 94;

    /**
     * byte      SSH_MSG_CHANNEL_EXTENDED_DATA
     * uint32    recipient channel
     * uint32    data_type_code         only the value 1 is defined: SSH_EXTENDED_DATA_STDERR
     * string    data
     */
    public static final byte SSH_MSG_CHANNEL_EXTENDED_DATA = 95;

    /**
     * byte      SSH_MSG_CHANNEL_EOF
     * uint32    recipient channel
     */
    public static final byte SSH_MSG_CHANNEL_EOF = 96;

    /**
     * byte      SSH_MSG_CHANNEL_CLOSE
     * uint32    recipient channel
     */
    public static final byte SSH_MSG_CHANNEL_CLOSE = 97;

    /**
     * byte      SSH_MSG_CHANNEL_REQUEST
     * uint32    recipient channel
     * string    request type in US-ASCII characters only
     * boolean   want reply
     * ....      type-specific data follows
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-5.4">
     * RFC 4254 SSH Connection Protocol, section 5.4. Channel-Specific Requests</a>
     */
    public static final byte SSH_MSG_CHANNEL_REQUEST = 98;

    /**
     * byte      SSH_MSG_CHANNEL_SUCCESS
     * uint32    recipient channel
     */
    public static final byte SSH_MSG_CHANNEL_SUCCESS = 99;

    /**
     * byte      SSH_MSG_CHANNEL_FAILURE
     * uint32    recipient channel
     */
    public static final byte SSH_MSG_CHANNEL_FAILURE = 100;


    /**
     * "reason code" values for {@link #SSH_MSG_CHANNEL_OPEN_FAILURE}
     */
    public static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
    public static final int SSH_OPEN_CONNECT_FAILED = 2;
    public static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
    public static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;


    /**
     * "reason code" values for {@link #SSH_MSG_DISCONNECT}
     */
    public static final int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
    public static final int SSH_DISCONNECT_PROTOCOL_ERROR = 2;
    public static final int SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
    public static final int SSH_DISCONNECT_RESERVED = 4;
    public static final int SSH_DISCONNECT_MAC_ERROR = 5;
    public static final int SSH_DISCONNECT_COMPRESSION_ERROR = 6;
    public static final int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    public static final int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    public static final int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
    public static final int SSH_DISCONNECT_CONNECTION_LOST = 10;
    public static final int SSH_DISCONNECT_BY_APPLICATION = 11;
    public static final int SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
    public static final int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    public static final int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    public static final int SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

    /**
     * {@link #SSH_MSG_EXT_INFO} supported extension:
     * <p>
     * string      "server-sig-algs"
     * name-list   public-key-algorithms-accepted
     * <p>
     * <a href="https://datatracker.ietf.org/doc/html/rfc8308#section-3.1">
     * RFC 8308 Extension Negotiation,
     * Section 3.1. "server-sig-algs"</a>
     */
    public static final String EXT_INFO_SERVER_SIG_ALGS = "server-sig-algs";

    private SshConstants() {
    }
}
