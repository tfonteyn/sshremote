package com.hardbacknutter.sshclient.channels.forward;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SocketFactory;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * @see <a href="https://www.x.org/releases/current/doc/xproto/x11protocol.html">X11 protocol</a>
 * @see <a href="https://www.x.org/releases/current/doc/xproto/x11protocol.html#connection_initiation">Connection initiation</a>
 * @see <a href="https://www.x.org/releases/current/doc/xproto/x11protocol.html#Encoding::Connection_Setup">Encoding</a>
 */
public class ChannelX11
        extends ForwardingChannel {

    /** internal use-only channel. */
    public static final String NAME = "x11";

    // LOWERCASE
    private static final byte[] HEX_BYTES =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static final int TIMEOUT_IN_MILLIS = 10_000;

    /**
     * The 16-byte bare auth cookies.
     * Used for receiving/decoding X11 packets.
     */
    private static final Map<Session, byte[]> cookiePool = new HashMap<>();
    /**
     * The 32-byte hexadecimal encoded version of the auth cookies.
     * Used for sending SSH packets.
     */
    private static final Map<Session, byte[]> hexCookiePool = new HashMap<>();

    /**
     * value 0x42 (ASCII uppercase B) means values are
     * transmitted most significant byte first
     */
    private static final int MSB = 0x42;
    /**
     * value 0x6c (ASCII lowercase l) means values are
     * transmitted least significant byte first.
     */
    private static final int LSB = 0x6c;

    /**
     * The local X11 host (display 0)
     */
    private static String host = "127.0.0.1";
    /**
     * The local X11 port
     */
    private static int port = 6000;
    /**
     * Must be set by {@link ChannelX11#setCookie(String)} with the authentication
     * cookie for the local X11 server
     * <p>
     * Bare 16-byte array
     */
    private static byte[] cookie;

    @NonNull
    private final SocketFactory socketFactory;

    /**
     * Handle the Connection initiation in the first packet received.
     */
    private boolean initConnection = true;

    ChannelX11(@NonNull final SessionImpl session) {
        super(NAME, session);

        this.socketFactory = session.getSocketFactory();
        connected = true;
    }

    public static void setHost(@NonNull final String host) {
        ChannelX11.host = host;
    }

    public static void setPort(final int port) {
        ChannelX11.port = port;
    }

    public static void setCookie(@NonNull final String cookie)
            throws ArrayIndexOutOfBoundsException {
        if (cookie.length() != 32) {
            // MIT-magic-cookie-1 must be 128 bits
            throw new ArrayIndexOutOfBoundsException("cookie must be a 32 hex char string");
        }

        final byte[] hex = cookie.toLowerCase(Locale.ENGLISH).getBytes(StandardCharsets.UTF_8);
        ChannelX11.cookie = hexDecode(hex);
    }

    private static byte[] hexDecode(@NonNull final byte[] hexBytes) {
        final byte[] bytes = new byte[16];
        for (int i = 0; i < 16; i++) {
            bytes[i] = (byte) (((Character.digit(hexBytes[i * 2], 16) << 4) & 0xf0) |
                    ((Character.digit(hexBytes[i * 2 + 1], 16)) & 0xf));
        }
        return bytes;
    }

    /**
     * Encode a 16 byte array containing 8-bit values into a 32 byte array containing
     * the hexadecimal representation of those bytes.
     *
     * @param bytes to encode
     *
     * @return hex byte[] (1 byte == hex enc of 1 nibble)
     */
    @NonNull
    private static byte[] hexEncode(@NonNull final byte[] bytes) {
        final byte[] hexBytes = new byte[32];
        for (int i = 0; i < 16; i++) {
            hexBytes[2 * i] = HEX_BYTES[(bytes[i] >>> 4) & 0xf];
            hexBytes[2 * i + 1] = HEX_BYTES[(bytes[i]) & 0xf];
        }
        return hexBytes;
    }

    /**
     * Get or create the 'x11 authentication cookie' for the given session.
     *
     * @param session to match
     *
     * @return the hexadecimal encoded cookie, ready to send.
     */
    @NonNull
    public static byte[] getHexEncodedAuthCookie(@NonNull final Session session)
            throws NoSuchAlgorithmException {
        synchronized (hexCookiePool) {

            byte[] hexEncodedCookie = hexCookiePool.get(session);
            if (hexEncodedCookie == null) {
                final byte[] cookieBlob = session.getConfig().getRandom().nextBytes(16);
                cookiePool.put(session, cookieBlob);

                hexEncodedCookie = hexEncode(cookieBlob);
                hexCookiePool.put(session, hexEncodedCookie);
            }
            return hexEncodedCookie;
        }
    }

    public static void removeAuthCookie(@NonNull final Session session) {
        synchronized (hexCookiePool) {
            hexCookiePool.remove(session);
            cookiePool.remove(session);
        }
    }

    /**
     * The channel transfer loop.
     */
    @Override
    protected void run() {
        try {
            final Socket socket = socketFactory.createSocket(host, port, TIMEOUT_IN_MILLIS);
            socket.setTcpNoDelay(true);
            setInputStream(socket.getInputStream());
            setOutputStream(socket.getOutputStream());
            sendChannelOpenConfirmation();

        } catch (final Exception e) {
            sendChannelOpenFailure(SshConstants.SSH_OPEN_CONNECT_FAILED);
            disconnect();
            return;
        }

        runDataTransferLoop();
    }

    @Override
    protected void writeData(@NonNull final byte[] bytes,
                             final int offset,
                             final int length)
            throws IOException {

        if (initConnection) {
            initConnection(bytes, offset, length);
        } else {
            ioStreams.write(bytes, offset, length);
        }
    }

    /**
     * Handle the initial X11 connection packet, and swap the auth cookie as needed.
     */
    private void initConnection(@NonNull final byte[] bytes,
                                final int offset,
                                final int length)
            throws IOException {
        // See class header docs
        final byte[] data = Arrays.copyOfRange(bytes, offset, offset + length);
        // sanity check
        if (data.length < 9) {
            // invalid packet
            return;
        }

        // data[0]                                  byte-order
        //                        #x42     MSB first
        //                        #x6C     LSB first
        // data[1]                                  unused
        // data[2] / data[3]      16-bit int        protocol-major-version
        // data[4] / data[5]      16-bit int        protocol-minor-version
        // data[6] / data[7]      n                 length of authorization-protocol-name
        // data[8] / data[9]      d                 length of authorization-protocol-data
        // data[10] / data[11]                      unused

        //      n     STRING8          authorization-protocol-name
        //      p                      unused, p=pad(n)
        //      d     STRING8          authorization-protocol-data
        //      q                      unused, q=pad(d)
        //
        // with pad(E) = (4 - (E mod 4)) mod 4

        // length of authorization-protocol-name;
        final int authProtocolLength;
        // length of authorization-protocol-data
        final int cookieDataLength;

        if ((data[0] & 0xff) == MSB) {
            authProtocolLength = (data[6] & 0xff) * 256 + (data[7] & 0xff);
            cookieDataLength = (data[8] & 0xff) * 256 + (data[9] & 0xff);

        } else if ((data[0] & 0xff) == LSB) {
            authProtocolLength = (data[7] & 0xff) * 256 + (data[6] & 0xff);
            cookieDataLength = (data[9] & 0xff) * 256 + (data[8] & 0xff);
        } else {
            // invalid packet
            return;
        }

        // We only support "MIT-MAGIC_COOKIE-1", so the data is our cookie.

        // 12 is the offset where the authorization-protocol-name starts,
        // add the length of the name + the unused bytes in between
        final int cookieStartOffset = 12 + authProtocolLength + ((-authProtocolLength) & 3);

        // sanity check
        if (data.length < cookieStartOffset + cookieDataLength) {
            // invalid packet
            return;
        }

        // The embedded cookie
        final byte[] packetCookie =
                Arrays.copyOfRange(data, cookieStartOffset,
                                   cookieStartOffset + cookieDataLength);

        // The fake (local session) cookie as created when the RequestX11 packet was send
        final byte[] fakeCookie;
        synchronized (cookiePool) {
            fakeCookie = cookiePool.get(getSession());
        }

        if (Arrays.equals(packetCookie, fakeCookie)) {
            // If the user has called #setCookie(), overwrite the embedded (fake)
            // cookie with that one before we hand the packet to the user's X port.
            if (cookie != null) {
                System.arraycopy(cookie, 0, data, cookieStartOffset, cookieDataLength);
            }
            ioStreams.write(data, 0, data.length);

            initConnection = false;

        } else {
            // Cookie mismatch, quit!
            channelThread = null;
            sendEOF();
            disconnect();
        }
    }
}
