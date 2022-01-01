
/*
 This file depends on following documents,
   - SOCKS: A protocol for TCP proxy across firewalls, Ying-Da Lee
     http://www.socks.nec.com/protocol/socks4.protocol
 */
package com.hardbackcollector.sshclient.proxy;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.SocketFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;

/*
 This file depends on following documents,
   - SOCKS: A protocol for TCP proxy across firewalls, Ying-Da Lee
     http://www.socks.nec.com/protocol/socks4.protocol
     (not accessible any more, but a copy was found here:
       http://www.ufasoft.com/doc/socks4_protocol.htm  -- P.E.)
 */

/**
 * A {@link Proxy} implementation using a SOCKS V4 proxy.
 * <p>
 * This sends an CONNECT request to connect to the desired server.
 *
 * @see <a href="http://www.socks.nec.com/protocol/socks4.protocol">SOCKS:
 * A protocol for TCP proxy across firewalls</a>
 */
public class ProxySOCKS4
        extends ProxyBase {

    private static final int DEFAULT_PORT = 1080;

    /**
     * Creates a new ProxySOCKS4 object.
     *
     * @param proxyHost the proxy's host name, maybe including the port
     *                  number separated by {@code :}. (The default port is 1080.)
     */
    public ProxySOCKS4(@NonNull final String proxyHost) {
        super(DEFAULT_PORT, proxyHost);
    }

    /**
     * Creates a new ProxySOCKS4 object.
     *
     * @param proxyHost the proxy's host name.
     * @param proxyPort the port number of the proxy.
     */
    public ProxySOCKS4(@NonNull final String proxyHost,
                       final int proxyPort) {
        super(proxyHost, proxyPort);
    }

    /**
     * returns the default proxy port - this is 1080 as defined for SOCKS.
     */
    public static int getDefaultPort() {
        return DEFAULT_PORT;
    }

    @Override
    public void connect(@NonNull final String host,
                        final int port,
                        final int timeout,
                        @NonNull final SocketFactory socketFactory)
            throws SshProxyException, IOException {
        try {
            initIO(socketFactory, timeout);

            final byte[] buf = new byte[1024];
            int index;

/*
   1) CONNECT

   The client connects to the SOCKS server and sends a CONNECT request when
   it wants to establish a connection to an application server. The client
   includes in the request packet the IP address and the port number of the
   destination host, and userid, in the following format.

               +----+----+----+----+----+----+----+----+----+----+....+----+
               | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
               +----+----+----+----+----+----+----+----+----+----+....+----+
   # of bytes:   1    1      2              4           variable       1

   VN is the SOCKS protocol version number and should be 4. CD is the
   SOCKS command code and should be 1 for CONNECT request. NULL is a byte
   of all zero bits.
*/

            index = 0;
            buf[index++] = 4;
            buf[index++] = 1;

            buf[index++] = (byte) (port >>> 8);
            buf[index++] = (byte) (port & 0xff);

            try {
                final byte[] byteAddress = InetAddress.getByName(host).getAddress();
                for (final byte address : byteAddress) {
                    buf[index++] = address;
                }
            } catch (final UnknownHostException e) {
                close();
                throw e;
            }

            if (user != null) {
                System.arraycopy(user.getBytes(StandardCharsets.UTF_8), 0, buf, index,
                                 user.length());
                index += user.length();
            }
            buf[index++] = 0;
            //noinspection ConstantConditions
            out.write(buf, 0, index);

/*
   The SOCKS server checks to see whether such a request should be granted
   based on any combination of source IP address, destination IP address,
   destination port number, the userid, and information it may obtain by
   consulting IDENT, cf. RFC 1413.  If the request is granted, the SOCKS
   server makes a connection to the specified port of the destination host.
   A reply packet is sent to the client when this connection is established,
   or when the request is rejected or the operation fails.

               +----+----+----+----+----+----+----+----+
               | VN | CD | DSTPORT |      DSTIP        |
               +----+----+----+----+----+----+----+----+
   # of bytes:   1    1      2              4

   VN is the version of the reply code and should be 0. CD is the result
   code with one of the following values:

   90: request granted
   91: request rejected or failed
   92: request rejected because SOCKS server cannot connect to
       identd on the client
   93: request rejected because the client program and identd
       report different user-ids

   The remaining fields are ignored.
*/

            final int len = 8;
            int s = 0;
            while (s < len) {
                //noinspection ConstantConditions
                final int i = in.read(buf, s, len - s);
                if (i <= 0) {
                    close();
                    throw new SshProxyException("ProxySOCKS4: stream is closed");
                }
                s += i;
            }
            if (buf[0] != 0) {
                close();
                throw new SshProxyException("ProxySOCKS4: server returns VN " + buf[0]);
            }
            if (buf[1] != 90) {
                close();
                throw new SshProxyException("ProxySOCKS4: server returns CD " + buf[1]);
            }
        } catch (final SshProxyException | IOException e) {
            close();
            throw e;
        } catch (final Exception e) {
            close();
            throw new SshProxyException("ProxySOCKS4", e);
        }
    }
}
