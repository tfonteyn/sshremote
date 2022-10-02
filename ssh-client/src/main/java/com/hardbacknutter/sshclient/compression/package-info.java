
/**
 * <h4>Compression {@link com.hardbacknutter.sshclient.compression.SshInflater}
 * and {@link com.hardbacknutter.sshclient.compression.SshDeflater}</h4>
 * <p>
 * The below three are hardcoded; any others listed will be ignored.
 * </p>
 * <p>
 * <h4>Implementations</h4>
 * <dl>
 *   <dt>{@code none}</dt>
 *   <dd>no compression</dd>
 *
 *   <dt>{@code zlib}</dt>
 *   <dd>zlib compression <a href="https://datatracker.ietf.org/doc/html/rfc1950">RFC 1950</a>
 *   and <a href="https://datatracker.ietf.org/doc/html/rfc1951">1951</a>)</dd>
 *
 *   <dt>{@code zlib@openssh.com}</dt>
 *   <dd>A variant of the zlib compression where the compression
 *       only starts after the client user is authenticated.
 *       This is described in the Internet-Draft
 *       <a href="https://datatracker.ietf.org/doc/html/draft-miller-secsh-compression-delayed-00">
 *           draft-miller-secsh-compression-delayed-00</a>.</dd>
 * </dl>
 * <p>
 * <h4>Configuration</h4>
 * <dl>
 *  <dt>{@code compression.c2s}</dt><dd>Compression algorithms
 *    for client-to-server transport. The default is "none",
 *    but this library also supports "zlib" and "zlib@openssh.com".</dd>
 *
 *  <dt>{@code compression.s2c}</dt><dd>Compression algorithms
 *    for server-to-client transport. The default is "none",
 *    but this library also supports "zlib" and "zlib@openssh.com".</dd>
 *
 *   <dt>{@code compression_level}</dt><dd>The compression level
 *      for client-to-server transport. This will only be used if the
 *      negotiated compression method is one of {@code zlib} and
 *      {@code zlib@openssh.com}.</dd>
 * </dl>
 */
package com.hardbacknutter.sshclient.compression;
