package com.hardbacknutter.sshclient;

import com.hardbacknutter.sshclient.connections.ConnectionTest;

/**
 * Test server: WLS2 Ubuntu with OpenSSH installed.
 * Initial install of the SSHD server:
 * <pre>
 *     sudo apt install openssh-server
 * </pre>
 * 2024-02-03: OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022
 * <p>
 * If needed, generate host keys:
 * <pre>
 *      ssh-keygen -b 4096 -f /etc/ssh/ssh_host_rsa_key -t rsa -N ""
 *      ssh-keygen -b 1024 -f /etc/ssh/ssh_host_dsa_key -t dsa -N ""
 *
 *      ssh-keygen -b 256 -f /etc/ssh/ssh_host_ecdsa_256_key -t ecdsa -N ""
 *      ssh-keygen -b 384 -f /etc/ssh/ssh_host_ecdsa_384_key -t ecdsa -N ""
 *      ssh-keygen -b 521 -f /etc/ssh/ssh_host_ecdsa_521_key -t ecdsa -N ""
 *
 *      ssh-keygen -f /etc/ssh/ssh_host_ed25519_key -t ed25519 -N ""
 *
 *      chmod 600 /etc/ssh/ssh_host_*_key
 * </pre>
 * Advice is not to edit the standard "/etc/ssh/sshd_config" but to add a file
 * e.g. "ssh4j.conf"
 * <pre>
 *      /etc/ssh/sshd_config.d/ssh4j.conf";
 * </pre>
 * <p>
 * Content of "ssh4j.conf":
 * The port must match {@link #PORT}.
 * <p>
 * Make sure none of these are already set in "/etc/ssh/sshd_config" !
 * <pre>
 *  Port 2222
 *
 *  PubkeyAuthentication yes
 *  PasswordAuthentication yes
 *  KbdInteractiveAuthentication yes
 *
 *  hostkey /etc/ssh/ssh_host_rsa_key
 *  hostkey /etc/ssh/ssh_host_dsa_key
 *
 *  hostkey /etc/ssh/ssh_host_ecdsa_256_key
 *  hostkey /etc/ssh/ssh_host_ecdsa_384_key
 *  hostkey /etc/ssh/ssh_host_ecdsa_521_key
 *
 *  hostkey /etc/ssh/ssh_host_ed25519_key
 * </pre>
 * Defaults for reference:
 * <pre>
 *     kexalgorithms        curve25519-sha256,
 *                          curve25519-sha256@libssh.org,
 *                          ecdh-sha2-nistp256,
 *                          ecdh-sha2-nistp384,
 *                          ecdh-sha2-nistp521,
 *                          sntrup761x25519-sha512@openssh.com,
 *                          diffie-hellman-group-exchange-sha256,
 *                          diffie-hellman-group16-sha512,
 *                          diffie-hellman-group18-sha512,
 *                          diffie-hellman-group14-sha256
 *
 *     hostkeyalgorithms    ssh-ed25519-cert-v01@openssh.com,
 *                          ecdsa-sha2-nistp256-cert-v01@openssh.com,
 *                          ecdsa-sha2-nistp384-cert-v01@openssh.com,
 *                          ecdsa-sha2-nistp521-cert-v01@openssh.com,
 *                          sk-ssh-ed25519-cert-v01@openssh.com,
 *                          sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,
 *                          rsa-sha2-512-cert-v01@openssh.com,
 *                          rsa-sha2-256-cert-v01@openssh.com,
 *                          ssh-ed25519,
 *                          ecdsa-sha2-nistp256,
 *                          ecdsa-sha2-nistp384,
 *                          ecdsa-sha2-nistp521,
 *                          sk-ssh-ed25519@openssh.com,
 *                          sk-ecdsa-sha2-nistp256@openssh.com,
 *                          rsa-sha2-512,
 *                          rsa-sha2-256
 *
 *     pubkeyacceptedalgorithms     ssh-ed25519-cert-v01@openssh.com,
 *                                  ecdsa-sha2-nistp256-cert-v01@openssh.com,
 *                                  ecdsa-sha2-nistp384-cert-v01@openssh.com,
 *                                  ecdsa-sha2-nistp521-cert-v01@openssh.com,
 *                                  sk-ssh-ed25519-cert-v01@openssh.com,
 *                                  sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,
 *                                  rsa-sha2-512-cert-v01@openssh.com,
 *                                  rsa-sha2-256-cert-v01@openssh.com,
 *                                  ssh-ed25519,
 *                                  ecdsa-sha2-nistp256,
 *                                  ecdsa-sha2-nistp384,
 *                                  ecdsa-sha2-nistp521,
 *                                  sk-ssh-ed25519@openssh.com,
 *                                  sk-ecdsa-sha2-nistp256@openssh.com,
 *                                  rsa-sha2-512,
 *                                  rsa-sha2-256
 *
 *     ciphers  chacha20-poly1305@openssh.com,
 *              aes128-ctr,
 *              aes192-ctr,
 *              aes256-ctr,
 *              aes128-gcm@openssh.com,
 *              aes256-gcm@openssh.com
 *
 *     macs     umac-64-etm@openssh.com,
 *              umac-128-etm@openssh.com,
 *              hmac-sha2-256-etm@openssh.com,
 *              hmac-sha2-512-etm@openssh.com,
 *              hmac-sha1-etm@openssh.com,
 *              umac-64@openssh.com,
 *              umac-128@openssh.com,
 *              hmac-sha2-256,
 *              hmac-sha2-512,
 *              hmac-sha1
 * </pre>
 * Useful command to see the current config
 * <pre>
 *    sudo /usr/sbin/sshd -T
 * </pre>
 * <p>
 * Optional / as needed - Allow Windows host to access WSL sshd:
 * <p>
 * Find the IP address and update {@link #HOST}.
 * <pre>
 *      # Powershell as admin, find the WSL ip:
 *      wsl hostname -I
 *
 *      # example: 172.20.137.77
 * </pre>
 * <p>
 * Port forwarding / firewall configuration:
 * <pre>
 *      # Windows OS port forwarding from the external address to WSL2:
 *      netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=2222 connectaddress=172.20.137.77 connectport=2222
 *
 *      # Open the firewall
 *      netsh advfirewall firewall add rule name="ALLOW TCP PORT 2222" dir=in action=allow protocol=TCP localport=2222
 *
 *      # Close the firewall
 *      netsh advfirewall firewall delete rule name="ALLOW TCP PORT 2222"
 * </pre>
 * <p>
 * <p>
 * When systemd is active:
 * <pre>
 *     systemctl start sshd.service
 *     systemctl stop sshd.service
 *     systemctl status sshd.service
 * </pre>
 * <p>
 * Without systemd:
 * <pre>
 *     sudo service rsyslog start
 *     sudo service ssh start
 *     sudo service ssh stop
 * </pre>
 * Alternative, with the background service stopped,
 * start for a single connection in foreground/debug mode:
 * <pre>
 *     sudo /usr/sbin/sshd -d
 * </pre>
 * -------------------------------------------------------------------------
 * Server side test user setup:
 * <p>
 * Add a "{@link #USERNAME} user with password {@link #PASSWORD} and login as this user.
 * <p>
 * Create "~/long.txt" with more than 4k of text. e.g. "help >long.txt" should do
 * <pre>
 *     help >~/long.txt
 * </pre>
 * <p>
 * Create the basic .ssh files:
 * <pre>
 *      mkdir ~/.ssh
 *      touch ~/.ssh/authorized_keys
 *      chmod 600 ~/.ssh/authorized_keys
 * </pre>
 * Edit "~/.ssh/authorized_keys" and add one or more
 * public keys from the clients "~/.ssh/*.pub" file(s)
 * (Windows clients:  "%USERPROFILE%\.ssh\*.pub"
 * <p>
 * -------------------------------------------------------------------------
 * Client side test user setup:
 * <p>
 * Prepare the {@link #KNOWN_HOSTS} file with the server side public keys.
 * Example keys as generated above:
 * <pre>
 *      172.20.137.77 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdH[snip]
 *      172.20.137.77 ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdH[snip]
 *      172.20.137.77 ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdH[snip]
 *      172.20.137.77 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDBl0LOnm9[snip]
 *      172.20.137.77 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDXflt+RO[snip]
 * </pre>
 * Update the list at {@link ConnectionTest#withKeys()} matching the ones
 * you added to the server "~/.ssh/authorized_keys"
 */
public final class Constants {
    public static final String KEY_FILES_PASSPHRASE = "secret";

    public static final String RESOURCES = "src/test/resources/";
    public static final String HOST = "172.20.137.77";
    public static final String USERNAME = "test";
    public static final String PASSWORD = "test";
    public static final int PORT = 2222;

    public static final String KNOWN_HOSTS = "C:/tmp/ssh/known_hosts";

    private Constants() {
    }

}
