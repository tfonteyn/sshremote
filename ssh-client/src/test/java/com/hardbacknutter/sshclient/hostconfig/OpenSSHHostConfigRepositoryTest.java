package com.hardbacknutter.sshclient.hostconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.kex.KexProposal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Test client:
 * <pre>
 * {@code ssh -Q cipher} to list all supported ciphers
 * {@code ssh -G dev} to test/list the config for the host "dev"
 * </pre>
 */
class OpenSSHHostConfigRepositoryTest
        extends BaseConnectionTest {

    private static final String configFile = Constants.RESOURCES + "ssh_config";

    private static final int ZIP = 0;
    private static final String COMPRESS_YES = "zlib@openssh.com,zlib,none";
    private static final String COMPRESS_NO = "none,zlib@openssh.com,zlib";

    private HostConfigRepository repo;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);

        repo = OpenSSHHostConfigRepository.parseFile(configFile);
    }

    @Test
    void parseFile01() {
        final HostConfig host = repo.getHostConfig("");
        assertNotNull(host);
        System.out.println(host);
        assertEquals("ERROR", host.getString(HostConfig.LOG_LEVEL));

        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));

        assertEquals("root", host.getUser());
        assertEquals("10.0.0.1", host.getString(HostConfig.BIND_ADDRESS));

        final List<String> ciphers = host.getStringList(HostConfig.CIPHERS, null);
        System.out.println(ciphers);
        assertEquals(2, ciphers.size());
        assertEquals("aes256-ctr", ciphers.get(0));
        assertEquals("rijndael-cbc@lysator.liu.se", ciphers.get(1));
    }

    @Test
    void parseFile02() {
        final HostConfig host = repo.getHostConfig("dev");
        assertNotNull(host);
        System.out.println(host);
        assertEquals("ERROR", host.getString(HostConfig.LOG_LEVEL));

        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));

        assertEquals("john", host.getUser());
        assertEquals("dev.example.com", host.getHostname());
        assertEquals(2322, host.getPort());
        assertEquals("10.0.0.1", host.getString(HostConfig.BIND_ADDRESS));

        final List<String> ciphers = host.getStringList(HostConfig.CIPHERS, null);
        System.out.println(ciphers);
        assertEquals(2, ciphers.size());
        assertEquals("aes256-ctr", ciphers.get(0));
        assertEquals("rijndael-cbc@lysator.liu.se", ciphers.get(1));

        assertEquals("~/.ssh/keys/dev_key", host.getString(HostConfig.IDENTITY_FILE));
    }

    @Test
    void parseFile03() {
        final HostConfig host = repo.getHostConfig("targaryen");
        assertNotNull(host);
        System.out.println(host);
        assertEquals("FATAL", host.getString(HostConfig.LOG_LEVEL));

        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));

        assertEquals("daenerys", host.getUser());
        assertEquals("192.168.1.10", host.getHostname());
        assertEquals(7654, host.getPort());
        assertEquals("10.0.0.1", host.getString(HostConfig.BIND_ADDRESS));

        final List<String> ciphers = host.getStringList(HostConfig.CIPHERS, null);
        System.out.println(ciphers);
        assertEquals(3, ciphers.size());
        assertEquals("aes256-ctr", ciphers.get(0));
        assertEquals("rijndael-cbc@lysator.liu.se", ciphers.get(1));
        assertEquals("aes192-cbc", ciphers.get(2));

        assertEquals("~/.ssh/targaryen.key", host.getString(HostConfig.IDENTITY_FILE));
    }

    @Test
    void parseFile04() {
        final HostConfig host = repo.getHostConfig("martell");
        assertNotNull(host);
        System.out.println(host);
        assertNotEquals("INFO", host.getString(HostConfig.LOG_LEVEL));

        assertFalse(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_NO, host.getString(KexProposal.PROPOSAL_COMP_CTOS));

        assertEquals("oberyn", host.getUser());
        assertEquals("192.168.10.50", host.getHostname());
        assertEquals(-1, host.getPort());
        assertEquals("10.0.0.1", host.getString(HostConfig.BIND_ADDRESS));

        final List<String> ciphers = host.getStringList(HostConfig.CIPHERS, null);
        System.out.println(ciphers);
        assertEquals(2, ciphers.size());
        assertEquals("aes256-ctr", ciphers.get(0));
        assertEquals("rijndael-cbc@lysator.liu.se", ciphers.get(1));
    }

    @Test
    void parseFile10() {
        final HostConfig host = repo.getHostConfig("tyrell");
        assertNotNull(host);
        System.out.println(host);
        assertEquals("ERROR", host.getString(HostConfig.LOG_LEVEL));

        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));

        assertEquals("oberyn", host.getUser());
        assertEquals("192.168.10.20", host.getHostname());
        assertEquals(-1, host.getPort());
        assertEquals("10.0.0.2", host.getString(HostConfig.BIND_ADDRESS));

        final List<String> ciphers = host.getStringList(HostConfig.CIPHERS, null);
        System.out.println(ciphers);

        assertEquals(5, ciphers.size());
        assertEquals("aes256-ctr", ciphers.get(0));
        assertEquals("rijndael-cbc@lysator.liu.se", ciphers.get(1));
        assertEquals("chacha20-poly1305@openssh.com", ciphers.get(2));
        assertEquals("aes128-ctr", ciphers.get(3));
        assertEquals("aes256-gcm@openssh.com", ciphers.get(4));
    }

    @Test
    void appendKexAlgorithms() throws IOException {
        final HostConfigRepository parse =
                OpenSSHHostConfigRepository.parse(
                        "KexAlgorithms +diffie-hellman-group1-sha1");

        final HostConfig hostConfig = parse.getHostConfig("");

        final String defValue = sshClient.getConfig(HostConfig.KEX_ALGS);

        assertEquals(String.join(",", defValue, "diffie-hellman-group1-sha1"),
                     hostConfig.getString(HostConfig.KEX_ALGS, defValue));
    }
}
