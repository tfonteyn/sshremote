package com.hardbackcollector.sshclient.hostconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hardbackcollector.sshclient.connections.BaseConnectionTest;
import com.hardbackcollector.sshclient.kex.KexProposal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

class OpenSSHHostConfigRepositoryTest
        extends BaseConnectionTest {

    private static final String configFile = TEST_RESOURCES + "ssh_config";

    private static final int ZIP = 0;
    private static final String COMPRESS_YES = "zlib@openssh.com,zlib,none";

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
        System.out.println(host);

        assertNotNull(host);
        assertEquals("root", host.getUser());
        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));
        assertEquals("INFO", host.getString("LogLevel"));
    }

    @Test
    void parseFile02() {
        final HostConfig host = repo.getHostConfig("dev");
        System.out.println(host);

        assertNotNull(host);
        assertEquals("john", host.getUser());
        assertEquals("dev.example.com", host.getHostname());
        assertEquals(2322, host.getPort());
        assertEquals("~/.ssh/keys/dev_key", host.getString(HostConfig.IDENTITY_FILE));
        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));
        assertEquals("INFO", host.getString("LogLevel"));
    }

    @Test
    void parseFile03() {
        final HostConfig host = repo.getHostConfig("targaryen");
        System.out.println(host);

        assertNotNull(host);
        assertEquals("daenerys", host.getUser());
        assertEquals("192.168.1.10", host.getHostname());
        assertEquals(7654, host.getPort());
        assertEquals("~/.ssh/targaryen.key", host.getString(HostConfig.IDENTITY_FILE));
        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));
        assertEquals("INFO", host.getString("LogLevel"));
    }

    @Test
    void parseFile04() {
        final HostConfig host = repo.getHostConfig("tyrell");
        System.out.println(host);

        assertNotNull(host);
        assertEquals("oberyn", host.getUser());
        assertEquals("192.168.10.20", host.getHostname());
        assertEquals("INFO", host.getString("LogLevel"));
        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));

        List<String> ciphers = host.getStringList("Ciphers", null);
        assertEquals(5, ciphers.size());
        assertEquals("blowfish-cbc", ciphers.get(0));
        assertEquals("chacha20-poly1305@openssh.com", ciphers.get(1));
        assertEquals("aes128-ctr", ciphers.get(2));
        assertEquals("3des-cbc", ciphers.get(3));
        assertEquals("aes192-cbc", ciphers.get(4));

        final String defCiphers = sshClient.getConfig(KexProposal.PROPOSAL_CIPHER_STOC);
        assertEquals("chacha20-poly1305@openssh.com,"
                        + "aes128-ctr,"
                        + "aes192-ctr,"
                        + "aes256-ctr,"
                        + "aes128-gcm@openssh.com,"
                        + "aes256-gcm@openssh.com",
                defCiphers,
                "The default cipher list is not as expected. Update the test-code!");

        ciphers = host.getStringList("Ciphers", defCiphers);
        // [blowfish-cbc, chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr,
        // aes128-gcm@openssh.com, aes256-gcm@openssh.com, 3des-cbc, aes192-cbc]
        //System.out.println(ciphers);

        assertEquals(8, ciphers.size());
        assertEquals("blowfish-cbc", ciphers.get(0));
        assertEquals("chacha20-poly1305@openssh.com", ciphers.get(1));
        assertEquals("aes128-ctr", ciphers.get(2));
        assertEquals("aes192-ctr", ciphers.get(3));
        assertEquals("aes128-gcm@openssh.com", ciphers.get(4));
        assertEquals("aes256-gcm@openssh.com", ciphers.get(5));
        assertEquals("3des-cbc", ciphers.get(6));
        assertEquals("aes192-cbc", ciphers.get(7));
    }

    @Test
    void parseFile05() {
        final HostConfig host = repo.getHostConfig("martell");
        System.out.println(host);

        assertNotNull(host);
        assertEquals("192.168.10.50", host.getHostname());
        assertEquals("oberyn", host.getUser());
        assertNotEquals("INFO", host.getString("LogLevel"));
        assertTrue(host.getBooleanValue(HostConfig.COMPRESSION, false));
        assertEquals(COMPRESS_YES, host.getString(KexProposal.PROPOSAL_COMP_CTOS));
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
