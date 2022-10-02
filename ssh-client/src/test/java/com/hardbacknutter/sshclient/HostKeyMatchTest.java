package com.hardbacknutter.sshclient;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hardbacknutter.sshclient.hostkey.HostKey;

import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

class HostKeyMatchTest {

    @Test
    void hkm()
            throws InvalidKeyException {
        HostKey h = new HostKey("bla.local.host,another.lo.com", "ssh-rsa", new byte[1]);

        assertTrue(h.isMatching("bla.local.host"));
        assertTrue(h.isMatching("another.lo.com"));

        assertFalse(h.isMatching("anotherone.lo.com"));

        h = new HostKey("bla.local.host,*.lo.com", "ssh-rsa", new byte[1]);
        assertTrue(h.isMatching("bla.local.host"));
        assertTrue(h.isMatching("de.lo.com"));

        h = new HostKey("bla.loc?l.host,*.lo.com", "ssh-rsa", new byte[1]);
        assertTrue(h.isMatching("bla.local.host"));
    }
}
