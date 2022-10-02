package com.hardbacknutter.sshclient.channels.sftp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.utils.Globber;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

class LocalPathTest {

    private Path lpwd;

    /**
     * The original byte[] based algorithms from jsch.
     */

    @NonNull
    static List<String> glob_with_bytes(@NonNull final Path lcwd,
                                        @NonNull final String path) {
        final String absPath;
        if (!path.isEmpty() && new File(path).isAbsolute()) {
            absPath = path;
        } else {
            absPath = lcwd.toString() + File.separatorChar + path;
        }

        final boolean fs_is_bs = File.separatorChar == '\\';

        final byte[] pathBytes = absPath.getBytes(StandardCharsets.UTF_8);

        int i = pathBytes.length - 1;
        while (i >= 0) {
            if (pathBytes[i] != '*' && pathBytes[i] != '?') {
                i--;
                continue;
            }
            if (!fs_is_bs && i > 0 && pathBytes[i - 1] == '\\') {

                i--;
                if (i > 0 && pathBytes[i - 1] == '\\') {
                    i--;
                    i--;
                    continue;
                }
            }
            break;
        }

        if (i < 0) {
            final List<String> list = new ArrayList<>();
            list.add(fs_is_bs ? absPath : Globber.unescapePath(absPath));
            return list;
        }

        while (i >= 0) {
            // On Windows, both '\' and '/' can be used as the separator.
            if (pathBytes[i] == File.separatorChar || fs_is_bs && pathBytes[i] == '/') {
                break;
            }
            i--;
        }

        if (i < 0) {
            final List<String> list = new ArrayList<>();
            list.add(fs_is_bs ? absPath : Globber.unescapePath(absPath));
            return list;
        }

        final String dir;
        if (i == 0) {
            // root
            dir = File.separator;
        } else {
            dir = new String(pathBytes, 0, i, StandardCharsets.UTF_8);
        }

        final byte[] tmpBuf = new byte[pathBytes.length - i - 1];
        System.arraycopy(pathBytes, i + 1, tmpBuf, 0, tmpBuf.length);
        final String pattern = new String(tmpBuf, 0, tmpBuf.length, StandardCharsets.UTF_8);

        final String[] children = new File(dir).list();
        if (children != null) {
            return Arrays.stream(children)
                         .filter(child -> Globber.globRemotePath(pattern, child))
                         .map(child -> new File(dir, child).getAbsolutePath())
                         .collect(Collectors.toList());

        }
        return new ArrayList<>();
    }

    @BeforeEach
    void setup() throws IOException {
        lpwd = new File("").toPath();
    }

    /**
     * TODO: don't rely on this directory:
     * <pre>
     *     c:\tmp\avd
     *     c:\tmp\d.txt
     *     c:\tmp\glenat.txt
     *     c:\tmp\insert.sql
     *     c:\tmp\ssh
     * </pre>
     */
    @Test
    void glob10() throws IOException {
        final List<String> s = ChannelSftpImpl.expandLocalPattern(lpwd, "c:\\tmp\\*");
        final List<String> b = glob_with_bytes(lpwd, "c:\\tmp\\*");
        assertEquals(s, b);

    }

    @Test
    void glob11() throws IOException {
        final List<String> s = ChannelSftpImpl.expandLocalPattern(lpwd, "c:/tmp/*");
        final List<String> b = glob_with_bytes(lpwd, "c:/tmp/*");
        assertEquals(s, b);
    }

    @Test
    void glob12() throws IOException {
        final List<String> s = ChannelSftpImpl.expandLocalPattern(lpwd, "c:/tmp/*.txt");
        final List<String> b = glob_with_bytes(lpwd, "c:/tmp/*.txt");
        assertEquals(s, b);
    }

    @Test
    void glob13() throws IOException {
        final List<String> s = ChannelSftpImpl.expandLocalPattern(lpwd, "c:/tmp/*en??.txt");
        final List<String> b = glob_with_bytes(lpwd, "c:/tmp/*en??.txt");
        assertEquals(s, b);
    }

    @Test
    void glob20() throws IOException {
        final List<String> s = ChannelSftpImpl.expandLocalPattern(lpwd, "/*");
        final List<String> b = glob_with_bytes(lpwd, "/*");
        assertEquals(s, b);
    }

    @Test
    void glob21() throws IOException {
        final List<String> s = ChannelSftpImpl.expandLocalPattern(lpwd, "/*nor?");
        final List<String> b = glob_with_bytes(lpwd, "/*nor?");
        assertEquals(s, b);
    }

}