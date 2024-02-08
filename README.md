A simple Android app mimicking a remote control (with buttons)
to execute commands over SSH on a remote host.

Contains the module "ssh-client", a Java SSH client library:

This is a fully fledged SSH client library for use by Java (with or without Android).

It is modelled after the [jsch](https://github.com/mwiede/jsch) library but written from scratch
using proper Java JDK and [Bouncycastle](https://bouncycastle.org) API's.

<h3>Supported protocols</h3>

[Ciphers](https://github.com/tfonteyn/sshremote/blob/dev/ssh-client/src/main/java/com/hardbacknutter/sshclient/ciphers/SshCipherConstants.java)

**Compression**:  none, zlib, zlib<span>@</span>openssh.com

[Hostkey formats](https://github.com/tfonteyn/sshremote/blob/dev/ssh-client/src/main/java/com/hardbacknutter/sshclient/hostkey/HostKeyAlgorithm.java)

[Key exchange protocols](https://github.com/tfonteyn/sshremote/blob/dev/ssh-client/src/main/java/com/hardbacknutter/sshclient/kex/keyexchange/KeyExchangeConstants.java)

[Message authentication codes (MACs)](https://github.com/tfonteyn/sshremote/blob/dev/ssh-client/src/main/java/com/hardbacknutter/sshclient/macs/SshMacConstants.java)

**User authentication methods**: gssapi-with-mic, keyboard-interactive, password, publickey

**Protocol extensions**: server-sig-algs