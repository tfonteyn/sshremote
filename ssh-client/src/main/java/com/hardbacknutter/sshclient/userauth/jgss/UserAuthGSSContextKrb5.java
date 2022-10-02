package com.hardbacknutter.sshclient.userauth.jgss;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.userauth.SshAuthException;
import com.hardbacknutter.sshclient.userauth.UserAuthGSSContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class UserAuthGSSContextKrb5
        implements UserAuthGSSContext {

    public static final String METHOD = "gssapi-with-mic.krb5";

    private static final String pUseSubjectCredsOnly =
            "javax.security.auth.useSubjectCredsOnly";
    private static final String useSubjectCredsOnly =
            getSystemProperty(pUseSubjectCredsOnly);

    private GSSContext context;

    @Nullable
    private static String getSystemProperty(@SuppressWarnings("SameParameterValue")
                                            @NonNull final String key) {
        try {
            return System.getProperty(key);
        } catch (final Exception ignore) {
            // We are not allowed to get the System properties.
            return null;
        }
    }

    private static void setSystemProperty(@SuppressWarnings("SameParameterValue")
                                          @NonNull final String key,
                                          @NonNull final String value) {
        try {
            System.setProperty(key, value);
        } catch (final Exception ignore) {
            // We are not allowed to set the System properties.
        }
    }

    public void create(@NonNull final String user,
                       @NonNull final String host)
            throws SshAuthException {
        try {
            // RFC 1964
            final Oid krb5 = new Oid("1.2.840.113554.1.2.2");
            // Kerberos Principal Name Form
            final Oid principalName = new Oid("1.2.840.113554.1.2.2.1");

            final GSSManager mgr = GSSManager.getInstance();

            final GSSCredential crd = null;

//            try {
//                GSSName _user = mgr.createName(user, principalName);
//                crd = mgr.createCredential(_user,
//                        GSSCredential.DEFAULT_LIFETIME,
//                        krb5,
//                        GSSCredential.INITIATE_ONLY);
//            } catch (final GSSException crdex) {
//            }

            String cname = host;
            try {
                cname = InetAddress.getByName(cname).getCanonicalHostName();
            } catch (final UnknownHostException ignore) {
            }
            final GSSName gssName = mgr.createName("host/" + cname, principalName);

            context = mgr.createContext(gssName, krb5, crd, GSSContext.DEFAULT_LIFETIME);

            // RFC4462  3.4.  GSS-API Session
            //
            // When calling GSS_Init_sec_context(), the client MUST set
            // integ_req_flag to "true" to request that per-message integrity
            // protection be supported for this context.  In addition,
            // deleg_req_flag MAY be set to "true" to request access delegation, if
            // requested by the user.
            //
            // Since the user authentication process by its nature authenticates
            // only the client, the setting of mutual_req_flag is not needed for
            // this process.  This flag SHOULD be set to "false".

            // TODO: OpenSSH's sshd does accepts 'false' for mutual_req_flag
            //context.requestMutualAuth(false);
            context.requestMutualAuth(true);
            context.requestConf(true);
            context.requestInteg(true);             // for MIC
            context.requestCredDeleg(true);
            context.requestAnonymity(false);

        } catch (final GSSException e) {
            throw new SshAuthException(e);
        }
    }

    public boolean isEstablished() {
        return context.isEstablished();
    }

    @NonNull
    public byte[] init(@NonNull final byte[] token,
                       final int offset,
                       final int len)
            throws SshAuthException {
        try {
            // Without setting "javax.security.auth.useSubjectCredsOnly" to "false",
            // Sun's JVM for Un*x will show messages to stderr in
            // processing context.initSecContext().
            // This hack is not thread safe ;-<.
            // If that property is explicitly given as "true" or "false",
            // this hack must not be invoked.
            if (useSubjectCredsOnly == null) {
                setSystemProperty(pUseSubjectCredsOnly, "false");
            }
            return context.initSecContext(token, 0, len);

        } catch (final GSSException | SecurityException e) {
            throw new SshAuthException(e);

        } finally {
            if (useSubjectCredsOnly == null) {
                // By the default, it must be "true".
                setSystemProperty(pUseSubjectCredsOnly, "true");
            }
        }
    }

    @NonNull
    public byte[] getMIC(@NonNull final byte[] inMsg,
                         final int offset,
                         final int len)
            throws SshAuthException {
        try {
            final MessageProp msgProp = new MessageProp(0, true);
            return context.getMIC(inMsg, offset, len, msgProp);
        } catch (final GSSException e) {
            throw new SshAuthException(e);
        }
    }

    public void dispose() {
        try {
            context.dispose();
        } catch (final GSSException ignore) {
        }
    }
}
