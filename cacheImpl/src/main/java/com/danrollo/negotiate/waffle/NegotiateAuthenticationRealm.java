package com.danrollo.negotiate.waffle;

/**
 * Derived from net.skorgenes.security.jsecurity.negotiate.NegotiateAuthenticationFilter.
 * see: https://bitbucket.org/lothor/shiro-negotiate/src/7b25efde130b/src/main/java/net/skorgenes/security/jsecurity/negotiate/NegotiateAuthenticationRealm.java?at=default
 *
 * @author Dan Rollo
 * Date: 1/16/13
 * Time: 12:23 AM
 */
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.sun.security.jgss.GSSUtil;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.servlet.WindowsPrincipal;
import waffle.servlet.spi.NegotiateSecurityFilterProvider;
import waffle.servlet.spi.SecurityFilterProvider;
import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

import java.security.Principal;

@SuppressWarnings("restriction")
public class NegotiateAuthenticationRealm extends AuthorizingRealm {

    private final IWindowsAuthProvider windowsAuthProvider;
    //private final SecurityFilterProvider waffleProviderNegotiate;

    private Configuration configuration;

    public NegotiateAuthenticationRealm() {
        windowsAuthProvider = new WindowsAuthProviderImpl();
        //waffleProviderNegotiate = new NegotiateSecurityFilterProvider(windowsAuthProvider);
    }


    @Override
    public boolean supports(final AuthenticationToken token) {
        return token instanceof NegotiateToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            final AuthenticationToken t) throws AuthenticationException {

        final NegotiateToken token = (NegotiateToken) t;
        Configuration.setConfiguration(configuration);
        final byte[] inToken = token.getIn();
//        try {
            // @todo check for ntlmPost

            final IWindowsSecurityContext securityContext;
        try {
            securityContext = windowsAuthProvider.acceptSecurityToken(
                    token.getConnectionId(), inToken, token.getSecurityPackage());
        } catch (RuntimeException e) {
            throw new AuthenticationException(e);
        }

            byte[] continueTokenBytes = securityContext.getToken();
            token.setOut(continueTokenBytes);

            if (securityContext.isContinue()
                    //|| ntlmPost
                    ) {
                throw new AuthenticationInProgressException();
            }

            final IWindowsIdentity windowsIdentity = securityContext.getIdentity();
            securityContext.dispose();

            final Principal principal = new WindowsPrincipal(windowsIdentity);
            token.setPrincipal(principal);

            final Subject subject = new Subject();
            subject.getPrincipals().add(principal);
            token.setSubject(subject);

            return token.createInfo();

/*
            final GSSContext context = createContext();
            final byte outToken[] = context.acceptSecContext(inToken, 0,
                    inToken.length);
            token.setOut(outToken);
            if (context.isEstablished()) {
                final Subject subject = createSubject(context);
                token.setSubject(subject);
                return token.createInfo();
            } else {
                throw new AuthenticationInProgressException();
            }
        } catch (final GSSException e) {
            throw new AuthenticationException(e);
        }
*/
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            final PrincipalCollection principals) {
        return null;
    }


    public void setConfiguration(final Configuration configuration) {
        this.configuration = configuration;
    }

}