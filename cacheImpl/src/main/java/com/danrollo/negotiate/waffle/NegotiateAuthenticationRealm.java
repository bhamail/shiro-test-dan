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
import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

@SuppressWarnings("restriction")
public class NegotiateAuthenticationRealm extends AuthorizingRealm {

    private final IWindowsAuthProvider windowsAuthProvider;

    public NegotiateAuthenticationRealm() {
        windowsAuthProvider = new WindowsAuthProviderImpl();
    }


    @Override
    public boolean supports(final AuthenticationToken token) {
        return token instanceof NegotiateToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            final AuthenticationToken t) throws AuthenticationException {

        final NegotiateToken token = (NegotiateToken) t;
//        Configuration.setConfiguration(configuration);

        // replace below with call to validate/login windows token (via provider?)
        // @todo Maybe negotiations should be done here instead of earlier in NegotiateAuthenticationFilter.onAccessDenied()? see: javadoc for NegotiateAuthenticationFilter.tryLogin()
/*
        final byte[] inToken = token.getIn();
        try {
            final GSSContext context = createContext();
            final byte outToken[] = context.acceptSecContext(inToken, 0,
                    inToken.length);
            token.setOut(outToken);
            if (context.isEstablished()) {
//            if (tryLogin(request, response)) {
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
        final String fqn = ((WindowsPrincipal)token.getPrincipal()).getName();
        final IWindowsAccount windowsAccount = windowsAuthProvider.lookupAccount(fqn);
        if (windowsAccount == null) {
            throw new AuthenticationException("Invalid Windows Principal, fqn: " + fqn);
        }

        final String sidString = windowsAccount.getSidString();
        if (sidString == null) {
            throw new AuthenticationException("Invalid Windows Principal, fqn: " + fqn);
        }

        return token.createInfo();
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            final PrincipalCollection principals) {
        return null;
    }

}