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
    public static final String ROLE = "NegotiateAuthenticationRealm";

    private static final String SPNEGO_OID = "1.3.6.1.5.5.2";

    private String hostName;

    private Configuration configuration;




    /** copied from NegotiateSecurityFilter. */
    private static final String PRINCIPAL_SESSION_KEY = NegotiateSecurityFilter.class
            .getName() + ".PRINCIPAL";

    private final IWindowsAuthProvider windowsAuthProvider;
    private final NegotiateSecurityFilterProvider negotiateProvider;

    public NegotiateAuthenticationRealm() {
        windowsAuthProvider = new WindowsAuthProviderImpl();
        negotiateProvider = new NegotiateSecurityFilterProvider(windowsAuthProvider);
    }

//    /**
//     * Template method to be overridden by subclasses to perform initialization logic at start-up.  The
//     * {@code ServletContext} and {@code FilterConfig} will be accessible
//     * (and non-{@code null}) at the time this method is invoked via the
//     * {@link #getServletContext() getServletContext()} and {@link #getFilterConfig() getFilterConfig()}
//     * methods respectively.
//     * <p/>
//     * {@code init-param} values may be conveniently obtained via the {@link #getInitParam(String)} method.
//     *
//     * @throws Exception if the subclass has an error upon initialization.
//     */
//    @Override
//    protected void onInit() throws Exception {
//        super.onInit();
//        negotiateFilter.init(getFilterConfig());
//    }




    @Override
    public boolean supports(final AuthenticationToken token) {
        return token instanceof NegotiateToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            final AuthenticationToken t) throws AuthenticationException {
        final NegotiateToken token = (NegotiateToken) t;
        Configuration.setConfiguration(configuration);

        // @todo replace below with call to validate/login windows token (via provider?)
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

    private Subject createSubject(final GSSContext context) throws GSSException {
        return GSSUtil.createSubject(context.getSrcName(),
                getDelegatedCredentials(context));
    }

    private GSSCredential getDelegatedCredentials(final GSSContext context)
            throws GSSException {
        if (context.getCredDelegState()) {
            return context.getDelegCred();
        }

        return null;
    }

    private GSSContext createContext() throws GSSException {
        final GSSManager manager = GSSManager.getInstance();
        final GSSName name = manager.createName("HTTP@" + getHostName(),
                GSSName.NT_HOSTBASED_SERVICE);
        final GSSCredential serverCreds = manager.createCredential(name,
                GSSCredential.DEFAULT_LIFETIME, new Oid(SPNEGO_OID),
                GSSCredential.ACCEPT_ONLY);
        return manager.createContext(serverCreds);
    }

    private String getHostName() {
        return hostName;
    }

    public void setHostName(final String hostName) {
        this.hostName = hostName;
    }

    public void setConfiguration(final Configuration configuration) {
        this.configuration = configuration;
    }


//    boolean tryLogin(final ServletRequest request,
//                     final ServletResponse response) throws Exception {
//
//        boolean loggedIn = false; // false by default or we wouldn't be in
//
//
//        // @todo find a better place/call to do "init" suff
//        if (negotiateFilter.getProviders() == null) {
//            negotiateFilter.init(getFilterConfig());
//        }
//
//        // @todo reuse as much as possible of NegotiateSecurityFilter.doFilterPrincipal(), and/or call isAccessAllowed() instead
//        final HttpSession existingSession = ((HttpServletRequest)request).getSession(false);
//        if (existingSession != null) {
//            final WindowsPrincipal windowsPrincipal = (WindowsPrincipal) existingSession.getAttribute(PRINCIPAL_SESSION_KEY);
//            if (windowsPrincipal != null) {
//                // we already authenticated...
//                return true;
//            }
//        }
//
//        final SignalFilterChain signalFilterChain = new SignalFilterChain();
//        negotiateFilter.doFilter(request, response, signalFilterChain);
//
//
//        final org.apache.shiro.subject.Subject currentUser = SecurityUtils.getSubject();
///*
//        if (!currentUser.isAuthenticated()) {
//            return false;
//        }
//*/
//        //final HttpSession session = ((HttpServletRequest)request).getSession(false);
//        final Session session = currentUser.getSession(false);
//        if (session == null) {
//            return false;
//        }
//        final javax.security.auth.Subject subject
//                = (javax.security.auth.Subject) session.getAttribute("javax.security.auth.subject");
//        if (subject == null) {
//            return false;
//        }
//        return true;
//    }

}