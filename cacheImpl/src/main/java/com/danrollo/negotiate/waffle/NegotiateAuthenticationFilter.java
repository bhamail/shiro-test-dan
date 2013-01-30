package com.danrollo.negotiate.waffle;

/**
 * Derived from net.skorgenes.security.jsecurity.negotiate.NegotiateAuthenticationFilter.
 * see: https://bitbucket.org/lothor/shiro-negotiate/src/7b25efde130b9cbcacf579b3f926c532d919aa23/src/main/java/net/skorgenes/security/jsecurity/negotiate/NegotiateAuthenticationFilter.java?at=default
 *
 * @author Dan Rollo
 * Date: 1/15/13
 * Time: 10:45 PM
 */
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.servlet.WindowsPrincipal;

import java.io.IOException;

/**
 * A authentication filter that implements the HTTP Negotiate mechanism. The
 * user is authenticated using his Kerberos credentials, providing
 * single-sign-on
 *
 * @author Tarjei Skorgenes
 * @since 1.0.0
 */
public class NegotiateAuthenticationFilter extends AuthenticatingFilter
        implements Initializable
{


    /** copied from NegotiateSecurityFilter. */
    private static final String PRINCIPAL_SESSION_KEY = NegotiateSecurityFilter.class
            .getName() + ".PRINCIPAL";

    private final NegotiateSecurityFilter waffleNegotiateFilter;


    public NegotiateAuthenticationFilter() {
        //negotiate = new NegotiateSecurityFilterProvider(new WindowsAuthProviderImpl());
        waffleNegotiateFilter = new NegotiateSecurityFilter();
    }


    /**
     * Initializes this object.
     *
     * @throws org.apache.shiro.ShiroException
     *          if an exception occurs during initialization.
     */
    @Override
    public void init() throws ShiroException {
        // @todo this is never called. Seems Initializable.init() should be called for Filter sub class at some point.
        try {
            waffleNegotiateFilter.init(getFilterConfig());
        } catch (ServletException e) {
            throw new ShiroException(e);
        }
    }

    /**
     * Template method to be overridden by subclasses to perform initialization logic at start-up.  The
     * {@code ServletContext} and {@code FilterConfig} will be accessible
     * (and non-{@code null}) at the time this method is invoked via the
     * {@link #getServletContext() getServletContext()} and {@link #getFilterConfig() getFilterConfig()}
     * methods respectively.
     * <p/>
     * {@code init-param} values may be conveniently obtained via the {@link #getInitParam(String)} method.
     *
     * @throws Exception if the subclass has an error upon initialization.
     */
    @Override
    protected void onFilterConfigSet() throws Exception {
        waffleNegotiateFilter.init(getFilterConfig());
    }



    @Override
    protected AuthenticationToken createToken(final ServletRequest in,
                                              final ServletResponse out) throws Exception {
        final String authorization = getAuthzHeader(in);
        final String[] elements = authorization.split(" ");
        final byte[] inToken = Base64.decode(elements[1]);
        final NegotiateToken negotiateToken = new NegotiateToken(inToken, new byte[0]);

        // add objects obtained from filter negotiation.
        // @todo Maybe these negotiations should be done later/elsewhere, perhaps in com.danrollo.negotiate.waffle.NegotiateAuthenticationRealm.doGetAuthenticationInfo()?
        // However, that would require duplication of a lot of logic that currently exists in the Waffle filter: waffle.servlet.NegotiateSecurityFilter.doFilter()
        final org.apache.shiro.subject.Subject currentUser = SecurityUtils.getSubject();
        final Session session = currentUser.getSession(false);
        final javax.security.auth.Subject subject
                = (javax.security.auth.Subject) session.getAttribute("javax.security.auth.subject");
        negotiateToken.setSubject(subject);

        final Object windowsPrincipal = ((HttpServletRequest)in).getSession().getAttribute(PRINCIPAL_SESSION_KEY);
        negotiateToken.setPrincipal(windowsPrincipal);

        return negotiateToken;
    }


    @Override
    protected boolean onLoginSuccess(AuthenticationToken token,
                                     Subject subject, ServletRequest request, ServletResponse response)
            throws Exception {

//        NegotiateToken t = (NegotiateToken) token;

//        byte[] out = t.getOut();
//        if (out != null && out.length > 0) {
//            sendAuthenticateHeader(out, WebUtils.toHttp(response));
//        }

//        request.setAttribute("MY_SUBJECT", t.getSubject());
        return true;
    }

/*
    @Override
    protected boolean onLoginFailure(final AuthenticationToken token,
                                     final AuthenticationException e, final ServletRequest request,
                                     final ServletResponse response) {
        final NegotiateToken t = (NegotiateToken) token;
        sendChallenge(request, response, t.getOut());
        return false;
    }
//*/



    /**
     * Used for stub filterChain to know when waffle filter made a call to FilterChain.doFilter().
     */
    private final class SignalFilterChain implements FilterChain {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        }

    }

    @Override
    protected boolean onAccessDenied(final ServletRequest request,
                                     final ServletResponse response) throws Exception {
        boolean loggedIn = false; // false by default or we wouldn't be in
        // this method
        //if (isLoginAttempt(request, response)) {
        // @todo Maybe these negotiations should be done later/elsewhere? see: javadoc for NegotiateAuthenticationFilter.tryLogin()
        if (tryLogin(request, response)) {
            loggedIn = executeLogin(request, response);
        }
//        if (!loggedIn) {
//            sendChallenge(request, response, null);
//        }
        return loggedIn;
    }

    /**
     * Maybe these negotiations should be done later/elsewhere, perhaps in
     * {@link com.danrollo.negotiate.waffle.NegotiateAuthenticationRealm#doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken) NegotiateAuthenticationRealm.doGetAuthenticationInfo()}?
     * However, that would require duplication of a lot of logic that currently exists in the Waffle tomcat filter:
     * {@link waffle.servlet.NegotiateSecurityFilter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain) NegotiateSecurityFilter.doFilter()}.
     *
     * @param request from javax.servlet
     * @param response from javax.servlet
     * @return true if login succeeded
     * @throws Exception when something broke
     */
    private boolean tryLogin(final ServletRequest request, final ServletResponse response) throws Exception {

        // @todo find a better place/call to do "init" suff
        if (waffleNegotiateFilter.getProviders() == null) {
            waffleNegotiateFilter.init(getFilterConfig());
        }

        // @todo reuse as much as possible of NegotiateSecurityFilter.doFilterPrincipal(), and/or call isAccessAllowed() instead
        final HttpSession existingSession = ((HttpServletRequest)request).getSession(false);
        if (existingSession != null) {
            final WindowsPrincipal windowsPrincipal = (WindowsPrincipal) existingSession.getAttribute(PRINCIPAL_SESSION_KEY);
            if (windowsPrincipal != null) {
                // we already authenticated...
                return true;
            }
        }

        final SignalFilterChain signalFilterChain = new SignalFilterChain();
        waffleNegotiateFilter.doFilter(request, response, signalFilterChain);


        final org.apache.shiro.subject.Subject currentUser = SecurityUtils.getSubject();

        final Session session = currentUser.getSession(false);
        if (session == null) {
            return false;
        }

        final javax.security.auth.Subject subject
                = (javax.security.auth.Subject) session.getAttribute("javax.security.auth.subject");
        if (subject == null) {
            return false;
        }
        return true;
    }


    /**
     * Returns the {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER} from the
     * specified ServletRequest.
     * <p/>
     * This implementation merely casts the request to an
     * <code>HttpServletRequest</code> and returns the header:
     * <p/>
     * <code>HttpServletRequest httpRequest = {@link WebUtils#toHttp(javax.servlet.ServletRequest) toHttp(reaquest)};<br/>
     * return httpRequest.getHeader({@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER});</code>
     *
     * @param request
     *            the incoming <code>ServletRequest</code>
     * @return the <code>Authorization</code> header's value.
     */
    String getAuthzHeader(final ServletRequest request) {
        final HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader("Authorization");
    }

}