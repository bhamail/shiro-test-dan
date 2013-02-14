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
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.servlet.WindowsPrincipal;
import waffle.util.AuthorizationHeader;
import waffle.util.NtlmServletRequest;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

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

    /** A space delimited list of waffle security filter provider names. */
    private String securityFilterProviders;


    private NegotiateToken token;  //@todo find better way to signal onAccessDenied when to sendChallenge


    public NegotiateAuthenticationFilter() {
        //negotiate = new NegotiateSecurityFilterProvider(new WindowsAuthProviderImpl());
        //waffleNegotiateFilter = new NegotiateSecurityFilter();
        waffleNegotiateFilter = null;
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
            doWaffleFilterInit();
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
        doWaffleFilterInit();
    }

    private void doWaffleFilterInit() throws ServletException {

        final FilterConfig filterConfig;
        if (getFilterConfig() != null) {
            // @todo test this, make sure ini config is reflected in filterConfig
            filterConfig =  getFilterConfig();
        } else if (securityFilterProviders != null) {
            filterConfig = new FilterConfig() {
                @Override
                public String getFilterName() { return null; }

                @Override
                public ServletContext getServletContext() { return null; }

                @Override
                public String getInitParameter(String name) {
                    if ("securityFilterProviders".equals(name)) {
                        return securityFilterProviders;
                    }
                    return null;
                }

                @Override
                public Enumeration getInitParameterNames() {
                    return Collections.enumeration(Arrays.asList("securityFilterProviders"));
                }
            };
        } else {
            filterConfig = null;
        }
        waffleNegotiateFilter.init(filterConfig);
    }


    @Override
    protected AuthenticationToken createToken(final ServletRequest in,
                                              final ServletResponse out) throws Exception {
        final String authorization = getAuthzHeader(in);
        final String[] elements = authorization.split(" ");
        final byte[] inToken = Base64.decode(elements[1]);

        // maintain a connection-based session for NTLM tokns
        final String connectionId = NtlmServletRequest.getConnectionId((HttpServletRequest)in); // @todo see about changing this parameter to ServletRequest in waffle

/*
        final AuthorizationHeader authorizationHeader = new AuthorizationHeader((HttpServletRequest)in); // @todo see about changing this parameter to ServletRequest in waffle
        final String securityPackage = authorizationHeader.getSecurityPackage();
*/
        final String securityPackage = elements[0];

        //@todo find better way to signal onAccessDenied when to sendChallenge
        return token = new NegotiateToken(inToken, new byte[0], connectionId, securityPackage);
    }


    @Override
    protected boolean onLoginSuccess(final AuthenticationToken token,
                                     final Subject subject, final ServletRequest request, final ServletResponse response)
            throws Exception {

        // clear instance reference to token //@todo find better way to signal onAccessDenied when to sendChallenge
        this.token = null;

        final NegotiateToken t = (NegotiateToken) token;
        final byte[] out = t.getOut();
        if (out != null && out.length > 0) {
            sendAuthenticateHeader(out, WebUtils.toHttp(response));
        }
        request.setAttribute("MY_SUBJECT", t.getSubject());
        return true;
    }

    @Override
    protected boolean onLoginFailure(final AuthenticationToken token,
                                     final AuthenticationException e, final ServletRequest request,
                                     final ServletResponse response) {
        final NegotiateToken t = (NegotiateToken) token;
        sendChallenge(request, response, t.getOut());
        return false;
    }



     @Override
    protected boolean onAccessDenied(final ServletRequest request,
                                     final ServletResponse response) throws Exception {
         boolean loggedIn = false; // false by default or we wouldn't be in
         // this method
         if (isLoginAttempt(request, response)) {
             loggedIn = executeLogin(request, response);
         }
         if (!loggedIn) {
             if (token != null && token.getOut() != null) {  //@todo find better way to signal onAccessDenied when to sendChallenge
                 sendChallenge(request, response, token.getOut());
             } else {
                 sendChallenge(request, response, null);
             }
/*
             final HttpServletResponse httpResponse = WebUtils.toHttp(response);
             httpResponse.setHeader("Connection", "keep-alive");
             httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
             httpResponse.setHeader("WWW-Authenticate", "Negotiate");
             httpResponse.flushBuffer();
*/
         }
         return loggedIn;
    }

    /**
     * Determines whether the incoming request is an attempt to log in.
     * <p/>
     * The default implementation obtains the value of the request's
     * {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#AUTHORIZATION_HEADER AUTHORIZATION_HEADER}, and if it is not
     * <code>null</code>, delegates to {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#isLoginAttempt(String)
     * isLoginAttempt(authzHeaderValue)}. If the header is <code>null</code>,
     * <code>false</code> is returned.
     *
     * @param request
     *            incoming ServletRequest
     * @param response
     *            outgoing ServletResponse
     * @return true if the incoming request is an attempt to log in based, false
     *         otherwise
     */
    protected boolean isLoginAttempt(final ServletRequest request,
                                     final ServletResponse response) {
        final String authzHeader = getAuthzHeader(request);
        return authzHeader != null && isLoginAttempt(authzHeader);
    }



    /**
     * Used for stub filterChain to know when waffle filter made a call to FilterChain.doFilter().
     */
    private final class SignalFilterChain implements FilterChain {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        }

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
            doWaffleFilterInit();
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
        // @todo Dectect error condition and throw exception?

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
     * Returns the {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#AUTHORIZATION_HEADER AUTHORIZATION_HEADER} from the
     * specified ServletRequest.
     * <p/>
     * This implementation merely casts the request to an
     * <code>HttpServletRequest</code> and returns the header:
     * <p/>
     * <code>HttpServletRequest httpRequest = {@link WebUtils#toHttp(javax.servlet.ServletRequest) toHttp(reaquest)};<br/>
     * return httpRequest.getHeader({@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#AUTHORIZATION_HEADER AUTHORIZATION_HEADER});</code>
     *
     * @param request
     *            the incoming <code>ServletRequest</code>
     * @return the <code>Authorization</code> header's value.
     */
    String getAuthzHeader(final ServletRequest request) {
        final HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader("Authorization");
    }

    /**
     * Default implementation that returns <code>true</code> if the specified
     * <code>authzHeader</code> starts with the same (case-insensitive)
     * characters specified by the {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#getAuthzScheme() authzScheme},
     * <code>false</code> otherwise.
     * <p/>
     * That is:
     * <p/>
     * <code>String authzScheme = getAuthzScheme().toLowerCase();<br/>
     * return authzHeader.toLowerCase().startsWith(authzScheme);</code>
     *
     * @param authzHeader
     *            the 'Authorization' header value (guaranteed to be non-null if
     *            the
     *            {@link #isLoginAttempt(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     *            method is not overriden).
     * @return <code>true</code> if the authzHeader value matches that
     *         configured as defined by the {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#getAuthzScheme()
     *         authzScheme}.
     */
    protected boolean isLoginAttempt(final String authzHeader) {
        final String authzScheme = "Negotiate".toLowerCase();
        return authzHeader.toLowerCase().startsWith(authzScheme);
    }

    /**
     * Builds the challenge for authorization by setting a HTTP <code>401</code>
     * (Unauthorized) status as well as the response's
     * {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#AUTHENTICATE_HEADER AUTHENTICATE_HEADER}.
     * <p/>
     * The header value constructed is equal to:
     * <p/>
     * <code>{@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#getAuthcScheme() getAuthcScheme()} + " realm=\"" + {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#getApplicationName() getApplicationName()} + "\"";</code>
     *
     * @param request
     *            incoming ServletRequest, ignored by this implementation
     * @param response
     *            outgoing ServletResponse
     * @param out
     * @return false - this sends the challenge to be sent back
     */
    protected boolean sendChallenge(final ServletRequest request,
                                    final ServletResponse response, final byte[] out) {
        final HttpServletResponse httpResponse = WebUtils.toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        sendAuthenticateHeader(out, httpResponse);
        return false;
    }

    private void sendAuthenticateHeader(final byte[] out,
                                        final HttpServletResponse httpResponse) {
        if (out == null || out.length == 0) {
            httpResponse.setHeader("WWW-Authenticate", "Negotiate");
        } else {
            httpResponse.setHeader("WWW-Authenticate", "Negotiate "
                    + Base64.encodeToString(out));
        }
    }
}