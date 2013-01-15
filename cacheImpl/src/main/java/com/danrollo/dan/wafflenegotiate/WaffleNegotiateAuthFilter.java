package com.danrollo.dan.wafflenegotiate;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.servlet.WindowsPrincipal;
import waffle.servlet.spi.NegotiateSecurityFilterProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Created with IntelliJ IDEA.
 * User: dan
 * Date: 1/8/13
 * Time: 10:55 PM
 * To change this template use File | Settings | File Templates.
 */
public class WaffleNegotiateAuthFilter extends BasicHttpAuthenticationFilter
                                       implements Initializable
{

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(WaffleNegotiateAuthFilter.class);

    /** copied from NegotiateSecurityFilter. */
    private static final String PRINCIPAL_SESSION_KEY = NegotiateSecurityFilter.class
            .getName() + ".PRINCIPAL";

    //private final NegotiateSecurityFilterProvider negotiate;
    private final NegotiateSecurityFilter negotiateFilter;


    public WaffleNegotiateAuthFilter() {
        //negotiate = new NegotiateSecurityFilterProvider(new WindowsAuthProviderImpl());

        negotiateFilter = new NegotiateSecurityFilter();

        setAuthcScheme("Negotiate"); // @todo ??
    }

    @Override
    public void setFilterConfig(FilterConfig filterConfig) {
        super.setFilterConfig(filterConfig);
        try {
            negotiateFilter.init(getFilterConfig());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void onFilterConfigSet() throws Exception {
        negotiateFilter.init(getFilterConfig());
    }

    /**
     * Initializes this object.
     *
     * @throws org.apache.shiro.ShiroException
     *          if an exception occurs during initialization.
     */
    public void init() throws ShiroException {
        try {
            super.init(getFilterConfig());
        } catch (ServletException e) {
            throw new ShiroException(e);
        }
    }

    /**
         * Used for stub filterChain to know when waffle filter made a call to FilterChain.doFilter().
         */
    final class SignalFilterChain implements FilterChain {
        private boolean wasDoFilterCalled;
        private ServletRequest lastRequest;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            wasDoFilterCalled = true;
            lastRequest = request;
        }

        boolean wasDoFilterCalled() {
            return wasDoFilterCalled;
        }

        ServletRequest getLastRequest() {
            return lastRequest;
        }
    }

    /**
     * Processes unauthenticated requests. It handles the two-stage request/challenge authentication protocol.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return true if the request should be processed; false if the request should not continue to be processed
     */
    @Override
    protected boolean onAccessDenied(final ServletRequest request, final ServletResponse response) throws Exception {
/*
        boolean loggedIn = false; //false by default or we wouldn't be in this method
        if (isLoginAttempt(request, response)) {
            loggedIn = executeLogin(request, response);
        } else if (!loggedIn) {
            sendChallenge(request, response);
        }
        return loggedIn;
*/
        // @todo find a better place/call to do "init" suff
        if (negotiateFilter.getProviders() == null) {
            negotiateFilter.init(getFilterConfig());
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
        negotiateFilter.doFilter(request, response, signalFilterChain);


        final Subject currentUser = SecurityUtils.getSubject();
/*
        if (!currentUser.isAuthenticated()) {
            return false;
        }
*/
        //final HttpSession session = ((HttpServletRequest)request).getSession(false);
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

    @Override
    protected boolean isLoginAttempt(final String authzHeader) {
        final String authzScheme = "Negotiate".toLowerCase();
        return authzHeader.toLowerCase().startsWith(authzScheme);
    }


/*
    @Override
    protected boolean sendChallenge(final ServletRequest request, final ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication required: sending 401 Authentication challenge response.");
        }
        HttpServletResponse httpResponse = WebUtils.toHttp(response);

        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        negotiate.sendUnauthorized(httpResponse);
//        String authcHeader = getAuthcScheme() + ":";
//        httpResponse.setHeader(AUTHENTICATE_HEADER, authcHeader);

        return false;
    }
*/


/*
    @Override
    protected boolean executeLogin(final ServletRequest request, final ServletResponse response) throws Exception {
*/
/*
        AuthenticationToken token = createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                    "must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        }
        try {
            Subject subject = getSubject(request, response);
            subject.login(token);
            return onLoginSuccess(token, subject, request, response);
        } catch (AuthenticationException e) {
            return onLoginFailure(token, e, request, response);
        }
*/

/*
        final HttpServletRequest hrequest = (HttpServletRequest) request;
        final HttpServletResponse hresponse = (HttpServletResponse) response;

        final IWindowsIdentity windowsIdentity = negotiate.doFilter(hrequest, hresponse);
        if (windowsIdentity == null) {
            // continue negotiations
            return false;
        }

        // continue add stuff from NegotiateSecurityFilter.doFilter() , set subject, principals....

        return true;
    }
*/



    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        //final boolean defaultValue = super.isAccessAllowed(request, response, mappedValue);

        // @todo reuse as much as possible of NegotiateSecurityFilter.doFilterPrincipal()
        final HttpSession existingSession = ((HttpServletRequest)request).getSession(false);
        if (existingSession != null) {
            final WindowsPrincipal windowsPrincipal = (WindowsPrincipal) existingSession.getAttribute(PRINCIPAL_SESSION_KEY);
            if (windowsPrincipal != null) {
                // we already authenticated...
                return true;
            }
        }
        return false;
    }

}
