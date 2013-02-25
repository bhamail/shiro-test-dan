package com.danrollo.negotiate.waffle;

/**
 * Derived from net.skorgenes.security.jsecurity.negotiate.NegotiateAuthenticationFilter.
 * see: https://bitbucket.org/lothor/shiro-negotiate/src/7b25efde130b9cbcacf579b3f926c532d919aa23/src/main/java/net/skorgenes/security/jsecurity/negotiate/NegotiateAuthenticationFilter.java?at=default
 *
 * @author Dan Rollo
 * Date: 1/15/13
 * Time: 10:45 PM
 */
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import waffle.util.AuthorizationHeader;
import waffle.util.NtlmServletRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A authentication filter that implements the HTTP Negotiate mechanism. The
 * current user is authenticated, providing single-sign-on
 *
 * @author Dan Rollo
 * @since 1.0.0
 */
public class NegotiateAuthenticationFilter extends AuthenticatingFilter
{

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(NegotiateAuthenticationFilter.class);


    private final List<String> protocols = new ArrayList<String>();
    {
        protocols.add("Negotiate");
        protocols.add("NTLM"); //@todo things (sometimes) break, depending on what user account is running tomcat:
                               // related to setSPN and running tomcat server as NT Service account vs. as normal user account.
                               // http://waffle.codeplex.com/discussions/254748
                               // setspn -A HTTP/<server-fqdn> <user_tomcat_running_under>
    }


    @Override
    protected AuthenticationToken createToken(final ServletRequest in,
                                              final ServletResponse out)  {
        final String authorization = getAuthzHeader(in);
        final String[] elements = authorization.split(" ");
        final byte[] inToken = Base64.decode(elements[1]);

        // maintain a connection-based session for NTLM tokns
        final String connectionId = NtlmServletRequest.getConnectionId((HttpServletRequest)in); // @todo see about changing this parameter to ServletRequest in waffle
        final String securityPackage = elements[0];

        final AuthorizationHeader authorizationHeader = new AuthorizationHeader((HttpServletRequest)in); // @todo see about changing this parameter to ServletRequest in waffle
        final boolean ntlmPost = authorizationHeader.isNtlmType1PostAuthorizationHeader();

        log.debug("security package: " + securityPackage + ", connection id: " + connectionId + ", ntlmPost: " + ntlmPost);

        return new NegotiateToken(inToken, new byte[0], connectionId, securityPackage, ntlmPost);
    }


    @Override
    protected boolean onLoginSuccess(final AuthenticationToken token,
                                     final Subject subject, final ServletRequest request, final ServletResponse response)
            throws Exception {

        final NegotiateToken t = (NegotiateToken) token;

        request.setAttribute("MY_SUBJECT", t.getSubject());
        return true;
    }

    @Override
    protected boolean onLoginFailure(final AuthenticationToken token,
                                     final AuthenticationException e, final ServletRequest request,
                                     final ServletResponse response) {
        final NegotiateToken t = (NegotiateToken) token;

        if (e instanceof AuthenticationInProgressException) {
            // negotiate is processing
            sendChallenge(response, t.getOut());
        } else {
            log.warn("login exception: " + e.getMessage());

            final HttpServletResponse httpResponse = WebUtils.toHttp(response);

            // do not send token.out bytes, this was a login failure.
            sendUnauthorized(null, httpResponse);

            httpResponse.setHeader("Connection", "close");
            try {
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                httpResponse.flushBuffer();
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
        }
        return false;
    }



    @Override
    protected boolean onAccessDenied(final ServletRequest request,
                                     final ServletResponse response) throws Exception {
         boolean loggedIn = false; // false by default or we wouldn't be in
         // this method
         if (isLoginAttempt(request)) {
             loggedIn = executeLogin(request, response);
         } else {
             log.debug("authorization required");
             sendChallenge(response, null);
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
     * @return true if the incoming request is an attempt to log in based, false
     *         otherwise
     */
    boolean isLoginAttempt(final ServletRequest request) {
        final String authzHeader = getAuthzHeader(request);
        return authzHeader != null && isLoginAttempt(authzHeader);
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
     * characters specified by any of the configured protocols (Negotiate or NTLM),
     * <code>false</code> otherwise.
     *
     * @param authzHeader
     *            the 'Authorization' header value (guaranteed to be non-null if
     *            the
     *            {@link #isLoginAttempt(javax.servlet.ServletRequest)}
     *            method is not overriden).
     * @return <code>true</code> if the authzHeader value matches any of the configured protocols (Negotiate or NTLM).
     */
    boolean isLoginAttempt(final String authzHeader) {
        for (final String protocol : protocols) {
            if (authzHeader.toLowerCase().startsWith(protocol.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the challenge for authorization by setting a HTTP <code>401</code>
     * (Unauthorized) status as well as the response's
     * {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#AUTHENTICATE_HEADER AUTHENTICATE_HEADER}.
     *
     * @param response
     *            outgoing ServletResponse
     * @param out
     *            token.out or null
     */
    void sendChallenge(final ServletResponse response, final byte[] out) {
        final HttpServletResponse httpResponse = WebUtils.toHttp(response);
        sendAuthenticateHeader(out, httpResponse);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void sendAuthenticateHeader(final byte[] out,
                                        final HttpServletResponse httpResponse) {

        sendUnauthorized(out, httpResponse);

        httpResponse.setHeader("Connection", "keep-alive");
    }

    private void sendUnauthorized(final byte[] out, final HttpServletResponse response) {
        for (final String protocol : protocols) {
            if (out == null || out.length == 0) {
                response.addHeader("WWW-Authenticate", protocol);
            } else {
                response.setHeader("WWW-Authenticate", protocol + " " + Base64.encodeToString(out));
            }
        }
    }

}