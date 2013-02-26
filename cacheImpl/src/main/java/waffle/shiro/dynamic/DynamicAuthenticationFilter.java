package waffle.shiro.dynamic;

import com.danrollo.negotiate.waffle.NegotiateAuthenticationFilter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * @author Dan Rollo
 * Date: 2/21/13
 * Time: 9:08 PM
 */
public class DynamicAuthenticationFilter extends FormAuthenticationFilter {

    private static final Logger log = LoggerFactory.getLogger(DynamicAuthenticationFilter.class);


    public static final String PARAM_NAME_AUTHTYPE = "authType";
    public static final String PARAM_VAL_AUTHTYPE_NEGOTIATE = "j_negotiate";

    private static final class WrapNegotiateAuthenticationFilter extends NegotiateAuthenticationFilter {

        private final DynamicAuthenticationFilter parent;

        private WrapNegotiateAuthenticationFilter(final DynamicAuthenticationFilter parent) {
            this.parent = parent;
        }

        @Override
        public boolean onAccessDenied(final ServletRequest request,
                                      final ServletResponse response) throws Exception {

            return super.onAccessDenied(request, response);
        }

        @Override
        public AuthenticationToken createToken(final ServletRequest request, final ServletResponse response) {
            return super.createToken(request, response);
        }

        @Override
        protected boolean onLoginSuccess(final AuthenticationToken token,
                                         final Subject subject, final ServletRequest request, final ServletResponse response) throws Exception {
            return parent.onLoginSuccess(token, subject, request, response);
        }
    }
    private final WrapNegotiateAuthenticationFilter filterNegotiate = new WrapNegotiateAuthenticationFilter(this);



    private static final class WrapBasicHttpAuthenticationFilter extends BasicHttpAuthenticationFilter {

        private final DynamicAuthenticationFilter parent;

        private WrapBasicHttpAuthenticationFilter(final DynamicAuthenticationFilter parent) {
            this.parent = parent;
        }

        @Override
        public AuthenticationToken createToken(final ServletRequest request, final ServletResponse response)  {
            return super.createToken(request, response);
        }

        @Override
        public boolean onAccessDenied(final ServletRequest request, final ServletResponse response) throws Exception {
            return super.onAccessDenied(request, response);
        }

        @Override
        protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                         ServletRequest request, ServletResponse response) throws Exception {
            return parent.onLoginSuccess(token, subject, request, response);
        }
    }
    private final WrapBasicHttpAuthenticationFilter filterBasicAuthc = new WrapBasicHttpAuthenticationFilter(this);



    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {

        if (isAuthTypeNegotiate(request)) {
            try {
                return filterNegotiate.createToken(request, response);
            } catch (Exception e) {
                throw new AuthenticationException(e);
            }
        } else {
            return filterBasicAuthc.createToken(request, response);
        }
    }


    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) isAccessAllowed}
     * method.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     *         handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     */
/*    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {

        if (isLoginRequest(request, response)) {
            if (isLoginSubmission(request, response)) {
                if (log.isTraceEnabled()) {
                    log.trace("Login submission detected.  Attempting to execute login.");
                }
                //return executeLogin(request, response);
                if (request.getParameter(PARAM_VAL_AUTHTYPE_NEGOTIATE) != null) {
                    return filterNegotiate.onAccessDenied(request, response);
                } else {
                    return filterBasicAuthc.onAccessDenied(request, response);
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("Login page view.");
                }
                //allow them to see the login page ;)
                return true;
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Attempting to access a path which requires authentication.  Forwarding to the " +
                        "Authentication url [" + getLoginUrl() + "]");
            }

            saveRequestAndRedirectToLogin(request, response);
            return false;
        }

    }
*/
    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        if (isAuthTypeNegotiate(request)) {
            return filterNegotiate.onAccessDenied(request, response);
        } else {
            return filterBasicAuthc.onAccessDenied(request, response);
        }
    }

    private boolean isAuthTypeNegotiate(final ServletRequest request) {
        final String authType = request.getParameter(PARAM_NAME_AUTHTYPE);
        return authType != null && PARAM_VAL_AUTHTYPE_NEGOTIATE.equalsIgnoreCase(authType);
    }

}
