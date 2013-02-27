package waffle.shiro.dynamic;

import waffle.shiro.negotiate.NegotiateAuthenticationFilter;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
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
        protected boolean onLoginSuccess(final AuthenticationToken token,
                                         final Subject subject, final ServletRequest request, final ServletResponse response) throws Exception {
            return parent.onLoginSuccess(token, subject, request, response);
        }
    }
    private final WrapNegotiateAuthenticationFilter filterNegotiate = new WrapNegotiateAuthenticationFilter(this);



    private static final class WrapFormAuthenticationFilter extends FormAuthenticationFilter {

        private final DynamicAuthenticationFilter parent;

        private WrapFormAuthenticationFilter(final DynamicAuthenticationFilter parent) {
            this.parent = parent;
        }

        @Override
        public boolean onAccessDenied(final ServletRequest request, final ServletResponse response) throws Exception {
            return super.onAccessDenied(request, response);
        }

        @Override
        protected boolean onLoginSuccess(final AuthenticationToken token, final Subject subject,
                                         final ServletRequest request, final ServletResponse response) throws Exception {
            return parent.onLoginSuccess(token, subject, request, response);
        }
    }
    private final WrapFormAuthenticationFilter filterFormAuthc = new WrapFormAuthenticationFilter(this);



    @Override
    protected boolean executeLogin(final ServletRequest request, final ServletResponse response) throws Exception {
        if (isAuthTypeNegotiate(request)) {
            log.debug("using filterNegotiate");
            return filterNegotiate.onAccessDenied(request, response);
        } else {
            log.debug("using filterFormAuthc");
            return filterFormAuthc.onAccessDenied(request, response);
        }
    }

    boolean isAuthTypeNegotiate(final ServletRequest request) {
        final String authType = request.getParameter(PARAM_NAME_AUTHTYPE);
        return authType != null && PARAM_VAL_AUTHTYPE_NEGOTIATE.equalsIgnoreCase(authType);
    }

}
