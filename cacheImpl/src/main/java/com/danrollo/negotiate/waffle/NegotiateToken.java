package com.danrollo.negotiate.waffle;

/**
 * Derived from net.skorgenes.security.jsecurity.negotiate.NegotiateToken.
 * see: https://bitbucket.org/lothor/shiro-negotiate/src/7b25efde130b9cbcacf579b3f926c532d919aa23/src/main/java/net/skorgenes/security/jsecurity/negotiate/NegotiateAuthenticationFilter.java?at=default
 *
 * @author Dan Rollo
 * Date: 1/15/13
 * Time: 10:54 PM
 */
import javax.security.auth.Subject;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import waffle.servlet.WindowsPrincipal;


/**
 * An authentication token wrapping a GSSAPI Negotiate token.
 *
 * @author Tarjei Skorgenes
 * @since 1.0.0
 */
public class NegotiateToken implements AuthenticationToken {
    private static final long serialVersionUID = 1345343228636916781L;

    private final byte[] in;

    private byte[] out;

    private Subject subject;


    private Object principal;


    public NegotiateToken(final byte[] in, final byte[] out) {
        this.in = in;
        this.out = out;
    }

    public Object getCredentials() {
        return subject;
    }

    public Object getPrincipal() {
        return principal;
    }

    byte[] getOut() {
        return out;
    }

    public void setOut(final byte[] outToken) {
        this.out = (outToken != null ? outToken.clone() : null);
    }

    public void setSubject(final Subject subject) {
        this.subject = subject;
    }

    public byte[] getIn() {
        return in.clone();
    }

    public Subject getSubject() {
        return subject;
    }

    public AuthenticationInfo createInfo() {
        //return new NegotiateInfo(subject, "NegotiateRealm");
        return new NegotiateInfo(subject, "NegotiateWaffleRealm");
    }


    public void setPrincipal(final Object principal) {
        this.principal = principal;
    }
}