package com.danrollo.negotiate.waffle;

/**
 * Derived from net.skorgenes.security.jsecurity.negotiate.NegotiateAuthenticationFilter.
 *
 * @author Dan Rollo
 * Date: 1/16/13
 * Time: 12:25 AM
 */
import org.apache.shiro.authc.AuthenticationException;

/**
 * Thrown when the negotiate authentication is being established and requires an extra
 * roundtrip to the client.
 *
 * @author Dan Rollo
 * @since 1.0.0
 */
public class AuthenticationInProgressException extends AuthenticationException {
    private static final long serialVersionUID = 2684886728102100988L;
}