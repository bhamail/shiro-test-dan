package com.danrollo.negotiate.waffle;

/**
 * Created with IntelliJ IDEA.
 * User: dan
 * Date: 1/16/13
 * Time: 12:25 AM
 * To change this template use File | Settings | File Templates.
 */
import org.apache.shiro.authc.AuthenticationException;

import java.io.Serializable;

/**
 * Thrown when the GSSAPI-context is being established and requires an extra
 * roundtrip to the client.
 *
 * @author Tarjei Skorgenes
 * @since 1.0.0
 */
public class AuthenticationInProgressException extends AuthenticationException {
    private static final long serialVersionUID = 2684886728102100988L;
}