package com.danrollo.negotiate.waffle;


import junit.framework.TestCase;

/**
 * @author Dan Rollo
 * Date: 2/14/13
 * Time: 11:11 PM
 */
public final class NegotiateAuthenticationFilterTest extends TestCase {

    private NegotiateAuthenticationFilter negAuthFilter;


    protected void setUp() {
        negAuthFilter = new NegotiateAuthenticationFilter();
    }

    public void testIsLoginAttempt()  {
        assertFalse(negAuthFilter.isLoginAttempt(""));
        assertTrue(negAuthFilter.isLoginAttempt("NEGOTIATe"));
        //assertTrue(negAuthFilter.isLoginAttempt("ntlm"));
    }
}
