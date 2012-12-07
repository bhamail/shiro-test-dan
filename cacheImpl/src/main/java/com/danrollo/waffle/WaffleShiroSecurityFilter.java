package com.danrollo.waffle;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.subject.WebSubject;
/*
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
*/

import waffle.servlet.spi.NegotiateSecurityFilterProvider;
import waffle.util.AuthorizationHeader;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;


public class WaffleShiroSecurityFilter extends AbstractShiroFilter {
  
  private NegotiateSecurityFilterProvider negotiate = null;
  
  public WaffleShiroSecurityFilter() {
    super();
    
    List<String> protocols = new ArrayList<String>(2);
//    if(r.isEnableNegotiate()) {
      protocols.add("Negotiate");
//    }
//    if(r.isEnableNtlm()) {
      protocols.add("NTLM");
//    }
    negotiate = new NegotiateSecurityFilterProvider(new WindowsAuthProviderImpl());
    negotiate.setProtocols(protocols);
  }

/*
  @Override
  protected WebSecurityManager createDefaultSecurityManager() {
    ApplicationContext context = WebApplicationContextUtils
      .getRequiredWebApplicationContext(getServletContext());
      
    return .....initialize(context);
  }
*/

  //----------------------------------------------------------------------
  
  /**
   * HTTP Authorization header, equal to <code>Authorization</code>
   */
  protected static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String AUTH_SCHEMA_BASIC = HttpServletRequest.BASIC_AUTH.toLowerCase();

  @Override
  protected WebSubject createSubject(ServletRequest request, ServletResponse response) {
    WebSubject subject = super.createSubject(request, response);
    if( subject.getPrincipal() == null ) {
      if( request instanceof HttpServletRequest ) {
        AuthorizationHeader header = new AuthorizationHeader((HttpServletRequest)request);
        if(!header.isNull()) {
          boolean success = false;
          String schema = header.getSecurityPackage().toLowerCase(Locale.US);
          String token = header.getToken();
          if(AUTH_SCHEMA_BASIC.equals(schema)) {
            String decoded = Base64.decodeToString(token);
            int idx = decoded.indexOf(':');
            if( idx > 0 ) {
              String u = decoded.substring(0,idx);
              String p = decoded.substring(idx+1);

              subject.login(new UsernamePasswordToken(u, p, false, request.getRemoteHost()));
            }
          }
          else {
                
                try {
                  IWindowsIdentity identity = negotiate.doFilter(
                      (HttpServletRequest) request,
                      (HttpServletResponse) response);

                  if(identity!=null) {
//                    IWindowsIdentityToken t = new IWindowsIdentityToken(identity, request.getRemoteHost());
                    try {
//                      subject.login(t);
                      success = true;
                    }
                    catch( AuthenticationException ex ) {
                      throw new RuntimeException( ex );
                    }
                  }
                }
                catch(Exception ex) {
//                  log.warn("Error running negotiate filter", ex);
                }
          }
          
          // Logged in -- should we redirect?
          if(success) {
//            String v = ....fetchAndRemoveStashedLocation((HttpServletRequest)request);
            String v = null;
            if(v!=null) {
              HttpServletResponse r = (HttpServletResponse) response;
              try {
                r.sendRedirect(r.encodeRedirectURL(v));
              } 
              catch (IOException e) {
                e.printStackTrace();
              }
            }
          }
        }
      }
    }
    return subject;
  }

}
