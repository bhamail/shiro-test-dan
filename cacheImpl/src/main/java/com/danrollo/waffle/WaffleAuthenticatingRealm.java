package com.danrollo.waffle;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

public class WaffleAuthenticatingRealm extends AuthenticatingRealm {
  static final Logger log = LoggerFactory.getLogger(WaffleAuthenticatingRealm.class);

  final IWindowsAuthProvider prov = new WindowsAuthProviderImpl();
//  final WindowsRealmSettings settings;

//  public WaffleAuthenticatingRealm(WindowsRealmSettings settings) {
  public WaffleAuthenticatingRealm() {
//    this.settings = settings;
  }

  /**
   * Accept a few kinds of tokens
   */
  @Override
  public boolean supports(AuthenticationToken token) {
    if(token!=null) {
      if(token instanceof UsernamePasswordToken) return true;
//      if(token instanceof IWindowsIdentityToken) return true;
    }
    return false;
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

    IWindowsIdentity identity = null;
//    if(token instanceof IWindowsIdentityToken) {
//      identity = ((IWindowsIdentityToken)token).getPrincipal();
      if(identity==null) {
        throw new AuthenticationException();
      }
//    }
    else if(token instanceof UsernamePasswordToken) {
      try {
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;
        identity = prov.logonUser(upToken.getUsername(), 
            String.valueOf(upToken.getPassword()));
      }
      catch(Throwable t) {
        String msg = t.getMessage();
        if(msg != null && msg.indexOf("Logon") >= 0) {
          throw new AuthenticationException(msg);
        }
        else {
          throw new AuthenticationException(t);
        }
      }
    }
    

    IWindowsAccount[] groups = identity.getGroups();
    List<String> ids = new ArrayList<String>(groups.length);
    for(IWindowsAccount a : groups) {
      ids.add( a.getSidString() );
    }

/*
    WindowsUserPrincipal p = new WindowsUserPrincipal(
        identity.getFqn(), 
        identity.getSidString(), 
        ids);
    
    return new SimpleAuthenticationInfo(p, token.getCredentials(), getName());
*/
      return null;
  }
}
