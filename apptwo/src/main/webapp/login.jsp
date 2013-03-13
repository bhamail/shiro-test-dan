<%--
    Document   : login.jsp
    Created on : Aug 2, 2012, 4:53:34 PM
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>

<!DOCTYPE html>

<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>JSP Page 2</title>
</head>
<body>

<%--<h1>2 Hello principal: <shiro:principal />. </h1>--%>


<h1>Login 2</h1>
<form method="POST" action="login.jsp">

    Authentication Type: <select name="authType">
        <option value="j_negotiate" ${param.authType == 'j_negotiate' ? 'selected' : ''}>Windows Auth (SSO)</option>
        <option value="userPass" ${param.authType == 'userPass' ? 'selected' : ''}>User/Password</option>
    </select>
    <br/>
    <br/>

    Username: <input type="text" name="username"/> <br/>
    Password: <input type="password" name="password"/> <br />
    <br/>
    <input type="checkbox" name="rememberMe" value="true"/>Remember Me? <br/>
    <br/>
    <input type="submit" name="submit" value="Login" />
</form>
</body>
</html>
