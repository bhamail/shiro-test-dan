<%@ page import="javax.security.auth.Subject" %>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<html>
<body>
<h2>Hello World!</h2>


<%--<h1>Hello principal: <shiro:principal />, user: <shiro:user />. </h1>--%>

remote user <b><%= request.getRemoteUser() %></b>
<%--, principal name: <b><%= request.getUserPrincipal().getName() %></b>--%>
<%--, Subject: <b><%= request.getSession().getAttribute("javax.security.auth.subject") %></b>--%>
<br>in session <b><%= session.getId() %></b>.<br>

<a href="logout">Logout</a><br>

</body>
</html>
