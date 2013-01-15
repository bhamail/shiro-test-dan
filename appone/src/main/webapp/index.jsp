<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<html>
<body>
<h2>Hello World!</h2>

<h1>Hello principal: <shiro:principal />, user: <shiro:user />. </h1>
<a href="logout">Logout</a>

<br>
remote user <b><%= request.getRemoteUser() %></b>, principal: <b><%= request.getUserPrincipal() %></b> in session <b><%= session.getId() %></b>.<br>

</body>
</html>
