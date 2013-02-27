<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<html>
<body>
<h2>Hello World2!</h2>

<h1>2 Hello, remote user <b><%= request.getRemoteUser() %></b>
    <%--, principal: <shiro:principal />. --%>
</h1>

<br>in session <b><%= session.getId() %></b>.<br>

<a href="logout">Logout</a>

</body>
</html>
