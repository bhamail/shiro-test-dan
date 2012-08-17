<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>

<%@ page import="com.danrollo.stuff.SomeSerializableObject" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>

<%! String nn( Object obj ) { return obj != null? obj.toString(): ""; } %>

<html>
<body>
<h2>Hello World2!</h2>

<h1>2 Hello principal: <shiro:principal />. </h1>

<%
    final String attributeName = "MyThingStoredInASession";
    final Object mySessionAttr = session.getAttribute( attributeName );

    final Map<String, String> myMap = (Map<String, String>) session.getAttribute( "MyMap" );

    if (mySessionAttr == null) {
        session.setAttribute(attributeName, new SomeSerializableObject("FromOne"));

        final Map<String, Object> newMap = new HashMap<String, Object>();
        newMap.put("origin", "FromTwo");

        session.setAttribute("MyMap", newMap);
    } else {
        ((SomeSerializableObject) mySessionAttr).increment();
    }
%>
<%=nn(attributeName)%> = <%=nn(mySessionAttr)%>
</p>
MyMap = <%=nn(myMap)%>

</p>

<a href="logout">Logout</a>

</body>
</html>
