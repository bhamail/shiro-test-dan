<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>

<%@ page import="com.danrollo.stuff.SomeSerializableObject" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>

<%! String nn( Object obj ) { return obj != null? obj.toString(): ""; } %>

<html>
<body>
<h2>Hello World!</h2>

<h1>Hello principal: <shiro:principal />. </h1>

<%
    final String attributeName = "MyThingStoredInASession";
    final Object mySessionAttr = session.getAttribute( attributeName );

    final Map<String, String> myMap = (Map<String, String>) session.getAttribute( "MyMap" );
    final String mapString;
    if (mySessionAttr == null) {
        final Object serObj = new SomeSerializableObject("FromOne");
        session.setAttribute(attributeName, serObj);

        final Map<String, Object> newMap = new HashMap<String, Object>();
        newMap.put("origin", "FromOne");

        newMap.put("serObj", serObj);

        session.setAttribute("MyMap", newMap);
        mapString = newMap.toString();
    } else {
        ((SomeSerializableObject) mySessionAttr).increment();
        mapString = myMap.toString();
    }
%>
<%=nn(attributeName)%> = <%=nn(mySessionAttr)%>
</p>
MyMap = <%=nn(myMap)%>
</p>
MyMap id: = <%=mapString%>

</p>

<a href="logout">Logout</a>

</body>
</html>
