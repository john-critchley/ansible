<%@ page contentType="application/json" %>
<%
    String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "anonymous";
    out.print("{\"status\":\"ok\",\"user\":\"" + user + "\",\"auth\":\"bearer-jwt\"}");
%>
