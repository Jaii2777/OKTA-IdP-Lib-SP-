<%@ page import="java.io.*,java.util.*,java.sql.*"%>
<%@ page import="javax.servlet.http.*,javax.servlet.*"%>
<%@ page session="false"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
	<center>
	<h1>Library IdP Login</h1>
	 <form name="loginForm" id="form-id" method="post" action="validateUser">
		 	<input type="text" name="samlRequestId" value="${SAMLRequest}" style="display:block">
		 	<input type="text" name="relayState" value="${RelayState}" style="display:block">
            <p>User your mailId: <input type="text" id="u_id" name="mailId" /></p>
            <p>Password: <input type="password" id="password-id" name="password"/></p>
			<p><input type="submit" value="submit" /></p>
        </form>
		</center>
</body>
</html>