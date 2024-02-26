<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>

<%
	String optxnid = (String) request.getAttribute("optxn");
	String Token = (String) request.getAttribute("token");
	String status = (String) request.getAttribute("status");
%>

<title>WEB Auth Response</title>
</head>
<body class="body">

	<p>Status - <b>is <%=status%></b>.</p>	
	<p>Transaction ID- <b>is <%=optxnid%></b>.</p>	
	<p>Token - <b>is <%=Token%></b>.</p>
	
</body>

</html>
