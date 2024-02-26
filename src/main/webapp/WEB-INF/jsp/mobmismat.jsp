<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<meta name="description" content="" />
<meta name="keywords" content="" />
<script src="js/jquery-1.9.1.min.js"></script>
<script src="js/gv-2.0.min.js"></script>
<script src="js/disableFunctionalKeys.js"></script>
<script src="js/aes.js"></script>
<script src="js/pbkdf2.js"></script>

<%
	
	String merchant = (String) request.getAttribute("header");
	String footer = (String) request.getAttribute("footer");
	String desc1 = (String) request.getAttribute("desc1");
%>

<style type="text/css">

body {
	font-family: Arial, Helvetica, sans-serif;
	margin:0;
	padding:0;
	width:100%;
}

#header {
	font-size: 18px;
	font-style: bold;
	font-valign: center;
	font-family: Arial, Helvetica, sans-serif;
	color: #FFFFFF;
	border-bottom:5px solid #FFFFFF;
	background:#e60000;
    left: 0;
    width: 100%;
    top: 0;
    height:30px;
    position: absolute;
    padding:2px 0 2px 0;
}

.header {
	padding: 10px;
 	text-align: center;
 	background: #e60000;
 	color: white;
 	font-size: 18px;
}

#price {
	margin-left: 0px;
	font-style: bold;
	font-align: center;
}

.footerb{
	border-top:1px solid #565656;
	background:#e60000;
	font-size:15px;
	font-family: Arial, Helvetica, sans-serif;
	margin:1px 0 0 0;
	position: fixed;
    left: 0;
    bottom: 0;
    height: auto;
    width: 100%;
    color: #FFFFFF;
}
#footerb{
	padding: 4px;
 	text-align: center;
 	background: #e60000;
 	color: white;
 	font-size: 15px;
}
</style>

<title>WEB Auth Response</title>
</head>
<body class="body">
	
	<div class="w3-container" align="center">
			<div class="header">
				<div align="center"><b><%=merchant%></b></div>
			</div>
			<div class="w3-container"
				style="margin-top: 30px; font-family: arial;" align="center">
				<p><font size="4"><strong> <%=desc1%></strong></p>
			</div>
						
			<footer class="w3-container">			  
    		  <div class="footerb" align="center"><%=footer%></div>
			</footer>
	</div>
</body>



</html>
