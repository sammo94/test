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
	String optxnid = (String) request.getAttribute("optxn");
	String merchant = (String) request.getAttribute("header");
	String footer = (String) request.getAttribute("footer");
	String hcolor = (String) request.getAttribute("hcolor");
	String desc1 = (String) request.getAttribute("desc1");
	String desc2 = (String) request.getAttribute("desc2");
	String imgsrc = (String) request.getAttribute("imgurl");
	String imgstr = (String) request.getAttribute("imgstr");
%>

<script>
$(document).ready(function(){
	sessiontout();
});
</script>
<script>
function sessiontout()
{
 var count = '<%=request.getAttribute("t")%>';
		var counter = count * 60;
		myVar = setInterval(
				function() {
					if (counter == 0) {	
						window.location = "https://" + "<%=request.getAttribute("domain")%>" + "/Ashield/sessTOut?txn=" + optxnid.value;						
					} else if (counter%10 == 0) {						
						var ursl1 = "https://" + "<%=request.getAttribute("domain")%>" + "/Ashield/readTxn";						
						$.post(ursl1,
						{
							rtxnid: optxnid.value
						},
						function(resp) {
							if(resp.trim() == "AS201") {
								window.location = "https://" + "<%=request.getAttribute("domain")%>" + "/Ashield/sessTOut?txn=" + optxnid.value;	
								exit;
							}
						});
					}
					counter--;
				}, 1000)
}
</script>

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
	background:<%=hcolor%>;
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
 	background: <%=hcolor%>;
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
	background:<%=hcolor%>;
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
 	background: <%=hcolor%>;
 	color: white;
 	font-size: 15px;
}
</style>

<title>WEB Auth Response</title>
</head>
<body class="body">
	<input type="hidden" name="cgtrxId" id="optxnid" value="<%=optxnid%>" />
	
	<div class="w3-container" align="center">
			<div class="header">
				<div align="center"><b><%=merchant%></b></div>
			</div>
			<div class="w3-container"
				style="margin-top: 30px; font-family: arial;" align="center">
				<p><font size="4"><strong> <%=desc1%></strong></p>
			</div>
						
			<div style="margin-top:30px; background-color: #e60000; color:#ffffff; font-family: arial;" align="center">
				<p><font size="4"><strong> <%=desc2%></strong></p>
			</div>
			
					
			<div id="i" align=center style="margin-top:30px;">
			<img src="data:image/png;base64,<%=imgstr%>" width="250" height="450">		
			</div>			
			
			<footer class="w3-container">			  
    		  <div class="footerb" align="center"><%=footer%></div>
			</footer>
	</div>
</body>



</html>
