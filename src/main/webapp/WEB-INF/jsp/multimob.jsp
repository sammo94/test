<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>

<script src="js/jquery-1.9.1.min.js"></script>
<script src="js/gv-2.0.min.js"></script>
<script src="js/disableFunctionalKeys.js"></script>
<script src="js/aes.js"></script>
<script src="js/pbkdf2.js"></script>

<script>

$(document).ready(function() {
	sessiontout();
	$("#aSecureImgId").bind('click', function(ev) {
		
		var copyText = document.getElementById("phone").value;
		
		if(copyText == "") {			
			copyText = "0";
		} else if (! /^[0-9]{10}$/.test(copyText)) {
			alert("Please enter valid  number!");
			document.getElementById('phone').value = ''
			document.getElementById('phone').focus();
			return false;
		}
		
		var $div = $(ev.target);
		var optxn = $("#optxnid").val();
		var captchaFlag = $("#captchaFlag").val();
		var jSecureDiv = $('#aSecureImgId');
		var offset = $div.offset();
		var bottom = jSecureDiv.offset().top + jSecureDiv.height();
		var x = ev.pageX - offset.left;
		var y = ev.pageY - offset.top;
		$("#xparamate").val(Math.round(x));
		$("#yparamate").val(Math.round(y));
		var param5 = gv(optxn, Math.round(x), Math.round(y));

		$("#param5").val(param5);
		$('#aSecureImgId').off('click');
		$("#jsec").css("background-color", "white");
		$("#share1").attr("src", "");
		$("#share2").attr("src", "");
		$("div.toshow").css("color", "red");
		$("div.toshow").css('font-weight', 'bold');
		$("div.toshow").show();
		
		var iv = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
        var salt = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
        var key = CryptoJS.PBKDF2(optxn,CryptoJS.enc.Hex.parse(salt),{keySize: 128/32, iterations: 100});
        var str= encodeURIComponent(copyText+"*"+navigator.platform+"*"+screen.width+"-"+screen.height+"*"+navigator.userAgent);
        var encrypted = CryptoJS.AES.encrypt(str,key,{ iv: CryptoJS.enc.Hex.parse(iv) });
        ciphertext = encrypted.ciphertext.toString(CryptoJS.enc.Base64);       
        var en = (iv+"::"+salt+"::"+encodeURIComponent(ciphertext));
        $("#mdnum").val(en);
        		
		document.getElementById("mdnform").submit();
	});
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
						window.location = "https://" + "<%=request.getAttribute("domain")%>" + "/Ashield/timeOut?txn=" + optxnid.value;
					}
					counter--;
				}, 1000)
	}
</script>

<% 
	String optxnid = (String) request.getAttribute("optxn");
	String img1 = (String) request.getAttribute("img1");
	String img2 = (String) request.getAttribute("img2");
	String merchant = (String) request.getAttribute("header");
	String footer = (String) request.getAttribute("footer");
	String hcolor = (String) request.getAttribute("hcolor");
	String desc1 = (String) request.getAttribute("desc1");
	String desc2 = (String) request.getAttribute("desc2");
	String imgsrc = (String) request.getAttribute("imgurl");
	String avtimgsrc = (String) request.getAttribute("avtimgurl");
	String mertxnid =  (String) request.getAttribute("meroptxn");
	String imgstr = (String) request.getAttribute("imgstr");
%>

<style type="text/css">
body {
	font-family: Arial, Helvetica, sans-serif;
	margin:0;
	padding:0;
	width:100%;
}

#form {
	border: 3px solid #f1f1f1;
}

input[type=text], input[type=password], input[type=tel] {
	width: 50%;
	padding: 12px 20px;
	margin: 8px 0;
	display: inline-block;
	border: 1px solid #ccc;
	box-sizing: border-box;
}

.button {
	background-color: #4CAF50;
	color: white;
	padding: 14px 20px 20px 20px;
	margin: 8px 0;
	border: none;
	cursor: pointer;
	width: 30%;
}

.imgcontainer {
	text-align: center;
	margin: 24px 0 12px 0;
}

img.avatar {
	width: 120px;
	height: 120px;
}

.jSecureOverlay {
	position: absolute;
}

#aSecureImgContainer {
	position: relative;
	text-align: center;
}

#aSecureImgContainer img {
	position: absolute;
	margin: auto;
	top: 0;
	left: 0;
	right: 0;
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
 	background: #33ddbf;
 	color: white;
 	font-size: 15px;
}
</style>

<meta content="application/xhtml+xml; charset=ISO-8859-1"
	http-equiv="Content-Type" />

<meta name="viewport" content="width=device-width,minimum-scale=1.0">

<title>WEB Auth Response</title>
</head>

<body>
	<div class="w3-container" align="center">
		<div class="header">
				<div align="center"><b><%=merchant%></b></div>
		</div>
		<div>
			<img src="data:image/png;base64,<%=imgstr%>"  alt=" " width="100" height="100">
		</div>
		<div class="container" align="center">
			<p><strong><%=desc1%> </strong></p>
		</div>		
		<%if(desc2 != null) { %>
		<div class="container" align="center">
			<p><strong><%=desc2%> </strong></p><br>
		</div>
		<%} %>
		<div class="container" align="center">
			<input type="tel" id="phone" name="phone" placeholder=" "
				pattern="[0-9]{10}"  maxlength="10" required autocomplete="off"
				style="-webkit-border-radius: 5px; -moz-border-radius: 5px;
				border-radius: 5px; width:300px; height:30px; padding: 12px 20px;
				margin: 8px 0;box-sizing: border-box;border: 2px solid black;"><br>
		</div>

		<table id="jsec" style="width: 240px; height: 120px; margin-top: 30px;">
			<tr align="left">
				<td align="center" valign="top" width="100%" style="text-align: center;">
				<input type="hidden" name="cgtrxId" id="optxnid" value="<%=optxnid%>" />
					<div id="aSecureImgId" align="center">
						<div id="aSecureImgContainer" align="center">
							<div class="toshow"	style="display: none; font-family =arial; 
							font-align =center; margin-top: 30px">Please Wait...</div>
							<canvas id="usertapp" height="120px" width="240px"></canvas>
							<img src="data:image/png;base64,<%=img1%>" id="share1" class="jSecureOverlay">
							<img src="data:image/png;base64,<%=img2%>" id="share2" class="jSecureOverlay">
						</div>
					</div> <br>
		</table>

		<form name="mdnform" id="mdnform" action="/Ashield/sendsms"
			method="post">
			<input type="hidden" name=param5 id="param5" /> 
			<input type="hidden" name="mdnum" id="mdnum" />
			<input type="hidden" name="txnid" value="<%=optxnid%>" />
			<input type="hidden" name="mertxnid" value="<%=mertxnid%>" />
		</form>
		
		
			<footer class="w3-container">			  
    		  <div class="footerb" align="center"><%=footer%></div>
			</footer>
	</div>
</body>
</html>
