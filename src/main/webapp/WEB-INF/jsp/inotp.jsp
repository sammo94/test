<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="viewport"
	content="width=device-width, initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<meta name="description" content="" />
<meta name="keywords" content="" />
<script src="js/jquery-1.9.1.min.js"></script>
<script src="js/gv-2.0.min.js"></script>
<script src="js/disableFunctionalKeys.js"></script>
<script src="js/aes.js"></script>
<script src="js/pbkdf2.js"></script>
<script>
$(document).ready(function(){
	sessiontout();
	$("#jSecureImgId").bind('click',function(ev){
		
		var msisdn = document.getElementById("txtmdn").value;

		if(msisdn == "") {			
			msisdn = "0";
		} else if (! /^[0-9]{4}$/.test(msisdn)) {
			alert("Please enter valid  Otp!");
			document.getElementById('txtmdn').value = ''
			document.getElementById('txtmdn').focus();
			return false;
		} 

			var $div = $(ev.target); 
			var optxn=$("#optxnid").val();
			var captchaFlag=$("#captchaFlag").val();
			var jSecureDiv = $('#jSecureImgId'); 
			var offset = $div.offset(); 
			var bottom = jSecureDiv.offset().top + jSecureDiv.height(); 
			var x=ev.pageX - offset.left; 
			var y=ev.pageY - offset.top; 
			$("#xparamate").val(Math.round(x));
			$("#yparamate").val(Math.round(y));
			
			var param5=gv(optxn,Math.round(x),Math.round(y));		
			$("#param5").val(param5);
			$('#jSecureImgId').off('click');
			$("#jsec").css("background-color","white");
			$("#share1").attr("src", "");
			$("#share2").attr("src", "");
			$("div.toshow").css("color", "red");
			$("div.toshow").css('font-weight', 'bold');
			$("div.toshow").show();
			$("#msisdn").val(msisdn);
			
			var iv = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
	        var salt = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
	        var key = CryptoJS.PBKDF2(optxn,CryptoJS.enc.Hex.parse(salt),{keySize: 128/32, iterations: 100});
	        var str= encodeURIComponent(navigator.platform+"*"+screen.width+"-"+screen.height+"*"
	        		+navigator.userAgent+"*"+msisdn);
	        var encrypted = CryptoJS.AES.encrypt(str,key,{ iv: CryptoJS.enc.Hex.parse(iv) });
	        ciphertext = encrypted.ciphertext.toString(CryptoJS.enc.Base64);       
	        var en = (iv+"::"+salt+"::"+encodeURIComponent(ciphertext));
	        $("#en").val(en);
			document.getElementById("junoform").submit();
	
});
	function disableBack() { window.history.forward() }
    window.onload = disableBack();
    window.onpageshow = function(evt) { if (evt.persisted) disableBack() }});
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

<script language="JavaScript">
  window.onload = function() {
    document.addEventListener("contextmenu", function(e){
      e.preventDefault();
    }, false);
    document.addEventListener("keydown", function(e) {
      if (e.ctrlKey && e.shiftKey && e.keyCode == 73) {
        disabledEvent(e);
      }
      if (e.ctrlKey && e.shiftKey && e.keyCode == 74) {
        disabledEvent(e);
      }
      if (e.keyCode == 83 && (navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey)) {
        disabledEvent(e);
      }
      if (e.ctrlKey && e.keyCode == 85) {
        disabledEvent(e);
      }
      if (event.keyCode == 123) {
        disabledEvent(e);
      }
    }, false);

    function disabledEvent(e){
      if (e.stopPropagation){
        e.stopPropagation();
      } else if (window.event){
        window.event.cancelBubble = true;
      }
      e.preventDefault();
      return false;
    }
  };

  window.history.forward();
        function noBack() {
            window.history.forward();
        }
        
        function isNumber(evt) {
            evt = (evt) ? evt : window.event;
            var charCode = (evt.which) ? evt.which : evt.keyCode;
            if (charCode > 31 && (charCode < 48 || charCode > 57)) {
                return false;
            }
            return true;
        }
</script>

<%
	String optxnid = (String) request.getAttribute("optxn");
	String img1 = (String) request.getAttribute("img1");
	String img2 = (String) request.getAttribute("img2");
	String pshare = (String) request.getAttribute("pshare");
	String pimage = (String) request.getAttribute("pimg");
	String merchant = (String) request.getAttribute("header");
	String mertxnid = (String) request.getAttribute("meroptxn");
	String footer = (String) request.getAttribute("footer");
	String hcolor = (String) request.getAttribute("hcolor");
	String desc1 = (String) request.getAttribute("desc1");
	String desc2 = (String) request.getAttribute("desc2");
	String imgsrc = (String) request.getAttribute("imgurl");
	int clkcnt = (int) request.getAttribute("clickcnt");
	String imgstr = (String) request.getAttribute("imgstr");
%>

<style type="text/css">
body {
	font-family: Arial, Helvetica, sans-serif;
	margin: 0;
	padding: 0;
	width: 100%;
}

.jSecureOverlay {
	position: absolute;
}

#jSecureImgContainer {
	position: relative;
	text-align: center;
}

#jSecureImgContainer img {
	position: absolute;
	margin: auto;
	top: 0;
	left: 0;
	right: 0;
}

p {
	font-size: 12px;
	font-family: arial;
	font-align: center;
}

#header {
	font-size: 18px;
	font-style: bold;
	font-valign: center;
	font-family: Arial, Helvetica, sans-serif;
	color: #FFFFFF;
	border-bottom: 5px solid #FFFFFF;
	background: #33ddbf;
	left: 0;
	width: 100%;
	top: 0;
	height: 30px;
	position: absolute;
	padding: 2px 0 2px 0;
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

.footerb {
	border-top: 1px solid #565656;
	background: <%=hcolor%>;
	font-size: 15px;
	font-family: Arial, Helvetica, sans-serif;
	margin: 1px 0 0 0;
	position: fixed;
	left: 0;
	bottom: 0;
	height: auto;
	width: 100%;
	color: #FFFFFF;
}

#footerb {
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

<title>WAP Consent Gateway</title>
</head>
<body oncontextmenu="return false;">
	<table cellpadding="0" cellspacing="0" width="100%" align="center">
		<tr>
			<td align="center" width="100%">&nbsp;</td>
		</tr>
		<div class="header">
			<div align="center">
				<b><%=merchant%></b>
			</div>
		</div>
		<div class="w3-container"
			style="margin-top: 30px; font-family: arial;" align="center">
			<p>
				<font size="4"><strong><%=desc1%> </strong>
			</p>
		</div>

		<div class="w3-container"
			style="margin-top: 35px; font-family: arial;" align="center">
			<p>
				<font size="4"><strong><%=desc2%> </strong>
			</p>
		</div>
		<tr>
			<td align="center" width="100%">&nbsp;</td>
		</tr>

		<tr>
			<td align="center" width="100%">
				<input type="text" onkeypress="return isNumber(event);"
				name="txtmdn" id="txtmdn" placeholder="Enter OTP" maxlength="4"
				size="4"
				style="-webkit-border-radius: 5px; -moz-border-radius: 5px; border-radius: 5px; width: 100px; height: 30px; border-style: solid 2px; border-color: #d6d6c2; font-size: 17px; color: #000000 font-family:arial;">
			</td>
		</tr>
		<tr>
			<td align="center" width="100%">&nbsp;</td>
		</tr>
		<tr>
			<td align="center" width="100%" align="center"
				style="font-size: 17px; font-family: arial; padding-top: 7px;">Click
				<b style="font-size: 20; font-family: arial; color: #009900;">"Submit"</b>to
				process
			</td>
		</tr>
		<tr>
			<td align="center" width="100%">&nbsp;</td>
		</tr>
		<tr>
			<td align="center" valign="top" width="100%"
				style="text-align: center; height: 140px;"><input type="hidden"
				name="cgtrxId" id="optxnid" value="<%=optxnid%>" />
				<div id="jSecureImgId">
					<div id="jSecureImgContainer">
						<div class="toshow" style="display: none">Please Wait...</div>
						<img src="data:image/png;base64,<%=img1%>" id="share1"
							class="jSecureOverlay"> <img
							src="data:image/png;base64,<%=img2%>" id="share2"
							class="jSecureOverlay">
					</div>
				</div>
			</td>
		</tr>
		<div id="i" align=center style="margin-top: 30px;">
			<img src="data:image/png;base64,<%=imgstr%>" alt=" " width="100"
				height="100">
		</div>

		<footer class="w3-container">
			<div class="footerb" align="center"><%=footer%></div>
		</footer>
	</table>
	<form name="junoform" id="junoform" action="/Ashield/validate-img"
		method="post">
		<input type="hidden" name="transID" value="<%=optxnid%>" /> <input
			type="hidden" name=param5 id="param5" /> <input type="hidden"
			name="en" id="en" /> <input type="hidden" name="mertxnid"
			value="<%=mertxnid%>" />
	</form>
</body>
</html>
