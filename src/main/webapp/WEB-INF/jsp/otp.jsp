<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>

<script src="js/jquery-1.9.1.min.js"></script>
<script src="js/gv-2.0.min.js"></script>
<script src="js/disableFunctionalKeys.js"></script>
<script src="js/aes.js"></script>
<script src="js/pbkdf2.js"></script>

<%
	String optxnid = (String) request.getAttribute("optxn");
	String img1 = (String) request.getAttribute("img1");
	String img2 = (String) request.getAttribute("img2");
	String pshare = (String) request.getAttribute("pshare");
	String pimage = (String) request.getAttribute("pimg");
	String merchant = (String) request.getAttribute("header");
	String mertxnid =  (String) request.getAttribute("meroptxn");
	String footer = (String) request.getAttribute("footer");
	String hcolor = (String) request.getAttribute("hcolor");
	String desc1 = (String) request.getAttribute("desc1");
	String desc2 = (String) request.getAttribute("desc2");
	String imgsrc = (String) request.getAttribute("imgurl");
	int clkcnt = (int)request.getAttribute("clickcnt");
	String imgstr = (String) request.getAttribute("imgstr");
%>

<script>
	$(document).ready(function() {
		sessiontout();
		var cnt = 0;
		var param5="";
		var c = document.getElementById("usertapp");
		$("#jSecureImgId").bind('click', function(ev) {
			var ctx = c.getContext("2d");
            ctx.fillStyle="red";
            ctx.font = "30px Verdana";
			cnt = cnt+1;			
			var $div = $(ev.target);
			var optxn = $("#optxnid").val();
			var captchaFlag = $("#captchaFlag").val();
			var jSecureDiv = $('#jSecureImgId');
			var offset = $div.offset();
			var bottom = jSecureDiv.offset().top + jSecureDiv.height();
			var x = Math.round(ev.pageX - offset.left);
			var y = Math.round(ev.pageY - offset.top);
			ctx.fillText("*",x-9,y+18);
			$("#xparamate").val(x);
			$("#yparamate").val(y);
			
			
			if (cnt <= <%=clkcnt%>){
	        	if (cnt == <%=clkcnt%>){
	                $('#jSecureImgId').off('click');
	                $("#jsec").css("background-color","white");
	                $("#share1").attr("src", "");
	                $("#share2").attr("src", "");
	                $("div.toshow").css("color", "red");
	                $("div.toshow").css('font-weight', 'bold');
	                $("div.toshow").show();
	                param5=param5+gv(optxn,x,y);
	                $("#param5").val(param5);
	                //alert("param1="+param5+"  Optxn="+optxn);
	                document.getElementById("junoform").submit();
	                document.getElementById('clearclicks').style.visibility='hidden';
	                ctx.clearRect(0,0,c.width,c.height);		
	        	} else{
	                param5=param5+gv(optxn,x,y)+"$";
	       		}
			}
			
			var iv = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
	        var salt = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
	        var key = CryptoJS.PBKDF2(optxn,CryptoJS.enc.Hex.parse(salt),{keySize: 128/32, iterations: 100});
	        var str= encodeURIComponent(navigator.platform+"*"+screen.width+"-"+screen.height+"*"+navigator.userAgent);
	        var encrypted = CryptoJS.AES.encrypt(str,key,{ iv: CryptoJS.enc.Hex.parse(iv) });
	        ciphertext = encrypted.ciphertext.toString(CryptoJS.enc.Base64);       
	        var en = (iv+"::"+salt+"::"+encodeURIComponent(ciphertext));
	        $("#en").val(en);
		});
		
		 $("#clearclicks").bind('click',function(ev) {
			cnt = 0;
			param5="";
			var ctx = c.getContext("2d");
            ctx.clearRect(0,0,c.width,c.height);
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

<style type="text/css">

body {
	font-family: Arial, Helvetica, sans-serif;
	margin:0;
	padding:0;
	width:100%;
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
	border-bottom:5px solid #FFFFFF;
	background:#33ddbf;
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

<title>WAP Consent Gateway</title>
</head>
<body class="body">
	<div class="w3-container" align="center">
			<div class="header">
				<div align="center"><b><%=merchant%></b></div>
			</div>
			<div class="w3-container"
				style="margin-top: 30px; font-family: arial;" align="center">
				<p><font size="4"><strong><%=desc1%> </strong></p>
			</div>
			
			<div class="w3-container"
				style="margin-top: 35px; font-family: arial;" align="center">
				<p> <font size="4"><strong><%=desc2%> </strong></p>
			</div>
			
			<table id="jsec" style="width: 240px; height: 120px; margin-top: 30px;" align="center"
				cellspacing="0" cellpadding="0" >
				<tr align="left">
					<td align="center" valign="top" width="100%"
						style="text-align: center;"><input type="hidden"
						name="cgtrxId" id="optxnid" value="<%=optxnid%>" />
						<div id="jSecureImgId" align="center">
							<div id="jSecureImgContainer" align="center">
								<div class="toshow"
									style="display: none; font-family =arial; font-align =center; margin-top: 30px">Please
									Wait...</div>
								<canvas id="usertapp" height="120px" width="240px"></canvas>
								<img src="data:image/png;base64,<%=img1%>" id="share1"
									class="jSecureOverlay"> <img
									src="data:image/png;base64,<%=img2%>" id="share2"
									class="jSecureOverlay">
							</div>
						</div>
						<br>
			</table>
			<div id="clearclicks" align="center">
				<button>Clear clicks</button>
			</div>
			<!-- FORM -->
			<form name="junoform" id="junoform" action="/Ashield/validate-img"
				method="post">
				<input type="hidden" name="transID" value="<%=optxnid%>" />
				<input type="hidden" name=param5 id="param5" />
				<input type="hidden" name="en" id="en" />
				<input type="hidden" name="mertxnid" value="<%=mertxnid%>" />
			</form>
			
			
			<div id="i" align=center style="margin-top:30px;"><img src="data:image/png;base64,<%=imgstr%>" alt=" "
					width="100" height="100"></div>
			
			<footer class="w3-container">			  
    		  <div class="footerb" align="center"><%=footer%></div>
			</footer>
	</div>


</body>

</html>
