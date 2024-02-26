package com.ashield.webapps;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.TextUtils;
import org.apache.log4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.ashield.datapojo.AuthMobDFEntity;
import com.ashield.datapojo.AuthReqDetail;
import com.ashield.datapojo.AuthReqValidObj;
import com.ashield.datapojo.AuthShareEntity;
import com.ashield.datapojo.AuthWebResp;
import com.ashield.datapojo.DiscoveryResponse;
import com.ashield.datapojo.ImageValidationResponse;

import com.ashield.datapojo.SecureImageResponse;
import com.ashield.datapojo.SignKeyEntity;
import com.ashield.datapojo.TxnResp;
import com.ashield.datapojo.WebDesignParam;
import com.ashield.dbservice.DbService;
import com.ashield.logging.CDRLogging;
import com.ashield.logging.ErrorLogging;
import com.ashield.logging.Logging;
import com.ashield.redisque.RedisMessagePublisher;
import com.ashield.redisrepo.AuthReqTransactionIDRepoImpl;
import com.ashield.redisrepo.AuthTransactionIDRepoImpl;
import com.ashield.redisrepo.AuthwebRespTokenRepoImpl;
import com.ashield.redisrepo.MCDiscoverRespRespoImpl;
import com.ashield.redisrepo.WebDesignparamRepoImpl;
import com.ashield.utils.AesEncryptDecrypt;
import com.ashield.utils.AshieldEncDec;
import com.ashield.utils.CommonHelper;
import com.ashield.utils.Constants;
import com.github.tsohr.JSONArray;
import com.github.tsohr.JSONObject;
import com.google.gson.Gson;


@Controller
public class AuthMultiDevControler implements Constants {

	@Autowired
	AshieldEncDec mEncDecObj;

	@Autowired
	DbService mAuthDbService;

	@Autowired
	AuthTransactionIDRepoImpl mMCTrackTransRespoImpl;

	@Autowired
	AuthReqTransactionIDRepoImpl mReqTrackTransRespoImpl;

	@Autowired
	WebDesignparamRepoImpl mWebDesignParamRepoImpl;

	@Autowired
	RedisMessagePublisher redisMessagePublisher;

	@Autowired
	AuthwebRespTokenRepoImpl mTokenRespRepoImpl;

	@Autowired
	MCDiscoverRespRespoImpl mMCDiscoverRespRespoImpl;

	@Value( "${ashield.imgSize}" )
	String mImgSize;

	@Value( "${ashield.getimg.url}" )
	String mImageReqUrl;

	@Value( "${ashield.chkimg.url}" )
	String mChkImgReqUrl;

	@Value( "${ashield.sendotp.intern.url}" )
	String mSendOTPUrl;

	@Value("${mchttpTimeout}")
	int mcHttpTimeout;

	@Value("${ashield.mobcon.clientid}")
	String mMCClientID;

	@Value("${ashield.mobcon.clientsec}")
	String mMCClientSec;

	@Value("${ashield.discover.url}")
	String mDiscoverUrl;

	@Value("${ashield.redirect.url}")
	String mRedirectUrl;

	@Value("${ashield.zom.redirect.url}")
	String mZomRedirectUrl;

	@Value("${ashield.getimg.intern.url}")
	String mGetImgUrl;

	Gson gson= new Gson();

	@Value("${ashield.multi.auth.time}")
	int mMultiAuthTimeout;

	@Value("${ashield.auth.timeout.url}")
	String mTimeoutUrl;

	@Value("${ashield.session.time}")
	int mSessionTimeout;

	@Value("${ashield.auth.mobmismat.url}")
	String mMobmismatUrl;

	@Value("${ashield.netiden.url}")
	String mNetIdeUrl;

	@Value("${ashield.creses.url}")
	String mCreSesUrl;

	@Value("${ashield.idedev.url}")
	String mIdeDevUrl;

	@Value("${ashield.linide.url}")
	String mLinIdeUrl;

	@Value("${ashield.initotp.cliname}")
	String mZoClientName;

	@Value("${ashield.zom.secclientid}")
	String mZomClientID;

	@Value("${ashield.zom.secclientsec}")
	String mZomClientSec;

	@Value("${ashield.zom.clientid}")
	String mZomClientIDen;

	@Value("${ashield.zom.dgsecclientid}")
	String mZomClientDGID;

	@Value("${ashield.zom.dgsecclientsec}")
	String mZomClientDGSec;

	@Value("${ashield.zom.dgclientid}")
	String mZomClientDGIDen;


	@RequestMapping(value="/multi-flow")
	public @ResponseBody void sendmultidevreq(@RequestParam(value="transID", required=true) String aTransID, 
			HttpServletRequest request, HttpServletResponse response) {

		try {	

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "df");
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
			String mob = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			CDRLogging.getCDRWriter().logCDR(authReqDetail, PRIMARY_NUM, "", "");

			String redirectUrl = "";

			String reqTime = CommonHelper.getFormattedDateString();

			authReqDetail.setSecMsisdn(mEncDecObj.encrypt(mob));
			authReqDetail.setStartTime(reqTime);			

			String newTxnID = getTransID();

			mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(newTxnID + "req", authReqDetail);
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "rdu", lRedirectUrl);
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "df", lDevicefin);
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "mn", mob);

			SecureImageResponse authRespdetail = new SecureImageResponse();
			authRespdetail.setOptxn(newTxnID);

			authRespdetail = sendImageReq(newTxnID, "null", authReqDetail.getCpID(),
					request, response, authReqDetail.getSeckey(), false, null);

			if(authRespdetail != null && authRespdetail.getStatusCode() != null &&
					authRespdetail.getStatusCode().contains("201")) {

				mWebDesignParamRepoImpl.saveToWebDesignparamRepo(newTxnID + "web", 
						mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web"));

				WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(newTxnID + "web");

				RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/multimob.jsp");

				String img1 = authRespdetail.getImage1();
				String img2 = authRespdetail.getImage2();
				String txt = authRespdetail.getPimage();
				String atxnID = authRespdetail.getOptxn();
				String pshare = "YES";

				request.setAttribute("img1", img1);
				request.setAttribute("img2", img2);
				request.setAttribute("optxn", atxnID);
				request.setAttribute("pshare", pshare);
				request.setAttribute("pimg", txt);
				request.setAttribute("meroptxn", authReqDetail.getMerTxnID());
				request.setAttribute("header", webparam.getHtext());
				request.setAttribute("hcolor", webparam.getHcolor());
				request.setAttribute("desc1",webparam.getDeswifi1());
				request.setAttribute("desc2",webparam.getDeswifi2());
				request.setAttribute("footer", webparam.getFtext());
				request.setAttribute("imgurl", webparam.getLogoimg());
				request.setAttribute("avtimgurl", webparam.getAvtimg());
				request.setAttribute("imgstr", webparam.getImgstr());
				request.setAttribute("t", mSessionTimeout);
				request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

				Logging.getLogger().info("multi mob:" + "imgurl: " + webparam.getLogoimg()
				+",avtimgurl:" + webparam.getAvtimg());

				try {
					rd.forward(request, response);
				} catch (ServletException | IOException e) {
					Logging.getLogger().info("Exception--" + e.getMessage());
				}	

				Logging.getLogger().info("displayImage over : ");
			} else {
				Logging.getLogger().info("displayImage fail : ");
				CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");

				redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) + "&txnid=" + 
						"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
						"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
						"&atxnid=" + aTransID + "&opn=" + "NA";
				MDC.clear();
				response.sendRedirect(redirectUrl);
			}
			MDC.clear();
		}  catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	public void sendmultidevreqonemp(String aTransID, HttpServletRequest request, HttpServletResponse response) {

		try {
			
			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String redirectUrl = "";
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
			

			SecureImageResponse authRespdetail = new SecureImageResponse();
			authRespdetail.setOptxn(aTransID);

			authRespdetail = sendImageReq(aTransID, "null", authReqDetail.getCpID(),
					request, response, authReqDetail.getSeckey(), false, null);

			if(authRespdetail != null && authRespdetail.getStatusCode() != null &&
					authRespdetail.getStatusCode().contains("201")) {
				
				WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web");

				RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/multimob.jsp");

				String img1 = authRespdetail.getImage1();
				String img2 = authRespdetail.getImage2();
				String txt = authRespdetail.getPimage();
				String atxnID = authRespdetail.getOptxn();
				String pshare = "YES";

				request.setAttribute("img1", img1);
				request.setAttribute("img2", img2);
				request.setAttribute("optxn", atxnID);
				request.setAttribute("pshare", pshare);
				request.setAttribute("pimg", txt);
				request.setAttribute("meroptxn", authReqDetail.getMerTxnID());
				request.setAttribute("header", webparam.getHtext());
				request.setAttribute("hcolor", webparam.getHcolor());
				request.setAttribute("desc1",webparam.getDeswifi1());
				request.setAttribute("desc2",webparam.getDeswifi2());
				request.setAttribute("footer", webparam.getFtext());
				request.setAttribute("imgurl", webparam.getLogoimg());
				request.setAttribute("avtimgurl", webparam.getAvtimg());
				request.setAttribute("imgstr", webparam.getImgstr());
				request.setAttribute("t", mSessionTimeout);
				request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

				Logging.getLogger().info("multi mob:" + "imgurl: " + webparam.getLogoimg()
				+",avtimgurl:" + webparam.getAvtimg());

				try {
					rd.forward(request, response);
				} catch (ServletException | IOException e) {
					Logging.getLogger().info("Exception--" + e.getMessage());
				}	

				Logging.getLogger().info("displayImage over : ");
			} else {
				Logging.getLogger().info("displayImage fail : ");
				CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");

				redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) + "&txnid=" + 
						"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
						"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
						"&atxnid=" + aTransID + "&opn=" + "NA";
				MDC.clear();
				response.sendRedirect(redirectUrl);
			}
			MDC.clear();
		}  catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	public String getTransID() {

		UUID uuid = UUID.randomUUID();

		return uuid.toString() + "saas";
	}

	public SecureImageResponse sendImageReq(String aTransID, String aMsisdn, String aMid, 
			HttpServletRequest aRequest, HttpServletResponse response, String seckey, 
			boolean otpimg, String otp) {

		SecureImageResponse lImageRs = new SecureImageResponse();
		try {

			Logging.getLogger().info("getsecure-img:" + "txnID: " + aTransID
					+",msisdn:" + mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid);			

			if(!TextUtils.isEmpty(aMid)) {
				StringBuilder imageStr = new StringBuilder();

				String browserAgent = aRequest.getHeader("user-agent");
				String size = mImgSize;
				String mobileIp = aRequest.getRemoteAddr()!=null?aRequest.getRemoteAddr():"null";
				String serviceId = "null";
				String orgId = aMid;
				String imsi = "null";
				String circleId = "null";
				String imei = "null";
				String channel = "WAP";
				String acpt = aRequest.getHeader("accept")!=null?aRequest.getHeader("accept"):"null";
				String sip = "null";
				String xfip = aRequest.getHeader("X-Forwarded-For") != null ? aRequest.getHeader("X-Forwarded-For") :"null";
				String itpe = "3b";
				String t1 = "null";
				String t2 = aMsisdn;
				String t3 = "null";
				String ts = String.valueOf(System.currentTimeMillis());

				if(otpimg) {
					if(otp != null) {
						itpe = "8d";
						t3 = otp;
					} else  {
						itpe = "8c";
					}					
				}

				if(t2.contains("null")) {
					itpe = "1c";
				}

				String dataToBeHashed = aTransID + ts + size +  mobileIp + aMsisdn + browserAgent + 
						serviceId + orgId + imsi + circleId + imei +  channel +  acpt + sip + xfip + itpe + t1 + t2 + t3;
				String sig = CommonHelper.generateSign(seckey, dataToBeHashed);

				HttpPost httpPost=new HttpPost(mImageReqUrl);
				List<NameValuePair> params = new ArrayList<>();
				params.add(new BasicNameValuePair("optxn", aTransID));                                             
				params.add(new BasicNameValuePair("size", size));                                               
				params.add(new BasicNameValuePair("sig", sig));                                      
				params.add(new BasicNameValuePair("ts", ts));                                
				params.add(new BasicNameValuePair("mip", mobileIp));                         
				params.add(new BasicNameValuePair("msisdn", aMsisdn));                        
				params.add(new BasicNameValuePair("bua", browserAgent));                     
				params.add(new BasicNameValuePair("sid", serviceId));                        
				params.add(new BasicNameValuePair("oid", orgId));                            
				params.add(new BasicNameValuePair("imsi", imsi));                            
				params.add(new BasicNameValuePair("cid", circleId));                         
				params.add(new BasicNameValuePair("imei", imei));  
				params.add(new BasicNameValuePair("channel", channel));
				params.add(new BasicNameValuePair("acpt", acpt));
				params.add(new BasicNameValuePair("sip", sip));
				params.add(new BasicNameValuePair("xfip", xfip));
				params.add(new BasicNameValuePair("itpe", itpe));
				params.add(new BasicNameValuePair("t1", t1));
				params.add(new BasicNameValuePair("t2", t2));
				params.add(new BasicNameValuePair("t3", t3));
				httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));
				httpPost.setHeader("origin", "https://junosecure");
				RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
						setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
				httpPost.setConfig(conf);
				CloseableHttpClient client = HttpClients.createDefault();
				CloseableHttpResponse imgresponse = client.execute(httpPost);
				if (imgresponse.getStatusLine().getStatusCode() == 200) {
					BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
					String readLine;
					while (((readLine = br.readLine()) != null)) {
						imageStr.append(readLine);
					}
				} else {
					Logging.getLogger().error(imgresponse.toString());
					System.out.println(imgresponse);	
				}
				lImageRs = new Gson().fromJson(imageStr.toString(), SecureImageResponse.class);
				//lImageRs.setOptxn(aTransID);
			}
		}catch (Exception e) {
			e.printStackTrace();
		}

		return lImageRs;
	}

	@RequestMapping(value = "/sendsms")
	public @ResponseBody void displaywait(@RequestParam("mdnum") String aesplatform,
			@RequestParam("txnid") String aTransID,
			@RequestParam("param5") String param5, 
			@RequestParam("mertxnid") String merTxnID, 
			HttpServletRequest request, HttpServletResponse response) {

		String lMobileNumber = "";

		ImageValidationResponse mImgResp = null;
		StringBuilder imageStr = new StringBuilder();
		String headerName = null;
		String headerValue = null;

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
		String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");

		String dataHashed = aTransID + param5;
		String hash = "";
		try {
			hash = CommonHelper.generateSign(authReqDetail.getSeckey(), dataHashed);
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		MDC.put(LOG4J_MDC_TOKEN, merTxnID);

		Logging.getLogger().info("displayOTP txnID" + aTransID);

		try {
			String decrypted_aesdata = null;

			aesplatform = (aesplatform!=null && !aesplatform.equalsIgnoreCase(""))?URLDecoder.decode(aesplatform, "UTF-8"):"";
			if (aesplatform != null && aesplatform.split("::").length == 3) {
				AesEncryptDecrypt aesEncryptDecrypt = new AesEncryptDecrypt(128, 100);
				Logging.getLogger().info("*********************AES Encrypted_platform from JS - " + aesplatform);
				String iv = aesplatform.split("\\::")[0];
				String salt = aesplatform.split("\\::")[1];
				String ciphertext = aesplatform.split("\\::")[2];

				Logging.getLogger().info("*********************AES encrypted value of aesplatform --> salt :"
						+ " " +salt+", iv : "+iv+", ciphertext : "+ciphertext);
				decrypted_aesdata = aesEncryptDecrypt.decrypt(salt, iv, aTransID, ciphertext);
				Logging.getLogger().info("*********************AES Decrypted platform from JS - " + lMobileNumber);
			}

			lMobileNumber = decrypted_aesdata!=null?URLDecoder.decode(decrypted_aesdata.split("\\*")[0],"UTF-8"):"null";
			String platform = decrypted_aesdata!=null?URLDecoder.decode(decrypted_aesdata.split("\\*")[1],"UTF-8"):"null";
			String scn_Size = decrypted_aesdata!=null?decrypted_aesdata.split("\\*")[2]:"null";
			String nav_bua = decrypted_aesdata!=null?URLDecoder.decode(decrypted_aesdata.split("\\*")[3],"UTF-8"):"null";


			String remoteIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null ? request.getHeader("X-FORWARDED-FOR") : "null";
			String clientIP = request.getHeader("CLIENT_IP") != null ? request.getHeader("CLIENT_IP") : "null";
			String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
			String acpt = request.getHeader("accept");
			String userAgent = request.getHeader("user-agent");
			String mip = Stream.of(xforwardedIP, remoteIp, clientIP)
					.filter(s -> s != null && !s.isEmpty() && !s.equalsIgnoreCase("null"))
					.collect(Collectors.joining("-"));

			Logging.getLogger().info("*** sendmdn Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent +", remoteIp : " + remoteIp +
					", X-forwardedIP : " + xforwardedIP + ", clientIP : " + clientIP + ", Referer : " + referer+", acpt : "+acpt+
					", param5 : "+param5);

			Logging.getLogger().info("sendmdn lMobileNumber" + lMobileNumber);

			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				Logging.getLogger().info("**HEADER --> "+headerName  + " : " + headerValue);
			}

			HttpPost httpPost=new HttpPost(mChkImgReqUrl);
			List<NameValuePair> params = new ArrayList<>();
			params.add(new BasicNameValuePair("optxn", aTransID));                                             
			params.add(new BasicNameValuePair("param5", param5));                                               
			params.add(new BasicNameValuePair("sig", hash));
			params.add(new BasicNameValuePair("bua", nav_bua));
			params.add(new BasicNameValuePair("ip", mip));
			params.add(new BasicNameValuePair("plf", platform));
			params.add(new BasicNameValuePair("srnsize", scn_Size));				

			httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));
			httpPost.setHeader("origin", "https://junosecure");
			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
			}
			mImgResp = new Gson().fromJson(imageStr.toString(), ImageValidationResponse.class);			

			if(mImgResp == null) {
				Logging.getLogger().info("displayImage fail : ");
				CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");	

				String redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) + "&txnid=" + 
						"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
						"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
						"&atxnid=" + aTransID + "&opn=" + "NA";
				MDC.clear();
				response.sendRedirect(redirectUrl);
			} else if(mImgResp != null && mImgResp.getStatusCode().contentEquals("JS201") 
					&& mImgResp.getResult().contentEquals("YES")) {	

				boolean runloop  = false;

				if(lMobileNumber.equals("0")) {					
					sendmultidevreqonemp(aTransID, request, response);	
				} else {

					if(sendrimsg(aTransID, lMobileNumber, authReqDetail.getSmsurl())) {
						authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMobileNumber));
						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);
						runloop  = true;
					} else {
						Logging.getLogger().info("Send msg fail : ");
						CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");	

						String redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) + "&txnid=" + 
								"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
								"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
								"&atxnid=" + aTransID + "&opn=" + "NA";
						MDC.clear();
						response.sendRedirect(redirectUrl);
					}
					WebDesignParam webparam = mWebDesignParamRepoImpl.
							getValueFromWebDesignparamRepo(aTransID + "web");

					RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/authowait.jsp");
					request.setAttribute("t", mMultiAuthTimeout);
					request.setAttribute("optxn", aTransID);
					request.setAttribute("header", webparam.getHtext());
					request.setAttribute("hcolor", webparam.getHcolor());
					request.setAttribute("desc1","We have sent an url via SMS to your mobile phone. check sms notification received. "
							+ "Click the url to Authorize the device to access the account");
					request.setAttribute("desc2","Steps to secure Authorization");
					request.setAttribute("footer", webparam.getFtext());
					request.setAttribute("inapp", "true");
					request.setAttribute("imgstr", webparam.getGifstr());

					try {
						rd.forward(request, response);
					} catch (ServletException | IOException e) {
						Logging.getLogger().info("Exception--" + e.getMessage());
					}
				}

			} else {
				Logging.getLogger().info("displayImage fail : ");
				CDRLogging.getCDRWriter().logCDR(authReqDetail, null, USER_CANCLED, "NA");	

				String redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(USER_CANCLED,authReqDetail.isIPhone()) + "&txnid=" + 
						"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
						"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
						"&atxnid=" + aTransID + "&opn=" + "NA";
				MDC.clear();
				response.sendRedirect(redirectUrl);
			}

		}catch (Exception e) {
			e.printStackTrace();
		}
		MDC.clear();
	}

	@RequestMapping(value = "/readTxn")
	public @ResponseBody String checkRedisData(@RequestParam(value="rtxnid") String aTransID, 
			HttpServletResponse response, HttpServletRequest request){
		MDC.put(LOG4J_MDC_TOKEN, aTransID);

		Logging.getLogger().info("Check Redis" + aTransID);

		String resp = "NoResp";

		AuthReqDetail authRespDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "aurires");

		if(authRespDetail != null) {
			resp = "AS201";
		}

		return resp;
	}

	/**
	 * 
	 * @param txn
	 */
	@RequestMapping(value = "/sessTOut")
	public @ResponseBody void PurchaseSessionTimedOut(@RequestParam(value="txn") String aTransID, 
			HttpServletResponse response, HttpServletRequest request){
		MDC.put(LOG4J_MDC_TOKEN, aTransID);

		Logging.getLogger().info("sessTOut" + aTransID);

		String status = "";
		try {
			AuthReqDetail authRespDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "aurires");

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lMobileNumber = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

			if(authRespDetail != null) {
				if(authRespDetail.isYesclick()) {
					String newTxnID = getTransID();
					String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");
					mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "aurires");
					generateshare(mEncDecObj.decrypt(authRespDetail.getDf()), lMobileNumber, newTxnID, lRedirectUrl, lOpn, response,
							aTransID, "YES", authReqDetail.getCpID(), request);
				} else {
					generateshare(mEncDecObj.decrypt(authRespDetail.getDf()), lMobileNumber, "", lRedirectUrl, "", response,
							aTransID, "NO", authReqDetail.getCpID(), request);
				}

			} else {

				authReqDetail.setAuthtimeout(true);
				authReqDetail.setSecTxnID(aTransID);

				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

				Logging.getLogger().info("displayOTP mobilenum" + lMobileNumber);

				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "mn", lMobileNumber);

				SecureImageResponse authRespdetail = new SecureImageResponse();

				authRespdetail = sendImageReq(aTransID, lMobileNumber, authReqDetail.getCpID(),
						request, response, authReqDetail.getSeckey(), true, null);

				if(authRespdetail != null && authRespdetail.getStatusCode() != null &&
						authRespdetail.getStatusCode().contains("201")) {
					displayOtpImage(authRespdetail, lMobileNumber, request, response, 4, true);
					Logging.getLogger().info("displayImage over : ");
				} else {
					Logging.getLogger().info("displayImage fail : ");
					CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");	

					String redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) 
					+ "&txnid=" + "0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" + "NA" + "&mtxnid=" + 
					authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn=" + "NA";
					MDC.clear();
					response.sendRedirect(redirectUrl);
				}
			}

		} catch (Exception e ) {
			ErrorLogging.getLogger().error("Exception in PurchaseSessionTimedOut : " + e.getMessage());
		}
	}

	/**
	 * 
	 * @param txn
	 */
	@RequestMapping(value = "/timeOut")
	public @ResponseBody void PageSessionTimedOut(@RequestParam(value="txn") String aTransID, 
			@RequestParam(value="jsbua" , required=false) String aJSBUA,
			HttpServletResponse response, HttpServletRequest request){
		MDC.put(LOG4J_MDC_TOKEN, aTransID);

		Logging.getLogger().info("sessTOut" + aTransID + ", jsBUA : " + aJSBUA);

		try {

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lMobileNumber = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

			generateshare(mEncDecObj.decrypt(authReqDetail.getDf()), lMobileNumber, "", lRedirectUrl, "", response,
					aTransID, "Timeout", authReqDetail.getCpID(), request);

		} catch (Exception e ) {
			ErrorLogging.getLogger().error("Exception in PurchaseSessionTimedOut : " + e.getMessage());
		}
	}



	private boolean sendrimsg(String aTransID, String lMobileNumber, String url) {

		try {
			String lMsisdn =  mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			String enctxnID = mEncDecObj.encrypt(aTransID);

			String message ="Please click the link to authorize " + lMsisdn +  " Device as your secondary devie " + 
					" https://" + System.getenv("DOMAIN_NAME") + "/Ashield/authorize?txnID=" + enctxnID;
			StringBuilder imageStr = new StringBuilder();

			HttpPost httpPost = null;

			if(TextUtils.isEmpty(url)) {
				httpPost = new HttpPost(mSendOTPUrl);
				url = mSendOTPUrl;
			} else {
				httpPost = new HttpPost(url);
			}
			
			List<NameValuePair> params = new ArrayList<>();
			if(url.contains(SMS_COUNTRY)) {
				params.add(new BasicNameValuePair("User", "JunoTele"));                                             
				params.add(new BasicNameValuePair("Passwd", "Jun0@SMSC"));                                               
				params.add(new BasicNameValuePair("Sid", "ASHELD"));                                      
				params.add(new BasicNameValuePair("Mobilenumber", lMsisdn));
				params.add(new BasicNameValuePair("Message", message));
				params.add(new BasicNameValuePair("Mtype", "N"));
				params.add(new BasicNameValuePair("DR", "Y"));
			} else if(url.contains(BRILIENT)) {
				params.add(new BasicNameValuePair("action", "send-sms"));                                             
				params.add(new BasicNameValuePair("api_key", "QVNoaWVsZDpAYXNoaWVsdiZ0eQ=="));                                               
				params.add(new BasicNameValuePair("from", "8809638097774"));                                      
				params.add(new BasicNameValuePair("to", lMsisdn));
				params.add(new BasicNameValuePair("sms", message));
			}

			httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
				Logging.getLogger().info("send sms resp : " + imageStr.toString());
				return true;
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);	
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private void displayOtpImage(SecureImageResponse mImageResp, String mobilenum, HttpServletRequest request,
			HttpServletResponse response, int clkcount, boolean sendMsg) {

		try {
			String img1 = mImageResp.getImage1();
			String img2 = mImageResp.getImage2();
			String txt = mImageResp.getPtext();
			String txnID = mImageResp.getOptxn();
			String pshare = mImageResp.getPimage();
			boolean showotp = false;

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "rdu");

			WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");
			if( authReqDetail != null && webparam != null) {
				try {
					if(sendMsg) {
						showotp = sendotpmsg(txt, mobilenum, authReqDetail.getSmsurl());
					} else {
						showotp = true;
					}
				} catch(Exception e) {
					e.printStackTrace();
				}

				if(showotp) {

					RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/otp.jsp");

					request.setAttribute("img1", img1);
					request.setAttribute("img2", img2);
					request.setAttribute("optxn", txnID);
					request.setAttribute("pshare", pshare);
					request.setAttribute("pimg", txt);
					request.setAttribute("simcnt", authReqDetail.getSimcount());
					request.setAttribute("meroptxn", authReqDetail.getMerTxnID());
					request.setAttribute("header", webparam.getHtext());
					request.setAttribute("hcolor", webparam.getHcolor());
					request.setAttribute("desc1",webparam.getDesotp1());
					request.setAttribute("desc2",webparam.getDesotp2());
					request.setAttribute("footer", webparam.getFtext());
					request.setAttribute("imgurl", webparam.getLogoimg());	
					request.setAttribute("clickcnt", clkcount);
					request.setAttribute("imgstr", webparam.getImgstr());
					request.setAttribute("t", mSessionTimeout);
					request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

					try {
						rd.forward(request, response);
					} catch (ServletException | IOException e) {
						Logging.getLogger().info("Exception--" + e.getMessage());
					}
				}
			} else {
				Logging.getLogger().info("displayImage fail : ");
				CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");				
				String redirectUrl = lRedirectUrl + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) + "&txnid=" + 
						"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
						"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
						"&atxnid=" + txnID + "&opn=" + "NA";
				MDC.clear();
				response.sendRedirect(redirectUrl);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@RequestMapping(value="/nodattxn")
	public @ResponseBody void timeoutauth(HttpServletRequest request, HttpServletResponse response) {

		Logging.getLogger().info("timeoutauth : ");

		RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/timeout.jsp");
		request.setAttribute("header", "AShield");
		request.setAttribute("desc1","Please check the received OTP sent to mobile number to enter in login device");
		request.setAttribute("footer", "AShield Technologies");

		try {
			rd.forward(request, response);
		} catch (ServletException | IOException e) {
			Logging.getLogger().info("Exception--" + e.getMessage());
		}
	}			

	@RequestMapping(value="/authorize")
	public @ResponseBody void autherizemob(@RequestParam(value="txnID", required=true) String aencTxnID,
			@RequestParam(value="inApp", required=false, defaultValue="false") boolean inAPP,
			@RequestParam(value="eshare", required=false) String aDevShare,
			@RequestParam(value="df", required=false) String aDevFin,
			@RequestParam(value="mRdu", required=false) String acpRdu,
			@RequestParam(value="newtxnID", required=false) String aenccpTxnID,
			@RequestParam(value="ipne", required=false, defaultValue="false") boolean isIphone,
			HttpServletRequest request, HttpServletResponse response) {

		String headerName = null;
		String headerValue = null;
		String resp = null;
		String userAgent = "";
		String deviceFin = "";
		String accept = "";
		String ipAddress = "";
		String acpTxnID = "";

		//boolean inAPP = false;

		try {
			String aTxnID = mEncDecObj.decrypt(aencTxnID);
			MDC.put(LOG4J_MDC_TOKEN, aTxnID);
			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				Logging.getLogger().info("**HEADER --> "+headerName  + " : " + headerValue);
			}

			String referer = request.getHeader("referer")==null?null:request.getHeader("referer");
			userAgent = request.getHeader("user-agent")==null?"null":request.getHeader("user-agent");

			if(referer != null || userAgent.contains("https://developers.google.com")) {
				return;
			}

			Logging.getLogger().info("inAPP : " + inAPP +
					", CPTXNID=" + aencTxnID + ", df=" + aDevFin +
					", eshare=" + aDevShare + ", newTxnID=" + aenccpTxnID +
					", cprdu=" + acpRdu);

			Logging.getLogger().info("aTxnID : " + aTxnID);

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTxnID + "req");

			WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTxnID + "web");

			String aDecDeviceFin = mEncDecObj.decrypt(aDevFin);

			Logging.getLogger().info("aDecDeviceFin : " + aDecDeviceFin);

			String reqTime = CommonHelper.getFormattedDateString();

			/*
			 * if(inaPP.contentEquals("true")) { inAPP = true; }
			 */

			if(authReqDetail != null) {		

				if(authReqDetail.isAuthtimeout()) {
					resp = mTimeoutUrl;
					response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
					response.setHeader("Location", resp);
					response.sendRedirect(resp);
					return;
				}

				AuthReqDetail authReqDetailnew = new AuthReqDetail();

				if(!inAPP) {

					ipAddress=request.getRemoteAddr()!=null?request.getRemoteAddr():"null";
					accept = request.getHeader("accept")==null?"null":request.getHeader("accept");

					String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null ? request.getHeader("X-FORWARDED-FOR") : "null";

					if(!xforwardedIP.contains("null")) {
						ipAddress = xforwardedIP;
					}

					String mCookieValue = "";
					Cookie[] cookies = request.getCookies();
					if (cookies != null) {
						for(Cookie c : cookies) {
							if(c.getName().equals("authshare")) {
								mCookieValue = c.getValue();
							}
						}
					}			
					Logging.getLogger().info(" mCookieValue:" +  mCookieValue);


					if(!TextUtils.isEmpty(mCookieValue)) {
						mCookieValue = mEncDecObj.decrypt(mCookieValue);
						String txnlenght = mCookieValue.substring(0, 2);
						acpTxnID = mCookieValue.substring(2,Integer.parseInt(txnlenght)+2);
						aDevShare = mCookieValue.substring(2 + Integer.parseInt(txnlenght), mCookieValue.length());

						Logging.getLogger().info("txnlenght - " + txnlenght + "asTxnID - " + acpTxnID + ", share-" + aDevShare);

					} else {						
						acpTxnID = "";
					}
					aDecDeviceFin = userAgent + accept;	

					if(TextUtils.isEmpty(acpTxnID)) {
						acpTxnID = getTransID();
					}

					SignKeyEntity signEnt = mAuthDbService.getByMid(authReqDetail.getCpID());					

					authReqDetailnew.setSimcount(1);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "wap");
					if(signEnt != null) {
						authReqDetailnew.setCpRdu(signEnt.getTokenRedirectUrl());
						/*authReqDetailnew.setShareurl("");
						authReqDetailnew.setSmsurl("");*/
					}

				} else {
					if(aenccpTxnID != null && !aenccpTxnID.contentEquals("null")) {
						acpTxnID = mEncDecObj.decrypt(aenccpTxnID);
					} else {
						acpTxnID = getTransID();
					}

					if(acpTxnID != null && acpTxnID.contentEquals("0")) {
						acpTxnID = getTransID();
					}
					authReqDetailnew.setCpRdu(acpRdu);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");
				}

				try {
					authReqDetailnew.setMip(ipAddress);
					authReqDetailnew.setBua(userAgent);
					authReqDetailnew.setCpID(authReqDetail.getCpID());
					authReqDetailnew.setStartTime(reqTime);
					authReqDetailnew.setCpTxnID(acpTxnID);
					authReqDetailnew.setDevshare(aDevShare);
					authReqDetailnew.setDf(aDecDeviceFin);
					authReqDetailnew.setIPhone(isIphone);
					authReqDetailnew.setVpnflag(false);
					authReqDetailnew.setSeckey(authReqDetail.getSeckey());		
					authReqDetailnew.setClientURl(authReqDetail.getClientURl());

					authReqDetailnew.setSecTxnID(aTxnID);
					authReqDetailnew.setSecMsisdn(authReqDetail.getSecMsisdn());
					authReqDetailnew.setPrimMsisdn(authReqDetail.getPrimMsisdn());
					authReqDetailnew.setDemography(authReqDetail.isDemography());
					authReqDetailnew.setMerTxnID(authReqDetail.getMerTxnID());

					authReqDetailnew.setOtpflow(authReqDetail.isOtpflow());
					authReqDetailnew.setClientURl(authReqDetail.getClientURl());
					authReqDetailnew.setCliOtp(authReqDetail.isCliOtp());
					authReqDetailnew.setMulitdevice(authReqDetail.isMulitdevice());
					authReqDetailnew.setAuthorize(true);
					authReqDetailnew.setDiUrl(authReqDetail.getDiUrl());
					authReqDetailnew.setShareurl(authReqDetail.getShareurl());
				}catch (Exception e) {
					e.printStackTrace();
				}

				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetailnew);

				mWebDesignParamRepoImpl.saveToWebDesignparamRepo(acpTxnID + "web", webparam);

				AuthReqValidObj msisdnObj = validatedevfin(acpTxnID, aDecDeviceFin, aDevShare, isIphone,
						authReqDetail.isMulitdevice(), authReqDetail.getShareurl(), request, response);

				if(!TextUtils.isEmpty(msisdnObj.getMsisdn())) {					

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", msisdnObj.getMsisdn());
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", authReqDetailnew.getCpRdu());

					resp = sendShare(acpTxnID, request, response);
					Logging.getLogger().info("sendShare resp: " + resp);

					if(resp != null) {
						//mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTxnID + "aurires", authReqDetail);					
						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", resp);
						response.sendRedirect(resp);
					}
					MDC.clear();
					return;
				} else {

					boolean otpflow = authReqDetail.isOtpflow();

					String devicefin = mEncDecObj.decrypt(authReqDetail.getDf());
					String lMobileNumber = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

					SecureImageResponse authRespdetail = new SecureImageResponse();
					authRespdetail.setOptxn(acpTxnID);

					String IdeNetResp = processIdeNet(ipAddress);

					if(!TextUtils.isEmpty(IdeNetResp)) {

						JSONObject lIderespJson = new JSONObject(IdeNetResp);
						String status = lIderespJson.getString("status");

						if(status.contentEquals("SUCCESS")) {
							String networkProvider = lIderespJson.getString("networkProvider");
							String isCellularNetwork = lIderespJson.getString("isCellularNetwork");
							String isMobile = lIderespJson.getString("isMobile");

							authReqDetailnew.setNetProvider(networkProvider);
							authReqDetailnew.setIsMobileNetwork(isCellularNetwork);

							if(isCellularNetwork.contentEquals("true") && (networkProvider.contains("AIRTEL") ||
									networkProvider.contains("IDEA") || 
									networkProvider.contains("VODAFONE"))) {
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn",
										networkProvider);

								//mMCDiscoverRespRespoImpl.saveToAshiledMCRedisRepo(acpTxnID + "_MC",	lDiscRep);

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");


								String createsesResp = createSession();

								if(!TextUtils.isEmpty(createsesResp)) {
									JSONObject lCrerespJson = new JSONObject(createsesResp);

									String sesstatus = lCrerespJson.getString("status");

									if(sesstatus.contentEquals("SUCCESS")) {
										String sesID = lCrerespJson.getString("sessionId");

										String lAuthrizeurl = mIdeDevUrl + "?sessionId=" + sesID + 
												"&correlationId=" + acpTxnID + "&redirectUrl=" +
												mZomRedirectUrl;

										authRespdetail.setUrl(lAuthrizeurl); 
										authRespdetail.setStatusCode(SUCCESS);
									} else {
										authRespdetail.setStatusCode(DISC_FAIL);
									}										
								}									
							} else { 
								authRespdetail.setStatusCode(DISC_FAIL);
							}
						} else { 
							authRespdetail.setStatusCode(DISC_FAIL);
						} 

					}  else {
						authRespdetail.setStatusCode(DISC_FAIL); 
					}

					if(authRespdetail != null && authRespdetail.getStatusCode().equals(DISC_FAIL)) {
						if(otpflow && !inAPP) {
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", devicefin);  
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", authReqDetailnew.getCpRdu());
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "wap");
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", lMobileNumber);
							authReqDetail.setTelco("OTP");
							authRespdetail = sendImageReq(acpTxnID, lMobileNumber, authReqDetail.getCpID(),
									request, response, authReqDetail.getSeckey(), true, null);

							if(authRespdetail != null && authRespdetail.getStatusCode() != null &&
									authRespdetail.getStatusCode().contains("201")) {
								displayOtpImage(authRespdetail, lMobileNumber, request, response, 4, true);
								Logging.getLogger().info("displayImage over : ");
							} else {
								Logging.getLogger().info("displayImage fail : ");
								CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");	

								String redirectUrl = authReqDetailnew.getCpRdu() + "msisdn=" +  mEncDecObj.encrypt(SERVER_ERROR,authReqDetail.isIPhone()) + "&txnid=" + 
										"0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" +
										"NA" + "&mtxnid=" + authReqDetail.getMerTxnID() + 
										"&atxnid=" + acpTxnID + "&opn=" + "NA";
								MDC.clear();
								response.sendRedirect(redirectUrl);
							}				
							return;
						} else if(inAPP) { 	
							String lWifiMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTxnID + "mn");

							if(TextUtils.isEmpty(lWifiMsisdn)) {
								authRespdetail.setStatusCode(INVALID_CPTXNID);
								getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
								sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPTXNID
										, INVALID_ZERO , INVALID_ZERO);
							} else {

								if(!authReqDetail.isMulitdevice()) {
									AuthMobDFEntity lMobData = mAuthDbService.getByMsisdn(lWifiMsisdn +
											authReqDetail.getCpID());

									if(lMobData != null && !lMobData.getDevicefin().
											contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
										Logging.getLogger().info("DF not match : " +  lMobData.getDevicefin());
										Logging.getLogger().info("DF not match : " +  authReqDetail.getDf());
										mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "action", "rereg");
									} else if (lMobData != null){
										Logging.getLogger().info("DF match : " +  lMobData.getDevicefin());
									} else {
										Logging.getLogger().info("NO DF Data : ");
									}
								}

								String message = "ASHIELD"+acpTxnID+"#"+reqTime;			
								redisMessagePublisher.publish(message);

								mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetailnew);

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", lWifiMsisdn);
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");

								String displayImgUrl = mGetImgUrl + "?mTxnID=" + acpTxnID + "&mID=" + 
										authReqDetailnew.getCpID();

								response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
								response.setHeader("Location", displayImgUrl);
								response.sendRedirect(displayImgUrl);

								Logging.getLogger().info(" Display image over WIFI authRespdetail" + authRespdetail.getUrl());
							}
							return;
						} else {
							authRespdetail.setStatusCode(DISC_FAIL);
							getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
							//sendResponse(authReqDetail, INVALID_SRC, INVALID_TOKEN, request, response);
							return;
						}
					}			

					if(authRespdetail != null && authRespdetail.getStatusCode().equals("AS201")) {
						try {

							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetailnew);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", devicefin);  
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", authReqDetailnew.getCpRdu());

							Logging.getLogger().info("**sendRedirect --> "+
									authRespdetail.getUrl());

							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", authRespdetail.getUrl());
							response.sendRedirect(authRespdetail.getUrl());

						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}
			} else {
				resp = mTimeoutUrl;
				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", resp);
				response.sendRedirect(resp);
				return;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		MDC.clear();
	}

	private String createSession() {

		String lCreateSessionResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();

			Logging.getLogger().info("mCreSesUrl : " + mCreSesUrl);

			String lAuthStr = mEncDecObj.decrypt(mZomClientID)
					+ "" + mEncDecObj.decrypt(mZomClientSec);
			//String lAuthStr =mZomClientID +  mZomClientSec;


			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

			HttpGet httpget = new HttpGet(mCreSesUrl);
			httpget.setHeader("Authorization", "Basic " + lAuthStr);
			httpget.setHeader("Content-Type", "application/json");
			httpget.setHeader("Accept", "application/json");
			httpget.setHeader("clientId", mZomClientIDen);
			httpget.setHeader("Cache-Control", "no-cache");
			httpget.setConfig(conf);

			CloseableHttpResponse imgresponse = client.execute(httpget);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					lDiscoveryRespStr.append(readLine);
				}
			} else {
				System.out.println(imgresponse);
			}
			lCreateSessionResp = lDiscoveryRespStr.toString();
			Logging.getLogger().info("lCreateSessionResp : " + lCreateSessionResp);
			Logging.getLogger().info("lCreateSessionResp Resp length " + lCreateSessionResp.length());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return lCreateSessionResp;

	}

	private String processIdeNet(String aSourceIP) {

		String lNetIdenResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();

			Logging.getLogger().info("mNetIdeUrl : " + mNetIdeUrl);
			Logging.getLogger().info("aSourceIP : " + aSourceIP);

			String lAuthStr = mEncDecObj.decrypt(mZomClientID)
					+ "" + mEncDecObj.decrypt(mZomClientSec);

			Logging.getLogger().info("lAuthStr : " + lAuthStr);

			//String lAuthStr =mZomClientID +  mZomClientSec;

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

			HttpGet httpget = new HttpGet(mNetIdeUrl + "?mobileIP=" + aSourceIP);
			httpget.setHeader("Authorization", "Basic " + lAuthStr);
			httpget.setHeader("Content-Type", "application/json");
			httpget.setHeader("Accept", "application/json");
			httpget.setHeader("clientId", mZomClientIDen);
			httpget.setHeader("Cache-Control", "no-cache");
			httpget.setConfig(conf);

			CloseableHttpResponse imgresponse = client.execute(httpget);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					lDiscoveryRespStr.append(readLine);
				}
			} else {
				System.out.println(imgresponse);
			}
			lNetIdenResp = lDiscoveryRespStr.toString();
			Logging.getLogger().info("lNetIdenResp : " + lNetIdenResp);
			Logging.getLogger().info("lNetIdenResp Resp length " + lNetIdenResp.length());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return lNetIdenResp;
	}


	@RequestMapping(value="/mobmismatch")
	public @ResponseBody void mobmismatch(HttpServletRequest request, HttpServletResponse response) {

		Logging.getLogger().info("mobmismatch : ");

		RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/mobmismat.jsp");
		request.setAttribute("header", "AShield");
		request.setAttribute("desc1","Please wait, You will receive OTP to authorize secondary device");
		request.setAttribute("footer", "AShield Technologies");

		try {
			rd.forward(request, response);
		} catch (ServletException | IOException e) {
			Logging.getLogger().info("Exception--" + e.getMessage());
		}
	}

	private void getLogErrorMsg(SecureImageResponse authRespdetail, Gson gson, AuthReqDetail authDetail, String statusCode) {
		authRespdetail.setStatusCode(statusCode);
		CDRLogging.getCDRWriter().logCDR(authDetail, "null", statusCode, "NA");
		Logging.getLogger().info("authResp" + gson.toJson(authRespdetail, SecureImageResponse.class));
	}

	private String processAutherize(DiscoveryResponse lDiscRep, HttpServletResponse response) {

		String authurl = lDiscRep.getAuthorizationURL();
		String clientID = lDiscRep.getClient_id();
		String finurl = "";

		try {
			finurl = authurl + "?" + "redirect_uri=" + mRedirectUrl + "&client_id=" + clientID +
					"&scope=openid+mc_attr_vm_share" + "&response_type=code" + "&acr_values=2" + "&state="
					+ lDiscRep.getCpTxnID() + "&nonce=" + lDiscRep.getCpTxnID();

		} catch (Exception e) {
			e.printStackTrace();
		}
		return finurl;
	}

	private String processDiscover(String aBaseAuthstr, String aSourceIP) {

		String lDiscoveryResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();

			HttpPost httpPost=new HttpPost(mDiscoverUrl);
			List<NameValuePair> params = new ArrayList<>();
			params.add(new BasicNameValuePair("Redirect_URL",mRedirectUrl));

			httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));
			httpPost.setHeader("Authorization", "Basic " + aBaseAuthstr);
			httpPost.setHeader("X-Source-ip", aSourceIP);

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);

			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					lDiscoveryRespStr.append(readLine);
				}
			} else {
				//System.out.println(imgresponse);
			}
			lDiscoveryResp = lDiscoveryRespStr.toString();
			Logging.getLogger().info("Web lDiscoveryResp Resp length " + lDiscoveryResp.length());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return lDiscoveryResp;
	}

	private DiscoveryResponse processResp(String aDiscResp) {

		DiscoveryResponse lDiscResp = new DiscoveryResponse();

		try {
			JSONObject lDiscrespJson = new JSONObject(aDiscResp);

			lDiscResp.setTtl(String.valueOf(lDiscrespJson.getInt("ttl")));		
			JSONObject respJson = lDiscrespJson.getJSONObject("response");

			lDiscResp.setClient_id(respJson.getString("client_id"));
			lDiscResp.setClient_secret(respJson.getString("client_secret"));
			lDiscResp.setCountry(respJson.getString("country"));
			lDiscResp.setServing_operator(respJson.getString("serving_operator"));
			lDiscResp.setCurrency(respJson.getString("currency"));

			JSONObject apiJson = respJson.getJSONObject("apis");
			JSONObject operJson = apiJson.getJSONObject("operatorid");
			JSONArray linkarray = operJson.getJSONArray("link");

			for(int i =0; i <linkarray.length(); i++) {
				JSONObject link = linkarray.getJSONObject(i);
				String hosturl = link.getString("href");
				String rela = link.getString("rel");
				if(rela.equals("authorization")) {
					lDiscResp.setAuthorizationURL(hosturl);
				} else if(rela.equals("token")) {
					lDiscResp.setTokenURL(hosturl);
				} else if(rela.equals("issuer")) {
					lDiscResp.setIssuerURL(hosturl);
				} else if(rela.equals("userinfo")) {
					lDiscResp.setUserinfoURL(hosturl);
				}
			}
		}catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		return lDiscResp;
	}

	private AuthReqValidObj validatedevfin(String acpTxnID, String aDeviceFin, 
			String aDevShare, boolean isIphone, boolean multidev, String aShareUrl,
			HttpServletRequest request, HttpServletResponse response) {

		AuthReqValidObj respObj = new AuthReqValidObj();

		AuthShareEntity authEntity = mAuthDbService.getByNewtxnID(acpTxnID);

		if(authEntity != null) {

			String share3 = ""; //getShareVal(acpTxnID, aShareUrl, request, response);

			long startTime_url = System.currentTimeMillis();
			Logging.getLogger().info("Share from url: " + share3);
			Logging.getLogger().info("Share URL fetch ElapsedTime: "+(System.currentTimeMillis()-startTime_url));

			String share1 = authEntity.getShare1();
			String share2 = authEntity.getShare2();
			String msisdn = authEntity.getMsisdn();
			String opn = authEntity.getOpn();
			String mID = authEntity.getMid();
			boolean authed = authEntity.isAuthed();

			if(TextUtils.isEmpty(share3)) {
				share3 = authEntity.getShare3();
			}

			respObj.setStatus(authed);	

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", opn);

			if(!authed) {
				authEntity.setAuthed(true);
				mAuthDbService.saveShare(authEntity);
			}

			String decShare1 = "";
			String decShare2 = "";
			String decShare3 = "";
			String condecshare = "";

			try {

				String decMsisdn = mEncDecObj.decrypt(msisdn , isIphone);
				
				AuthMobDFEntity mModData = mAuthDbService.getByMsisdn(decMsisdn + mID);

				if(mModData != null) {
					Logging.getLogger().info("msisdn def :" + mModData.getDevicefin());
				}

				decShare1 =  mEncDecObj.decrypt(share1, isIphone /*, mEncDecObj.decrypt(mEncKey1)*/);
				decShare2 =  mEncDecObj.decrypt(share2, isIphone /*, mEncDecObj.decrypt(mEncKey2)*/);
				decShare3 =  mEncDecObj.decrypt(share3, isIphone /*, mEncDecObj.decrypt(mEncKey3)*/);
				String decr = decShare1 + decShare2 + decShare3;
				condecshare =  mEncDecObj.decrypt(decr, isIphone /*, mEncDecObj.decrypt(mEncKey4)*/);


				String txnidLen = condecshare.substring(condecshare.length()-2, condecshare.length());

				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(txnidLen) - 2);

				String msisdnlen = condecshare.substring(condecshare.length()-2, condecshare.length());

				String msisdnshre = condecshare.substring(condecshare.length() - Integer.valueOf(msisdnlen), 
						condecshare.length()-2);

				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(msisdnlen) - 2);

				Logging.getLogger().info("multidev :" + multidev);
				Logging.getLogger().info("aDeviceFin :" + aDeviceFin);
				Logging.getLogger().info("aDevShare :" + aDevShare);
				Logging.getLogger().info("share1 :" + share1);
				Logging.getLogger().info("condecshare :" + condecshare);

				if ((multidev || (mModData != null && mModData.getDevicefin().contentEquals(aDeviceFin)))&& 
						aDevShare.contentEquals(share1)  &&  condecshare.contentEquals(aDeviceFin)) {
					respObj.setMsisdn(mEncDecObj.decrypt(msisdn, isIphone));
					Logging.getLogger().info("validatedevfin :" + mEncDecObj.encrypt(respObj.getMsisdn(), isIphone));
				} else  {
					respObj.setMsisdn("");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		} else {
			Logging.getLogger().info("authEntity : null for txnID :" + acpTxnID);
		}
		return respObj;		
	}

	private void generateshare(String lDevicefin, String lMsisdn, String newTxnID, String lRedirectUrl, 
			String lOpn, HttpServletResponse response, String aTransID, String imgRespRes, String aMID,
			HttpServletRequest request) {

		try {

			String redirectUrl = "";

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			if(imgRespRes.contentEquals("YES")) {				

				String tlen = "";
				String mlen = "";

				if(aTransID.length() < 10) {
					tlen = "0" + aTransID.length();
				} else {
					tlen = "" + aTransID.length();
				}

				if(lMsisdn.length() < 10) {
					mlen = "0" + lMsisdn.length();
				} else {
					mlen = "" + lMsisdn.length();
				}


				String encval = lDevicefin + lMsisdn + mlen + aTransID + tlen;

				String mEncDf = mEncDecObj.encrypt(encval, authReqDetail.isIPhone() /*, mEncDecObj.decrypt(mEncKey4)*/);
				Logging.getLogger().info("generateshare:" + "mEncDf: " + mEncDf);


				int len =  mEncDf.length();

				int devlength = len/3;

				String s1 = mEncDf.substring(0,devlength-1);
				String s2 = mEncDf.substring(devlength -1 , 2*devlength-1);
				String s3 = mEncDf.substring(2*devlength -1 , len);

				String EncString1 = "";
				String EncString2 = "";
				String EncString3 = "";
				try {
					EncString1 = mEncDecObj.encrypt(s1, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey1) */);
					EncString2 = mEncDecObj.encrypt(s2, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey2) */);
					EncString3 = mEncDecObj.encrypt(s3, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey3) */);
				} catch (Exception e) {
					e.printStackTrace();
				}

				Logging.getLogger().info("Crypto Share 1 : " + EncString1);
				Logging.getLogger().info("Crypto Share 2 : " + EncString2);
				Logging.getLogger().info("Crypto Share 3 : " + EncString3);

				AuthShareEntity mEntity = new AuthShareEntity();

				mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn,authReqDetail.isIPhone()));
				mEntity.setDevicefin(lDevicefin);
				mEntity.setNewtxnid(newTxnID);
				mEntity.setShare1(EncString1);
				mEntity.setShare2(EncString2);
				mEntity.setShare3(EncString3);
				mEntity.setTxnid(aTransID);
				mEntity.setMertxnid(authReqDetail.getMerTxnID());
				mEntity.setOpn(lOpn);
				mEntity.setMid(aMID);
				mEntity.setAuthed(false);


				AuthMobDFEntity mMobEntity = new AuthMobDFEntity();

				mMobEntity.setMsisdn(lMsisdn + aMID);
				mMobEntity.setMid(aMID);
				mMobEntity.setDevicefin(lDevicefin);
				mMobEntity.setChannel(authReqDetail.getChannel());

				mAuthDbService.saveDf(mMobEntity);

				//mAuthsharedbrepoImpl.saveauthsharetodb(mEntity);
				mAuthDbService.saveShare(mEntity);

				authReqDetail.setNewTxnID(newTxnID);

				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

				boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
						aTransID + "chan") != null && mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
								aTransID + "chan").equals("wap");

				AuthWebResp resp = new AuthWebResp();			

				if(wap) {				
					String shareval = newTxnID.length() + newTxnID + EncString1;				
					Logging.getLogger().info("**shareval--> " + shareval );
					String encshare = mEncDecObj.encrypt(shareval);

					Cookie cookie = new Cookie("authshare", encshare);
					cookie.setDomain(System.getenv("DOMAIN_NAME"));
					cookie.setPath(request.getContextPath());
					cookie.setMaxAge(60*60*24*30);
					response.addCookie(cookie);

					resp.setStatus(SUCCESS);
					resp.setToken(newTxnID);
					resp.setTxnID(authReqDetail.getMerTxnID());
					resp.setMsisdn(mEncDecObj.encrypt(lMsisdn));

					String reqTime = CommonHelper.getFormattedDateString();

					String message = "WEBASHIELD"+newTxnID+"#"+reqTime;				
					redisMessagePublisher.publish(message);

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", aTransID);

					mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

					redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS 
							+ "&mertxnid=" + authReqDetail.getMerTxnID();

				} else {

					CDRLogging.getCDRWriter().logCDR(authReqDetail, 
							mEncDecObj.encrypt(lMsisdn,authReqDetail.isIPhone()), SUCCESS, imgRespRes);

					redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn,authReqDetail.isIPhone()) + "&txnid=" + 
							newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result=" + imgRespRes + 
							"&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn=" + lOpn +
							"&secmsisdn=" + mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone());;
							//mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
							deleteredis(aTransID);
				}

				//saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

				sendClientResp(aTransID, authReqDetail.getMerTxnID(),  SUCCESS, lMsisdn, authReqDetail.getSecMsisdn());			

				MDC.clear();
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", redirectUrl);
				response.setHeader("Connection", "close");
				response.sendRedirect(redirectUrl);	
			} else {

				boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
						aTransID + "chan") != null && mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
								aTransID + "chan").equals("wap");

				String respval = USER_CANCLED;

				if(imgRespRes.contentEquals("Timeout")) {
					respval = SESSION_TIME_OUT;
				}

				if(wap) {	
					Cookie cookie = new Cookie("authshare", "");
					cookie.setDomain(System.getenv("DOMAIN_NAME"));
					cookie.setPath(request.getContextPath());
					cookie.setMaxAge(0);
					response.addCookie(cookie);
					redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + respval
							+ "&mertxnid=" + authReqDetail.getMerTxnID();
				} else {

					CDRLogging.getCDRWriter().logCDR(authReqDetail, 
							mEncDecObj.encrypt(lMsisdn,authReqDetail.isIPhone()), respval, imgRespRes);

					redirectUrl = lRedirectUrl + "msisdn=" +  
							mEncDecObj.encrypt(lMsisdn ,authReqDetail.isIPhone())
					+ "&txnid=" + "0" + "&status=" + respval + "&eshare=" + "" + "&result=" +
					imgRespRes + "&mtxnid=" + authReqDetail.getMerTxnID() + 
					"&atxnid=" + aTransID + "&opn=" + lOpn;
					//mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
					deleteredis(aTransID);
				}
				MDC.clear();
				response.setHeader("Location", redirectUrl);
				response.setHeader("Connection", "close");
				response.sendRedirect(redirectUrl);
			}
		}catch(Exception e) {
			e.printStackTrace();
		}
	}

	private boolean sendotpmsg(String txt, String mobilenum, String url) {

		String message ="Your OTP is " + txt + " This OTP is valid only for 10 minutes";
		StringBuilder imageStr = new StringBuilder();
		try {
			HttpPost httpPost = null;

			if(TextUtils.isEmpty(url)) {
				httpPost = new HttpPost(mSendOTPUrl);
				url = mSendOTPUrl;
			} else {
				httpPost = new HttpPost(url);
			}

			List<NameValuePair> params = new ArrayList<>();
			if(url.contains(SMS_COUNTRY)) {
				params.add(new BasicNameValuePair("User", "JunoTele"));                                             
				params.add(new BasicNameValuePair("Passwd", "Jun0@SMSC"));                                               
				params.add(new BasicNameValuePair("Sid", "ASHELD"));                                      
				params.add(new BasicNameValuePair("Mobilenumber", mobilenum));
				params.add(new BasicNameValuePair("Message", message));
				params.add(new BasicNameValuePair("Mtype", "N"));
				params.add(new BasicNameValuePair("DR", "Y"));
			} else if(url.contains(BRILIENT)) {
				message ="Your confidential one time password for mobile number authentication is " + txt 
						+ ", valid for 3 min. Do not share this OTP to anyone for security reasons";
				params.add(new BasicNameValuePair("action", "send-sms"));                                             
				params.add(new BasicNameValuePair("api_key", "QVNoaWVsZDpAYXNoaWVsdiZ0eQ=="));                                               
				params.add(new BasicNameValuePair("from", "8809638097774"));                                      
				params.add(new BasicNameValuePair("to", mobilenum));
				params.add(new BasicNameValuePair("sms", message));
			}

			httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
				Logging.getLogger().info("send sms resp : " + imageStr.toString());
				return true;
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);	
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private String sendShare(String aTransID, HttpServletRequest request, HttpServletResponse response) {

		String lDevicefin = "";
		String lMsisdn = "0";

		try {
			String newTxnID = getTransID();

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");

			lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "df");
			lMsisdn =  mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			Logging.getLogger().info("sendShare:" + "lDevicefin: " + mEncDecObj.encrypt(lDevicefin));

			String tlen = "", mlen = "";

			if(aTransID.length() < 10) {
				tlen = "0" + aTransID.length();
			} else {
				tlen = "" + aTransID.length();
			}

			if(lMsisdn.length() < 10) {
				mlen = "0" + lMsisdn.length();
			} else {
				mlen = "" + lMsisdn.length();
			}			

			String encval = lDevicefin + lMsisdn + mlen + aTransID + tlen;

			Logging.getLogger().info("encval:" + encval);

			String mEncDf = mEncDecObj.encrypt(encval, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey4) */);
			Logging.getLogger().info("sendShare:" + "mEncDf: " + mEncDf);

			int len =  mEncDf.length();

			int devlength = len/3;

			String s1 = mEncDf.substring(0,devlength-1);
			String s2 = mEncDf.substring(devlength -1 , 2*devlength-1);
			String s3 = mEncDf.substring(2*devlength -1 , len);

			String EncString1 = "";
			String EncString2 = "";
			String EncString3 = "";
			try {
				EncString1 = mEncDecObj.encrypt(s1, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey1) */);
				EncString2 = mEncDecObj.encrypt(s2, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey2) */);
				EncString3 = mEncDecObj.encrypt(s3, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey3) */);
			} catch (Exception e) {
				e.printStackTrace();
			}

			Logging.getLogger().info("Crypto Share 1 : " + EncString1);
			Logging.getLogger().info("Crypto Share 2 : " + EncString2);
			Logging.getLogger().info("Crypto Share 3 : " + EncString3);

			AuthShareEntity mEntity = new AuthShareEntity();

			mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn,authReqDetail.isIPhone()));
			mEntity.setDevicefin(lDevicefin);
			mEntity.setNewtxnid(newTxnID);
			mEntity.setShare1(EncString1);
			mEntity.setShare2(EncString2);
			mEntity.setShare3(EncString3);
			mEntity.setTxnid(aTransID);
			mEntity.setMertxnid(authReqDetail.getMerTxnID());
			mEntity.setOpn(lOpn);
			mEntity.setMid(authReqDetail.getCpID());
			mEntity.setAuthed(false);

			//mAuthsharedbrepoImpl.saveauthsharetodb(mEntity);
			mAuthDbService.saveShare(mEntity);

			authReqDetail.setNewTxnID(newTxnID);

			boolean isVPNClient = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
					aTransID + "vpn") != null && mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
							aTransID + "vpn").equals("YES");

			Logging.getLogger().info("isVPNClient : " + isVPNClient + ", authReqDetail.isVpnflag() :" + authReqDetail.isVpnflag());

			if(authReqDetail.isVpnflag() && isVPNClient) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "vpn");

				if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(lMsisdn + "vpnreq") != null) {
					authReqDetail.setVpnServerReq(SUCCESS);
					String reqTime = CommonHelper.getFormattedDateString();

					String message = "VPNASHIELD"+lMsisdn+"#"+reqTime;			
					redisMessagePublisher.publish(message);

					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(lMsisdn + "vpnres", 
							authReqDetail);
				} else {
					Logging.getLogger().info("NO_VPN_DATA");
					authReqDetail.setVpnServerReq(NO_VPN_DATA);
				}
			}

			CDRLogging.getCDRWriter().logCDR(authReqDetail, mEncDecObj.encrypt(lMsisdn,authReqDetail.isIPhone()), SUCCESS, "YES");

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
					aTransID + "chan") != null && mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(
							aTransID + "chan").equals("wap");

			Logging.getLogger().info("wap :" + wap);
			String redirectUrl = "";

			mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(newTxnID + "req", authReqDetail);

			String displayImgUrl = mGetImgUrl + "?mTxnID=" + newTxnID + "&mID=" + 
					authReqDetail.getCpID();

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "df", lDevicefin);
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "mn", lMsisdn);
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "rdu", lRedirectUrl);

			mWebDesignParamRepoImpl.saveToWebDesignparamRepo(newTxnID + "web", 
					mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web"));

			Logging.getLogger().info("sendShare msisdnObj.getMsisdn(): " + lMsisdn);
			Logging.getLogger().info("sendShare authReqDetail.getPrimMsisdn(): " + 
					mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()));

			String lMob = lMsisdn;
			if(lMsisdn.length() != 10) {
				lMob = lMob.substring(2, lMob.length());
			}

			if(wap) {
				String shareval = newTxnID.length() + newTxnID + EncString1;				
				Logging.getLogger().info("**shareval--> " + shareval );
				String encshare = mEncDecObj.encrypt(shareval);

				Cookie cookie = new Cookie("authshare", encshare);
				cookie.setDomain(System.getenv("DOMAIN_NAME"));
				cookie.setPath(request.getContextPath());
				cookie.setMaxAge(60*60*24*30);
				response.addCookie(cookie);				

				if(!lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {
					deleteredis(aTransID);
					deleteredis(newTxnID);
					redirectUrl = mMobmismatUrl;
				} else  {
					redirectUrl = displayImgUrl;			
				}
			} else {

				if(!lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {
					displayImgUrl =  mMobmismatUrl + "?mTxnID=" + newTxnID + "&mID=" + 
							authReqDetail.getCpID();
					deleteredis(aTransID);
					deleteredis(newTxnID);
				}

				redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone())
				+ "&txnid=" + newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result=" +
				"YES" + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn=" + lOpn +  
				"&secmsisdn=" + mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone()) + 
				"&dispimg=" + displayImgUrl;
			}		

			//saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

			//sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SUCCESS);

			Logging.getLogger().info("redirectUrl : " + redirectUrl);

			return redirectUrl;
		}catch (Exception e) {
			e.printStackTrace();
			MDC.clear();
			return null;
		}
	}

	private void deleteredis(String aTransID) {

		if(mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req") != null) {
			mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "dffin") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "dffin");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "opn");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "chan");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "rdu");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "mn");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "action");
		}

		if(mMCDiscoverRespRespoImpl.getValueFromAshiledMCRedisRepo(aTransID + "_MC") != null) {
			mMCDiscoverRespRespoImpl.deleteValueFromAshiledMCRedisRepo(aTransID + "_MC");
		}

		if(mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web") != null) {
			mWebDesignParamRepoImpl.deleteValueFromWebDesignparamRepo(aTransID + "web");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "seskey") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "seskey");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "refid") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "refid");
		}

		if(mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "locret") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "locret");
		}
	}

	private void sendClientResp(String txnID, String mertxnID, String resp, String pmdn, String smdn) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		TxnResp mResp = new TxnResp();

		StringBuilder imageStr = new StringBuilder();
		mResp.setStatus(resp!=null?resp:"0");
		mResp.setMertxnid(mertxnID!=null?mertxnID:"null");
		mResp.setPmdn(pmdn!=null?pmdn:"0");
		mResp.setSmdn(smdn!=null?smdn:"0");
		mResp.setAstxnid(txnID!=null?txnID:"0");

		String resps = gson.toJson(mResp);
		try {
			if(authReqDetail != null) {
				String clientUrl = authReqDetail.getClientURl();

				if(clientUrl != null) {

					Logging.getLogger().info("ClientURl : " + clientUrl);
					Logging.getLogger().info("ClientURl resp: " + resps);

					CloseableHttpClient client = HttpClients.createDefault();
					CloseableHttpResponse imgresponse = null;

					RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
							setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

					if (authReqDetail.getCpID().contentEquals("024")) {

						StringBuilder UrlBuilder = new StringBuilder();

						UrlBuilder.append(clientUrl);
						UrlBuilder.append("uniqueCode=");
						UrlBuilder.append(mertxnID!=null?mertxnID:"null");
						UrlBuilder.append("&mobileNumber=");
						UrlBuilder.append(pmdn!=null?pmdn:"0");
						UrlBuilder.append("&virtualMobileNo=");
						UrlBuilder.append(txnID!=null?txnID:"0");

						String httpURl = UrlBuilder.toString();

						HttpGet httpget = new HttpGet(httpURl);						

						httpget.setConfig(conf);

						imgresponse = client.execute(httpget);

					} else {
						HttpPost httpPost=new HttpPost(clientUrl);

						StringEntity mEntity = new StringEntity(resps);
						httpPost.setEntity(mEntity);
						httpPost.setHeader("Content-Type", "application/json");
						httpPost.setHeader("Accept", "application/json");

						//List<NameValuePair> params = new ArrayList<>();
						//params.add(new BasicNameValuePair("resp", resps)); 

						//httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));

						httpPost.setConfig(conf);

						imgresponse = client.execute(httpPost);
					}
					if (imgresponse.getStatusLine().getStatusCode() == 200) {
						BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
						String readLine;
						while (((readLine = br.readLine()) != null)) {
							imageStr.append(readLine);
						}
					} else {
						Logging.getLogger().error(imgresponse.toString());
						System.out.println(imgresponse);	
					}
					Logging.getLogger().info("sendclientresp : " + imageStr.toString());
				} else {
					Logging.getLogger().info("sendclientresp : " + "Client Url not set");
				}
			} else {
				Logging.getLogger().info("sendclientresp : " + "Client Url not set");
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private void saveShareVal(AuthReqDetail authReqDetail, String newTxnID, String encString1, 
			HttpServletRequest request, HttpServletResponse response) {

		StringBuilder imageStr = new StringBuilder();

		try {

			String lSaveShareUrl = authReqDetail.getShareurl() + "/setShare";

			HttpPost httpPost=new HttpPost(lSaveShareUrl);
			//HttpPost httpPost=new HttpPost(mSaveShareUrl);
			List<NameValuePair> params = new ArrayList<>();

			params.add(new BasicNameValuePair("mid", authReqDetail.getCpID()));
			params.add(new BasicNameValuePair("txnId", newTxnID));
			params.add(new BasicNameValuePair("share", encString1));

			httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);	
			}
			Logging.getLogger().info("saveShareVal : " + imageStr.toString());			

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String getShareVal(String newTxnID , String aShareUrl, HttpServletRequest request, 
			HttpServletResponse response) {

		StringBuilder imageStr = new StringBuilder();

		try {

			String lGetShareUrl = aShareUrl + "/getShare";

			HttpPost httpPost=new HttpPost(lGetShareUrl);

			//HttpPost httpPost=new HttpPost(mGetShareUrl);
			List<NameValuePair> params = new ArrayList<>();

			params.add(new BasicNameValuePair("txnId", newTxnID));

			httpPost.setEntity(new UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout).
					setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);	
			}
			Logging.getLogger().info("getShareVal : " + imageStr.toString());			

		} catch (Exception e) {
			e.printStackTrace();
		}
		return imageStr.toString();
	}

}
