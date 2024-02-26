package com.ashield.webapps;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Timer;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
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
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.TextUtils;
import org.apache.log4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.ashield.datapojo.AppBotRequest;
import com.ashield.datapojo.AccountInfoEntity;
import com.ashield.datapojo.AuthMobDFEntity;
import com.ashield.datapojo.AuthReqDetail;
import com.ashield.datapojo.AuthReqValidObj;
import com.ashield.datapojo.AuthShareEntity;
import com.ashield.datapojo.AuthWebResp;
import com.ashield.datapojo.DiscoveryResponse;
import com.ashield.datapojo.ImageValidationResponse;
import com.ashield.datapojo.ImgKeyEntity;
import com.ashield.datapojo.MobResp;
import com.ashield.datapojo.OptVebdorEntity;
import com.ashield.datapojo.SecureImageResponse;
import com.ashield.datapojo.SignKeyEntity;
import com.ashield.datapojo.TxnResp;
import com.ashield.datapojo.WebDesignParam;
import com.ashield.dbservice.DbService;
import com.ashield.logThread.CDRLoggingThread;
import com.ashield.logThread.LoggingThread;
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

@CrossOrigin
@Controller
public class AuthWebControler implements Constants {

	@Autowired
	AshieldEncDec mEncDecObj;

	@Autowired
	DbService mAuthDbService;

	@Autowired
	AuthTransactionIDRepoImpl mMCTrackTransRespoImpl;

	@Autowired
	MCDiscoverRespRespoImpl mMCDiscoverRespRespoImpl;

	@Autowired
	RedisMessagePublisher redisMessagePublisher;

	@Autowired
	WebDesignparamRepoImpl mWebDesignParamRepoImpl;

	@Autowired
	AuthReqTransactionIDRepoImpl mReqTrackTransRespoImpl;

	@Autowired
	AuthwebRespTokenRepoImpl mTokenRespRepoImpl;

	@Value("${ashield.authreq.valid.time}")
	String mValidTime;

	@Value("${ashield.enc.key1}")
	String mEncKey1;

	@Value("${ashield.enc.key2}")
	String mEncKey2;

	@Value("${ashield.enc.key3}")
	String mEncKey3;

	@Value("${ashield.enc.key4}")
	String mEncKey4;

	@Value("${ashield.discover.url}")
	String mDiscoverUrl;

	@Value("${ashield.redirect.url}")
	String mRedirectUrl;

	@Value("${ashield.zom.redirect.url}")
	String mZomRedirectUrl;

	@Value("${ashield.mobcon.clientid}")
	String mMCClientID;

	@Value("${ashield.mobcon.clientsec}")
	String mMCClientSec;

	@Value("${mchttpTimeout}")
	int mcHttpTimeout;

	@Value("${ashield.imgSize}")
	String mImgSize;

	@Value("${ashield.getimg.url}")
	String mImageReqUrl;

	@Value("${ashield.chkimg.url}")
	String mChkImgReqUrl;

	@Value("${ashield.sendotp.intern.url}")
	String mSendOTPUrl;

	@Value("${ashield.authbot.url}")
	String mAuthBotUrl;

	@Value("${ashield.saveshare.url}")
	String mSaveShareUrl;

	@Value("${ashield.getshare.url}")
	String mGetShareUrl;

	@Value("${ashield.multi.auth.time}")
	int mMultiAuthTimeout;

	@Value("${ashield.session.time}")
	int mSessionTimeout;

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

	@Value("${ashield.dispimg.url}")
	String mImageDispUrl;

	@Value("${ashield.appbot.appid}")
	String mAuthAppBotmid;

	@Value("${ashield.appbot.appidkey}")
	String mAuthAppBotkey;

	@Value("${ashield.authappbot.url}")
	String mAuthAppBotUrl;

	private List<String> mSBuaList;

	Gson gson = new Gson();

	@RequestMapping(value = "/web-authen")
	public @ResponseBody void WebAuthenticate(@RequestParam("mertxnid") String mertxnID,
			@RequestParam("mid") String mID, @RequestParam("ts") String timestamp,
			@RequestParam(value = "authtype", required = false) String authtype,
			@RequestParam(value = "redurl", required = false) String aRedURl, @RequestParam("sign") String signature,
			HttpServletRequest request, HttpServletResponse response) {

		long startTime = System.currentTimeMillis();
		MDC.put(LOG4J_MDC_TOKEN, mertxnID);

		String headerName = null;
		String headerValue = null;
		String userAgent = "";
		String deviceFin = "";
		String accept = "";
		String ipAddress = "";

		try {
			String dataHashed = mID + mertxnID + timestamp;

			LoggingThread lt1 = new LoggingThread("[" + mertxnID + "]" + "WebAuthenticate " + " starttime: " + startTime
					+ " mID:" + mID + " mertxnID:" + mertxnID + " timestamp: " + timestamp + " authtype:" + authtype
					+ " aRedURl:" + aRedURl + " hash: " + signature + " ** hashstring: " + dataHashed);
			lt1.start();
//			Logging.getLogger()
//					.info("WebAuthenticate " + " starttime: " + startTime + " mID:" + mID + " mertxnID:" + mertxnID
//							+ " timestamp: " + timestamp + " authtype:" + authtype + " aRedURl:" + aRedURl + " hash: "
//							+ signature + " ** hashstring: " + dataHashed);

			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				LoggingThread lt2 = new LoggingThread(
						"[" + mertxnID + "]" + "**HEADER --> " + headerName + " : " + headerValue);
				lt2.start();
				// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
			}

			String reqTime = CommonHelper.getFormattedDateString();

			SecureImageResponse authRespdetail = new SecureImageResponse();
			authRespdetail.setMerTxnID(mertxnID);

			AuthReqDetail authReqDetail = new AuthReqDetail();

			authReqDetail.setCpID(mID);
			authReqDetail.setStartTime(reqTime);
			authReqDetail.setMerTxnID(mertxnID);
			authReqDetail.setCpRdu(aRedURl);
			authReqDetail.setSimcount(2);
			authReqDetail.setChannel("wap");
			authReqDetail.setAuthorize(false);

			String operatorSecretKey = "";
			String lRdUrl = "";
			long startTime_db = System.currentTimeMillis();

			SignKeyEntity signEnt = mAuthDbService.getByMid(mID);

			ImgKeyEntity imgEnt = mAuthDbService.getImgByMid(mID);

			AccountInfoEntity accEnt = mAuthDbService.getByCustomerID(mID);

			String encKey = "";
			if (accEnt != null) {
				encKey = accEnt.getApiKey();
				// operatorSecretKey = mEncDecObj.decrypt(encKey);
				operatorSecretKey = accEnt.getApiKey();
				authReqDetail.setSeckey(operatorSecretKey);

				LoggingThread lt3 = new LoggingThread("[" + mertxnID + "]" + "OrgID Key found : " + encKey);
				lt3.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
			} else {
				LoggingThread lt4 = new LoggingThread("[" + mertxnID + "]" + "INVALID: mertxnID ");
				lt4.start();
				// Logging.getLogger().info("INVALID: mertxnID ");
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sendResponse(authReqDetail, INVALID_CPID, INVALID_TOKEN, request, response);
				return;
			}

			if (signEnt != null) {

				authReqDetail.setMulitdevice(signEnt.isMultiDevice());

				// authReqDetail.setDemography(signEnt.isDemography());
				authReqDetail.setDemography(false);

				authReqDetail.setOtpflow(signEnt.isEnableOtpFlow());
				authReqDetail.setClientURl(signEnt.getIdentityCallbackUrl());
				authReqDetail.setCliOtp(!signEnt.isGenerateOtp());

				// authReqDetail.setNoconsent(signEnt.isNoconsent());
				authReqDetail.setNoconsent(false);

				// set this url
				/*
				 * authReqDetail.setDiUrl(signEnt.getDiurl());
				 * authReqDetail.setShareurl(signEnt.getShareurl());
				 * authReqDetail.setSmsurl(signEnt.getSmsurl());
				 */

				LoggingThread lt5 = new LoggingThread("[" + mertxnID + "]" + "OrgID Key found : " + encKey);
				lt5.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
			} else {
				LoggingThread lt6 = new LoggingThread("[" + mertxnID + "]" + "INVALID: mertxnID ");
				lt6.start();
				// Logging.getLogger().info("INVALID: mertxnID ");
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sendResponse(authReqDetail, INVALID_CPID, INVALID_TOKEN, request, response);
				return;
			}

			LoggingThread lt7 = new LoggingThread(
					"[" + mertxnID + "]" + "DB Fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_db));
			lt7.start();
			// Logging.getLogger().info("DB Fetch ElapsedTime: " +
			// (System.currentTimeMillis() - startTime_db));

			if (TextUtils.isEmpty(mertxnID)) {
				LoggingThread lt8 = new LoggingThread("[" + mertxnID + "]" + "INVALID: mertxnID ");
				lt8.start();
				// Logging.getLogger().info("INVALID: mertxnID ");
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
				sendResponse(authReqDetail, INVALID_CPTXNID, INVALID_TOKEN, request, response);
				return;
			}

			if (!TextUtils.isEmpty(aRedURl)) {
				if (!aRedURl.contains(lRdUrl)) {
					LoggingThread lt9 = new LoggingThread("[" + mertxnID + "]" + "INVALID: aRedURl ");
					lt9.start();
					// Logging.getLogger().info("INVALID: aRedURl ");
					getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPRDU);
					sendResponse(authReqDetail, INVALID_CPRDU, INVALID_TOKEN, request, response);
					return;
				}
			}

			if (!validateSignature(operatorSecretKey, signature, dataHashed)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SIGN);
				sendResponse(authReqDetail, INVALID_SIGN, INVALID_TOKEN, request, response);
				return;
			}

			ipAddress = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			userAgent = request.getHeader("user-agent") == null ? "null" : request.getHeader("user-agent");
			accept = request.getHeader("accept") == null ? "null" : request.getHeader("accept");

			String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null ? request.getHeader("X-FORWARDED-FOR")
					: "null";

			if (!xforwardedIP.contains("null")) {
				ipAddress = xforwardedIP;
			}

			if (TextUtils.isEmpty(userAgent) || (mSBuaList != null && mSBuaList.indexOf(userAgent) == -1)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
				sendResponse(authReqDetail, INVALID_SRC, INVALID_TOKEN, request, response);
				return;
			}

			authReqDetail.setBua(userAgent);
			authReqDetail.setMip(xforwardedIP);

			LoggingThread lt10 = new LoggingThread("[" + mertxnID + "]" + "ipAddress - " + ipAddress + ", userAgent-"
					+ userAgent + ", accept-" + accept);
			lt10.start();
			// Logging.getLogger().info("ipAddress - " + ipAddress + ", userAgent-" +
			// userAgent + ", accept-" + accept);

			long reqtimediff = startTime - Long.parseLong(timestamp);
			// Logging.getLogger().info("Time Difference is - " + reqtimediff);
			long minutes = TimeUnit.MILLISECONDS.toMinutes(reqtimediff);
			// Logging.getLogger().info("Time Difference in min - " + minutes);

			LoggingThread lt11 = new LoggingThread("[" + mertxnID + "]" + "Time Difference is - " + reqtimediff
					+ ", Time Difference in min - " + minutes);
			lt11.start();

			if (minutes > Integer.parseInt(mValidTime)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
				sendResponse(authReqDetail, INVALID_SRC, INVALID_TOKEN, request, response);
				return;
			}

			String browserAgent = request.getHeader("user-agent");
			String mobileIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			String acpt = request.getHeader("accept") != null ? request.getHeader("accept") : "null";
			String msisdn = "null";
			String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
			String xRequestedWithReferer = request.getHeader("x-requested-with") != null
					? request.getHeader("x-requested-with")
					: "null";

			String botResp = getBotAnalyze(mertxnID, mobileIp, msisdn, browserAgent, mID, acpt, referer,
					xRequestedWithReferer, "wap");

			String appbotkey = mEncDecObj.decrypt(mAuthAppBotkey, false);

			if (!botResp.contentEquals(DEFAULT_RESP)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, BLOCK);
				sendResponse(authReqDetail, BLOCK, INVALID_TOKEN, request, response);
				return;
			}

			String mCookieValue = "";
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				for (Cookie c : cookies) {
					if (c.getName().equals("authshare")) {
						mCookieValue = c.getValue();
					}
				}
			}
			LoggingThread lt12 = new LoggingThread("[" + mertxnID + "]" + " mCookieValue:" + mCookieValue);
			lt12.start();
			// Logging.getLogger().info(" mCookieValue:" + mCookieValue);

			String asTxnID = "";
			String asShare = "";

			if (!TextUtils.isEmpty(mCookieValue)) {
				mCookieValue = mEncDecObj.decrypt(mCookieValue);
				String txnlenght = mCookieValue.substring(0, 2);
				asTxnID = mCookieValue.substring(2, Integer.parseInt(txnlenght) + 2);
				asShare = mCookieValue.substring(2 + Integer.parseInt(txnlenght), mCookieValue.length());

				LoggingThread lt13 = new LoggingThread("[" + mertxnID + "]" + "txnlenght - " + txnlenght + "asTxnID - "
						+ asTxnID + ", share-" + asShare);
				lt13.start();
				// Logging.getLogger().info("txnlenght - " + txnlenght + "asTxnID - " + asTxnID
				// + ", share-" + asShare);
			}
			deviceFin = userAgent + accept;

			getAPPBotAnalyze(mertxnID, mobileIp, msisdn, browserAgent, mAuthAppBotmid, acpt, referer,
					xRequestedWithReferer, "wap", deviceFin, appbotkey);

			if (authtype != null && authtype.contains("CN")) {
				authtype = "NO";
			} else {
				authtype = "YES";
			}

			if (TextUtils.isEmpty(asTxnID)) {
				asTxnID = getTransID();
			}

			authReqDetail.setCpTxnID(asTxnID);
			authReqDetail.setDevshare(asShare);
			authReqDetail.setDf(mEncDecObj.encrypt(deviceFin));

			authRespdetail.setOptxn(asTxnID);

			WebDesignParam webparam = new WebDesignParam();

			if (webparam != null) {
				webparam.setCpID(mID);
				webparam.setCpTxnID(asTxnID);
				webparam.setDesdata1(TextUtils.isEmpty(signEnt.getCpSubheader())
						? "Authenticate your Mobile Number, Which is displayed on the image"
						: signEnt.getCpSubheader());
				webparam.setDesdata2(TextUtils.isEmpty(signEnt.getCpBodyText())
						? "Please click on YES to confirm your mobile number and accept terms and conditions"
						: signEnt.getCpBodyText());
				webparam.setDesotp1(TextUtils.isEmpty(signEnt.getOpSubHeader())
						? "Authenticate your Mobile Number, Which is displayed on the image"
						: signEnt.getOpSubHeader());
				webparam.setDesotp2(TextUtils.isEmpty(signEnt.getOpBodyText())
						? "Please click on OTP to confirm your mobile number and accept terms and conditions"
						: signEnt.getOpBodyText());
				webparam.setDeswifi1("Enter Mobile Number");
				webparam.setDeswifi2("Click 'Submit' to Process");
				webparam.setFtext(
						TextUtils.isEmpty(signEnt.getCpFooter()) ? "Powered By Ashield" : signEnt.getCpFooter());
				webparam.setHcolor("#000000");
				webparam.setHtext(TextUtils.isEmpty(signEnt.getCpHeader()) ? "Ashield" : signEnt.getCpHeader());
				webparam.setMclkflag(signEnt.isCpEnableMultiClick());
				webparam.setWififlag(signEnt.isEnableOtpFlow());
				webparam.setLogoimg("");
				webparam.setAvtimg("");

				if (imgEnt != null) {
					if (imgEnt.getImgstr() != null) {
						// webparam.setImgstr(Base64.getEncoder().encodeToString(imgEnt.getImgstr().getData()));
						webparam.setImgstr(Base64.getEncoder().encodeToString(imgEnt.getImgstr().getBytes()));
					}

					if (imgEnt.getGifstr() != null) {
						// webparam.setGifstr(Base64.getEncoder().encodeToString(imgEnt.getGifstr().getData()));
						webparam.setGifstr(Base64.getEncoder().encodeToString(imgEnt.getGifstr().getBytes()));
					}
				}
			}

			mWebDesignParamRepoImpl.saveToWebDesignparamRepo(asTxnID + "web", webparam);

			processTrnID(authReqDetail, authRespdetail, ipAddress, authtype, request, response);

			MDC.clear();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@RequestMapping(value = "/fetchmdn")
	public @ResponseBody void fetchMsisdn(@RequestParam("mertxnid") String mertxnID, @RequestParam("mid") String mID,
			@RequestParam("ts") String timestamp, @RequestParam("sign") String signature, HttpServletRequest request,
			HttpServletResponse response) {

		long startTime = System.currentTimeMillis();
		MDC.put(LOG4J_MDC_TOKEN, mertxnID);

		String headerName = null;
		String headerValue = null;
		String userAgent = "";
		String deviceFin = "";
		String accept = "";
		String ipAddress = "";

		try {
			String dataHashed = mID + mertxnID + timestamp;

			LoggingThread lt14 = new LoggingThread("[" + mertxnID + "]" + "WebAuthenticate " + " starttime: "
					+ startTime + " mID:" + mID + " mertxnID:" + mertxnID + " timestamp: " + timestamp + " hash: "
					+ signature + " ** hashstring: " + dataHashed);
			lt14.start();
//			Logging.getLogger().info("WebAuthenticate " + " starttime: " + startTime + " mID:" + mID + " mertxnID:"
//					+ mertxnID + " timestamp: " + timestamp + " hash: " + signature + " ** hashstring: " + dataHashed);

			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				LoggingThread lt15 = new LoggingThread(
						"[" + mertxnID + "]" + "**HEADER --> " + headerName + " : " + headerValue);
				lt15.start();
				// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
			}

			String reqTime = CommonHelper.getFormattedDateString();

			SecureImageResponse authRespdetail = new SecureImageResponse();
			authRespdetail.setMerTxnID(mertxnID);

			AuthReqDetail authReqDetail = new AuthReqDetail();

			authReqDetail.setCpID(mID);
			authReqDetail.setStartTime(reqTime);
			authReqDetail.setMerTxnID(mertxnID);
			authReqDetail.setSimcount(1);
			authReqDetail.setChannel("wap");
			authReqDetail.setAuthorize(false);

			String operatorSecretKey = "";
			String lRdUrl = "";
			long startTime_db = System.currentTimeMillis();

			SignKeyEntity signEnt = mAuthDbService.getByMid(mID);

			AccountInfoEntity accEnt = mAuthDbService.getByCustomerID(mID);

			String encKey = "";
			if (accEnt != null) {
				encKey = accEnt.getApiKey();
				// operatorSecretKey = mEncDecObj.decrypt(encKey);
				operatorSecretKey = accEnt.getApiKey();
				authReqDetail.setSeckey(operatorSecretKey);

				LoggingThread lt16 = new LoggingThread("[" + mertxnID + "]" + "OrgID Key found : " + encKey);
				lt16.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
			} else {
				LoggingThread lt17 = new LoggingThread("[" + mertxnID + "]" + "OrgID not found : " + operatorSecretKey);
				lt17.start();
				// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sendResponse(authReqDetail, INVALID_CPID, INVALID_TOKEN, request, response);
				return;
			}

			if (signEnt != null) {

				lRdUrl = signEnt.getTokenRedirectUrl();
				authReqDetail.setCpRdu(lRdUrl);

				authReqDetail.setOtpflow(signEnt.isEnableOtpFlow());
				authReqDetail.setClientURl(signEnt.getIdentityCallbackUrl());
				authReqDetail.setCliOtp(!signEnt.isGenerateOtp());

				// authReqDetail.setNoconsent(signEnt.isNoconsent());
				authReqDetail.setNoconsent(false);

				// authReqDetail.setSmsurl(signEnt.getSmsurl());

				LoggingThread lt18 = new LoggingThread(
						"[" + mertxnID + "]" + "OrgID Key found : " + encKey + "- url = " + lRdUrl);
				lt18.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey + "- url = " +
				// lRdUrl);
			} else {
				LoggingThread lt19 = new LoggingThread("[" + mertxnID + "]" + "OrgID not found : " + operatorSecretKey);
				lt19.start();
				// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sendResponse(authReqDetail, INVALID_CPID, INVALID_TOKEN, request, response);
				return;
			}
			LoggingThread lt20 = new LoggingThread(
					"[" + mertxnID + "]" + "DB Fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_db));
			lt20.start();
			// Logging.getLogger().info("DB Fetch ElapsedTime: " +
			// (System.currentTimeMillis() - startTime_db));

			if (TextUtils.isEmpty(mertxnID)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
				sendResponse(authReqDetail, INVALID_CPTXNID, INVALID_TOKEN, request, response);
				return;
			}

			if (!validateSignature(operatorSecretKey, signature, dataHashed)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SIGN);
				sendResponse(authReqDetail, INVALID_SIGN, INVALID_TOKEN, request, response);
				return;
			}

			ipAddress = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			userAgent = request.getHeader("user-agent") == null ? "null" : request.getHeader("user-agent");
			accept = request.getHeader("accept") == null ? "null" : request.getHeader("accept");

			String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null ? request.getHeader("X-FORWARDED-FOR")
					: "null";

			if (!xforwardedIP.contains("null")) {
				ipAddress = xforwardedIP;
			}

			if (TextUtils.isEmpty(userAgent) || (mSBuaList != null && mSBuaList.indexOf(userAgent) == -1)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
				sendResponse(authReqDetail, INVALID_SRC, INVALID_TOKEN, request, response);
				return;
			}

			LoggingThread lt21 = new LoggingThread("[" + mertxnID + "]" + "ipAddress - " + ipAddress + ", userAgent-"
					+ userAgent + ", accept-" + accept);
			lt21.start();
			// Logging.getLogger().info("ipAddress - " + ipAddress + ", userAgent-" +
			// userAgent + ", accept-" + accept);

			long reqtimediff = startTime - Long.parseLong(timestamp);
			// Logging.getLogger().info("Time Difference is - " + reqtimediff);
			long minutes = TimeUnit.MILLISECONDS.toMinutes(reqtimediff);
			// Logging.getLogger().info("Time Difference in min - " + minutes);

			LoggingThread lt22 = new LoggingThread("[" + mertxnID + "]" + "Time Difference is - " + reqtimediff
					+ ", Time Difference in min - " + minutes);
			lt22.start();

			if (minutes > Integer.parseInt(mValidTime)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
				sendResponse(authReqDetail, INVALID_SRC, INVALID_TOKEN, request, response);
				return;
			}

			String browserAgent = request.getHeader("user-agent");
			String mobileIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			String acpt = request.getHeader("accept") != null ? request.getHeader("accept") : "null";
			String msisdn = "null";
			String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
			String xRequestedWithReferer = request.getHeader("x-requested-with") != null
					? request.getHeader("x-requested-with")
					: "null";

			String botResp = getBotAnalyze(mertxnID, mobileIp, msisdn, browserAgent, mID, acpt, referer,
					xRequestedWithReferer, "wap");

			if (!botResp.contentEquals(DEFAULT_RESP)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, BLOCK);
				sendResponse(authReqDetail, BLOCK, INVALID_TOKEN, request, response);
				return;
			}

			String asTxnID = "";
			String asShare = "";

			deviceFin = userAgent + accept;

			if (TextUtils.isEmpty(asTxnID)) {
				asTxnID = getTransID();
			}

			authReqDetail.setCpTxnID(asTxnID);
			authReqDetail.setDevshare(asShare);
			authReqDetail.setDf(mEncDecObj.encrypt(deviceFin));

			authRespdetail.setOptxn(asTxnID);

			processTrnID(authReqDetail, authRespdetail, ipAddress, request, response);

			MDC.clear();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void processTrnID(AuthReqDetail authReqDetail, SecureImageResponse authRespdetail, String ipAddress,
			HttpServletRequest request, HttpServletResponse response) {

		try {
			String aMid = authReqDetail.getCpID();
			String asTxnID = authReqDetail.getCpTxnID();
			String asRedUrl = authReqDetail.getCpRdu();
			String reqTime = authReqDetail.getStartTime();
			String devicefin = mEncDecObj.decrypt(authReqDetail.getDf());
			DiscoveryResponse lDiscRep = null;
			String resp = "";

			String IdeNetResp = processIdeNet(ipAddress, authReqDetail.getMerTxnID());
			String lIdeResp = "";

			if (!TextUtils.isEmpty(IdeNetResp)) {

				JSONObject lIderespJson = new JSONObject(IdeNetResp);
				String status = lIderespJson.getString("status");

				if (status.contentEquals("SUCCESS")) {
					String networkProvider = lIderespJson.getString("networkProvider");
					String isCellularNetwork = lIderespJson.getString("isCellularNetwork");
					String isMobile = lIderespJson.getString("isMobile");

					authReqDetail.setNetProvider(networkProvider);
					authReqDetail.setIsMobileNetwork(isCellularNetwork);

					if (isCellularNetwork.contentEquals("true") && (networkProvider.contains("AIRTEL")
							|| networkProvider.contains("IDEA") || networkProvider.contains("VODAFONE"))) {
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "opn", networkProvider);

						String createsesResp = createSession(authReqDetail.getMerTxnID());

						if (!TextUtils.isEmpty(createsesResp)) {
							JSONObject lCrerespJson = new JSONObject(createsesResp);

							String sesstatus = lCrerespJson.getString("status");

							if (sesstatus.contentEquals("SUCCESS")) {
								String sesID = lCrerespJson.getString("sessionId");

								String lAuthrizeurl = mIdeDevUrl + "?sessionId=" + sesID + "&correlationId=" + asTxnID
										+ "&redirectUrl=" + mZomRedirectUrl;

								authRespdetail.setUrl(lAuthrizeurl);
								authRespdetail.setStatusCode(SUCCESS);
							} else {
								authRespdetail.setStatusCode(DISC_FAIL);
								getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
							}
						}
					} else {
						authRespdetail.setStatusCode(DISC_FAIL);
						getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
					}
				} else {
					authRespdetail.setStatusCode(DISC_FAIL);
					getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
				}

			} else {
				authRespdetail.setStatusCode(DISC_FAIL);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
			}

			if (authRespdetail != null && authRespdetail.getStatusCode().equals("AS201")) {
				try {

					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");

					LoggingThread lt23 = new LoggingThread(
							"[" + authRespdetail.getMerTxnID() + "]" + "**sendRedirect --> " + authRespdetail.getUrl());
					lt23.start();
					// Logging.getLogger().info("**sendRedirect --> " + authRespdetail.getUrl());

					response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
					response.setHeader("Location", authRespdetail.getUrl());
					response.sendRedirect(authRespdetail.getUrl());

				} catch (Exception e) {
					e.printStackTrace();
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String createSession(String mertxnID) {

		String lCreateSessionResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();

			// Logging.getLogger().info("mCreSesUrl : " + mCreSesUrl);

			// String lAuthStr =mZomClientID + mZomClientSec;
			String lAuthStr = mEncDecObj.decrypt(mZomClientID) + "" + mEncDecObj.decrypt(mZomClientSec);

			LoggingThread lt24 = new LoggingThread(
					"[" + mertxnID + "]" + "mCreSesUrl : " + mCreSesUrl + ", lAuthStr : " + lAuthStr);
			lt24.start();
			// Logging.getLogger().info("lAuthStr : " + lAuthStr);

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

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
			LoggingThread lt25 = new LoggingThread("[" + mertxnID + "]" + "lCreateSessionResp : " + lCreateSessionResp
					+ ", lCreateSessionResp Resp length " + lCreateSessionResp.length());
			lt25.start();
			// Logging.getLogger().info("lCreateSessionResp : " + lCreateSessionResp);
			// Logging.getLogger().info("lCreateSessionResp Resp length " +
			// lCreateSessionResp.length());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return lCreateSessionResp;

	}

	private String processIdeNet(String aSourceIP, String mertxnID) {

		String lNetIdenResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();

			LoggingThread lt26 = new LoggingThread(
					"[" + mertxnID + "]" + "mNetIdeUrl : " + mNetIdeUrl + ", aSourceIP : " + aSourceIP);
			lt26.start();
			// Logging.getLogger().info("mNetIdeUrl : " + mNetIdeUrl);
			// Logging.getLogger().info("aSourceIP : " + aSourceIP);

			// String lAuthStr =mZomClientID + mZomClientSec;

			String lAuthStr = mEncDecObj.decrypt(mZomClientID) + "" + mEncDecObj.decrypt(mZomClientSec);

			LoggingThread lt27 = new LoggingThread("[" + mertxnID + "]" + "lAuthStr : " + lAuthStr);
			lt27.start();
			// Logging.getLogger().info("lAuthStr : " + lAuthStr);

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

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
			LoggingThread lt28 = new LoggingThread("[" + mertxnID + "]" + "lNetIdenResp : " + lNetIdenResp
					+ ", lNetIdenResp Resp length " + lNetIdenResp.length());
			lt28.start();
			// Logging.getLogger().info("lNetIdenResp : " + lNetIdenResp);
			// Logging.getLogger().info("lNetIdenResp Resp length " +
			// lNetIdenResp.length());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return lNetIdenResp;
	}

	private String getBotAnalyze(String acpTxnID, String mip, String msisdn, String browserAgent, String acpID,
			String acpt, String referer, String xRequestedWithReferer, String aChannel) {

		String resp = DEFAULT_RESP;
		StringBuilder respStr = new StringBuilder();

		try {

			HttpPost httpPost = new HttpPost(mAuthBotUrl);
			List<NameValuePair> params = new ArrayList<>();

			params.add(new BasicNameValuePair("oid", acpID));
			params.add(new BasicNameValuePair("optxn", acpTxnID));
			params.add(new BasicNameValuePair("mip", mip));
			params.add(new BasicNameValuePair("mdn", msisdn));
			params.add(new BasicNameValuePair("bua", browserAgent));
			params.add(new BasicNameValuePair("acpt", acpt));
			params.add(new BasicNameValuePair("ref", referer));
			params.add(new BasicNameValuePair("xreqRef", xRequestedWithReferer));
			params.add(new BasicNameValuePair("channel", aChannel));

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					respStr.append(readLine);
				}
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);
			}
			resp = respStr.toString();
			LoggingThread lt29 = new LoggingThread("[" + acpTxnID + "]" + "BotRespVal : " + resp);
			lt29.start();
			// Logging.getLogger().info("BotRespVal : " + resp);

		} catch (Exception e) {
			ErrorLogging.getLogger().info("Auth Bot error " + e.getMessage());
		}

		return resp;
	}

	private String getAPPBotAnalyze(String acpTxnID, String mip, String msisdn, String browserAgent, String acpID,
			String acpt, String referer, String xRequestedWithReferer, String aChannel, String aDevFingerPrt,
			String operatorSecretKey) {
		String resp = DEFAULT_RESP;

		AppBotRequest botReq = new AppBotRequest();
		StringBuilder respStr = new StringBuilder();
		String lAuthStr = "";

		try {

			long startTime = System.currentTimeMillis();

			botReq.setAcpt(acpt);
			botReq.setAptxn(acpTxnID);
			botReq.setBua(browserAgent);
			botReq.setChannel(aChannel);
			botReq.setDevFingerPrt(aDevFingerPrt);
			botReq.setMdn(msisdn);
			botReq.setMip(mip);
			botReq.setOid(acpID);
			botReq.setRef(referer);
			botReq.setSrnsize("null");
			botReq.setSrvId("null");
			botReq.setTs(String.valueOf(startTime));
			botReq.setXreqRef(xRequestedWithReferer);

			String dataToBeHashed = acpID + startTime + operatorSecretKey;

			lAuthStr = CommonHelper.generateSign(operatorSecretKey, dataToBeHashed);

			HttpPost httpPost = new HttpPost(mAuthAppBotUrl);

			StringEntity entity = new StringEntity(gson.toJson(botReq));
			httpPost.setEntity(entity);

			httpPost.setHeader("Authorization", "Bearer " + lAuthStr);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Accept", "application/json");
			httpPost.setHeader("Cache-Control", "no-cache");

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					respStr.append(readLine);
				}
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);
			}
			resp = respStr.toString();
			LoggingThread lt30 = new LoggingThread("[" + acpTxnID + "]" + "AppBotRespVal : " + resp);
			lt30.start();
			// Logging.getLogger().info("AppBotRespVal : " + resp);

		} catch (Exception e) {
			ErrorLogging.getLogger().info("Auth APP Bot error " + e.getMessage());
		}
		return resp;
	}

	private void sendResponse(AuthReqDetail authReqDetail, String status, String aToken, HttpServletRequest request,
			HttpServletResponse response) {
		try {

			String lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(authReqDetail.getCpTxnID() + "mn");

			sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), status, lMsisdn,
					authReqDetail.getSecMsisdn());

			Cookie cookie = new Cookie("authshare", "");
			cookie.setDomain(System.getenv("DOMAIN_NAME"));
			cookie.setPath(request.getContextPath());
			cookie.setMaxAge(0);
			response.addCookie(cookie);
			MDC.clear();

			String url = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status=" + status + "&mertxnid="
					+ authReqDetail.getMerTxnID();
			response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
			response.setHeader("Location", url);
			response.setHeader("Connection", "close");
			response.sendRedirect(url);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void processTrnID(AuthReqDetail authReqDetail, SecureImageResponse authRespdetail, String remoteAddr,
			String authtype, HttpServletRequest request, HttpServletResponse response) {

		try {
			String aMid = authReqDetail.getCpID();
			String asTxnID = authReqDetail.getCpTxnID();
			String devicefin = mEncDecObj.decrypt(authReqDetail.getDf());
			String asShare = authReqDetail.getDevshare();
			String asRedUrl = authReqDetail.getCpRdu();
			String reqTime = authReqDetail.getStartTime();
			String shareUrl = authReqDetail.getShareurl();
			boolean otpFlow = authReqDetail.isOtpflow();
			DiscoveryResponse lDiscRep = null;
			String resp = "";

			AuthReqValidObj msisdnObj = validatedevfin(asTxnID, devicefin, asShare, shareUrl, request, response);

			if (msisdnObj.isStatus()) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, DUPLICATE_REQ);
				sendResponse(authReqDetail, DUPLICATE_REQ, INVALID_TOKEN, request, response);
				return;
			}

			if (TextUtils.isEmpty(msisdnObj.getMsisdn())) {

				String IdeNetResp = processIdeNet(remoteAddr, authReqDetail.getMerTxnID());

				if (!TextUtils.isEmpty(IdeNetResp)) {

					JSONObject lIderespJson = new JSONObject(IdeNetResp);
					String status = lIderespJson.getString("status");

					if (status.contentEquals("SUCCESS")) {
						String networkProvider = lIderespJson.getString("networkProvider");
						String isCellularNetwork = lIderespJson.getString("isCellularNetwork");
						String isMobile = lIderespJson.getString("isMobile");

						authReqDetail.setNetProvider(networkProvider);
						authReqDetail.setIsMobileNetwork(isCellularNetwork);

						if (isCellularNetwork.contentEquals("true") && isMobile.contentEquals("true")) {
							OptVebdorEntity data = mAuthDbService.getByOperator(networkProvider, "act");

							if (data != null && data.getVertype().contains("HE")) {

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "opn", networkProvider);

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");

								String createsesResp = createSession(authReqDetail.getMerTxnID());

								if (!TextUtils.isEmpty(createsesResp)) {
									JSONObject lCrerespJson = new JSONObject(createsesResp);

									String sesstatus = lCrerespJson.getString("status");

									if (sesstatus.contentEquals("SUCCESS")) {
										String sesID = lCrerespJson.getString("sessionId");

										String lAuthrizeurl = mIdeDevUrl + "?sessionId=" + sesID + "&correlationId="
												+ asTxnID + "&redirectUrl=" + mZomRedirectUrl;

										authRespdetail.setUrl(lAuthrizeurl);
										authRespdetail.setStatusCode(SUCCESS);
									} else {
										authRespdetail.setStatusCode(DISC_FAIL);
									}
								}
							} else if (data != null && data.getVertype().contains("VERIFY")) {
								authReqDetail.setVerType("VERIFY");

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "veri", data.getVertype());

								mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");
								displayMdnpage(asTxnID, request, response, true);
								return;
							} else {
								authRespdetail.setStatusCode(DISC_FAIL);
							}
						} else {
							authRespdetail.setStatusCode(DISC_FAIL);
						}
					} else {
						authRespdetail.setStatusCode(DISC_FAIL);
					}

				} else {
					authRespdetail.setStatusCode(DISC_FAIL);
				}

				if (authRespdetail != null && authRespdetail.getStatusCode().equals(DISC_FAIL)) {
					if (otpFlow) {
						authReqDetail.setTelco("OTP");
						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");
						displayMdnpage(asTxnID, request, response, false);
						return;
					} else {
						authRespdetail.setStatusCode(DISC_FAIL);
						getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
						sendResponse(authReqDetail, INVALID_SRC, INVALID_TOKEN, request, response);
						return;
					}
				}

				if (authRespdetail != null && authRespdetail.getStatusCode().equals("AS201")) {
					try {

						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");

						LoggingThread lt31 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]"
								+ "**sendRedirect --> " + authRespdetail.getUrl());
						lt31.start();
						// Logging.getLogger().info("**sendRedirect --> " + authRespdetail.getUrl());

						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", authRespdetail.getUrl());
						response.sendRedirect(authRespdetail.getUrl());

					} catch (Exception e) {
						e.printStackTrace();
					}
				}

			} else {

				authReqDetail.setTelco("Auth");
				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);

				if (authtype != null && (authtype.contains("YES") || authtype.contains("yes"))) {
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "mn", msisdnObj.getMsisdn());
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);

					resp = sendShare(asTxnID, request, response);
					if (!authReqDetail.isNoconsent()) {
						response.sendRedirect(resp);
					}

				} else {

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "mn", msisdnObj.getMsisdn());
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);

					takeConsent(asTxnID, aMid, request, response, authReqDetail.getSeckey());
				}
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void displayMdnpage(String txnID, HttpServletRequest request, HttpServletResponse response,
			boolean verify) {

		SecureImageResponse authRespdetail = new SecureImageResponse();

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		authRespdetail = sendImageReq(txnID, "null", authReqDetail.getCpID(), request, response,
				authReqDetail.getSeckey(), false, null);

		if (authRespdetail != null && authRespdetail.getStatusCode() != null
				&& authRespdetail.getStatusCode().contains("201")) {

			WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");
			RequestDispatcher rd = null;

			if (verify) {
				rd = request.getRequestDispatcher("/WEB-INF/jsp/verify.jsp");
			} else {
				rd = request.getRequestDispatcher("/WEB-INF/jsp/mdn.jsp");
			}

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
			request.setAttribute("desc1", webparam.getDeswifi1());
			request.setAttribute("desc2", webparam.getDeswifi2());
			request.setAttribute("footer", webparam.getFtext());
			request.setAttribute("imgurl", webparam.getLogoimg());
			request.setAttribute("avtimgurl", webparam.getAvtimg());
			request.setAttribute("imgstr", webparam.getImgstr());
			request.setAttribute("t", mSessionTimeout);
			request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

			try {
				rd.forward(request, response);
			} catch (ServletException | IOException e) {
				Logging.getLogger().info("Exception--" + e.getMessage());
			}

			LoggingThread lt32 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]" + "displayImage over : ");
			lt32.start();
			// Logging.getLogger().info("displayImage over : ");
		} else {
			LoggingThread lt33 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]" + "displayImage fail : ");
			lt33.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
		}
	}

	@RequestMapping(value = "/disp-mdn")
	public @ResponseBody void dispmdnpag(@RequestParam(value = "transID", required = true) String aTransID,
			HttpServletRequest request, HttpServletResponse response) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
		String mertxnID = authReqDetail.getMerTxnID();
		LoggingThread lt34 = new LoggingThread("[" + mertxnID + "]" + "disp-mdn page : ");
		lt34.start();
		// Logging.getLogger().info("disp-mdn page : ");

		if (authReqDetail != null) {
			authReqDetail.setTelco("OTP");

			String txnID = getTransID();

			mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);

			WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web");

			mWebDesignParamRepoImpl.saveToWebDesignparamRepo(txnID + "web", webparam);

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "df",
					mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "df"));
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "rdu",
					mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu"));
			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "chan", "wap");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, ALTERNATE_NUM, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, ALTERNATE_NUM, "NA");

			displayMdnpage(txnID, request, response, false);
		} else {
			LoggingThread lt35 = new LoggingThread("[" + mertxnID + "]" + "disp-mdn page  fail : ");
			lt35.start();
			// Logging.getLogger().info("disp-mdn page fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
		}
	}

	@RequestMapping(value = "/wifi-flow")
	public @ResponseBody void sendwififlowreq(@RequestParam(value = "transID", required = true) String aTransID,
			HttpServletRequest request, HttpServletResponse response) {

		try {

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

			String redirectUrl = "";

			if (wap) {
				redirectUrl = mImageDispUrl + "?transID=" + aTransID;
			} else {
				String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
				AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

				CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, ALTERNATE_NUM, "", "");
				clt.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, ALTERNATE_NUM, "", "");

				redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(ALTERNATE_NUM, authReqDetail.isIPhone())
						+ "&txnid=" + "0" + "&status=" + "NA" + "&eshare=" + "" + "&result=" + "NA" + "&mtxnid="
						+ authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn=" + "NA";

			}
			MDC.clear();
			response.sendRedirect(redirectUrl);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void takeConsent(String asTxnID, String aMid, HttpServletRequest request, HttpServletResponse response,
			String seckey) {

		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(asTxnID + "req");
			String mertxnID = authReqDetail.getMerTxnID();
			SecureImageResponse authRespdetail = new SecureImageResponse();

			String msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(asTxnID + "mn");

			authRespdetail = sendImageReq(asTxnID, msisdn, aMid, request, response, seckey, false, null);

			if (authRespdetail != null && authRespdetail.getStatusCode() != null
					&& authRespdetail.getStatusCode().contains("201")) {
				displayImage(authRespdetail, request, response);
				LoggingThread lt36 = new LoggingThread("[" + mertxnID + "]" + "displayImage over : ");
				lt36.start();
				// Logging.getLogger().info("displayImage over : ");
			} else {
				LoggingThread lt37 = new LoggingThread("[" + mertxnID + "]" + "displayImage fail : ");
				lt37.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
				clt.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
				sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String getTransID() {
		UUID uuid = UUID.randomUUID();
		return uuid.toString() + "saas";
	}

	private void getLogErrorMsg(SecureImageResponse authRespdetail, Gson gson, AuthReqDetail authDetail,
			String statusCode) {
		authRespdetail.setStatusCode(statusCode);
		CDRLoggingThread clt = new CDRLoggingThread(authDetail, "null", statusCode, "NA");
		clt.start();
		// CDRLogging.getCDRWriter().logCDR(authDetail, "null", statusCode, "NA");
		LoggingThread lt38 = new LoggingThread("[" + authDetail.getMerTxnID() + "]" + "authResp"
				+ gson.toJson(authRespdetail, SecureImageResponse.class));
		lt38.start();
		// Logging.getLogger().info("authResp" + gson.toJson(authRespdetail,
		// SecureImageResponse.class));
	}

	boolean validateSignature(String operatorSecretKey, String hash, String dataHashed)
			throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		boolean result = true;
		String hashres = CommonHelper.generateSign(operatorSecretKey, dataHashed);
		LoggingThread lt39 = new LoggingThread("datatohashmc : " + dataHashed + ", hashres : " + hashres);
		lt39.start();
		// Logging.getLogger().info("datatohashmc : " + dataHashed);
		// Logging.getLogger().info("hashres : " + hashres);
		if (!hashres.contentEquals(hash)) {
			result = false;
		}
		return result;
	}

	private String processAutherize(DiscoveryResponse lDiscRep, HttpServletResponse response) {

		String authurl = lDiscRep.getAuthorizationURL();
		String clientID = lDiscRep.getClient_id();
		String finurl = "";

		try {
			finurl = authurl + "?" + "redirect_uri=" + mRedirectUrl + "&client_id=" + clientID
					+ "&scope=openid+mc_attr_vm_share" + "&response_type=code" + "&acr_values=2" + "&state="
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

			HttpPost httpPost = new HttpPost(mDiscoverUrl);
			List<NameValuePair> params = new ArrayList<>();
			params.add(new BasicNameValuePair("Redirect_URL", mRedirectUrl));

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));
			httpPost.setHeader("Authorization", "Basic " + aBaseAuthstr);
			httpPost.setHeader("X-Source-ip", aSourceIP);

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);

			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					lDiscoveryRespStr.append(readLine);
				}
			} else {
				// System.out.println(imgresponse);
			}
			lDiscoveryResp = lDiscoveryRespStr.toString();
			LoggingThread lt40 = new LoggingThread("Web lDiscoveryResp Resp length " + lDiscoveryResp.length());
			lt40.start();
			// Logging.getLogger().info("Web lDiscoveryResp Resp length " +
			// lDiscoveryResp.length());

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

			for (int i = 0; i < linkarray.length(); i++) {
				JSONObject link = linkarray.getJSONObject(i);
				String hosturl = link.getString("href");
				String rela = link.getString("rel");
				if (rela.equals("authorization")) {
					lDiscResp.setAuthorizationURL(hosturl);
				} else if (rela.equals("token")) {
					lDiscResp.setTokenURL(hosturl);
				} else if (rela.equals("issuer")) {
					lDiscResp.setIssuerURL(hosturl);
				} else if (rela.equals("userinfo")) {
					lDiscResp.setUserinfoURL(hosturl);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		return lDiscResp;
	}

	private AuthReqValidObj validatedevfin(String acpTxnID, String aDeviceFin, String aDevShare, String shareUrl,
			HttpServletRequest request, HttpServletResponse response) {

		AuthReqValidObj respObj = new AuthReqValidObj();
		// AuthShareEntity authEntity =
		// mAuthsharedbrepoImpl.getauthsharefromdb(acpTxnID);

		AuthShareEntity authEntity = mAuthDbService.getByNewtxnID(acpTxnID);
		String mertxnID = authEntity.getMertxnid();
		LoggingThread lt41 = new LoggingThread("[" + mertxnID + "]" + "validatedevfin aDeviceFin :" + aDeviceFin);
		lt41.start();
		// Logging.getLogger().info("validatedevfin aDeviceFin :" + aDeviceFin);

		if (authEntity != null) {

			// String share3 = getShareVal(acpTxnID, shareUrl, request, response);

			// long startTime_url = System.currentTimeMillis();
			// Logging.getLogger().info("Share from url: " + share3);
			// Logging.getLogger().info("Share URL fetch ElapsedTime:
			// "+(System.currentTimeMillis()-startTime_url));

			String share1 = authEntity.getShare1();
			String share2 = authEntity.getShare2();
			String share3 = authEntity.getShare3();
			String msisdn = authEntity.getMsisdn();
			String opn = authEntity.getOpn();
			String mID = authEntity.getMid();
			boolean authed = authEntity.isAuthed();

			respObj.setStatus(authed);

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", opn);

			if (!authed) {
				authEntity.setAuthed(true);
				// mAuthsharedbrepoImpl.saveauthsharetodb(authEntity);
				mAuthDbService.saveShare(authEntity);
			}

			String decShare1 = "";
			String decShare2 = "";
			String decShare3 = "";
			String condecshare = "";

			try {
				decShare1 = mEncDecObj.decrypt(share1);
				decShare2 = mEncDecObj.decrypt(share2);
				decShare3 = mEncDecObj.decrypt(share3);
				String decr = decShare1 + decShare2 + decShare3;
				condecshare = mEncDecObj.decrypt(decr);

				String txnidLen = condecshare.substring(condecshare.length() - 2, condecshare.length());

				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(txnidLen) - 2);

				String msisdnlen = condecshare.substring(condecshare.length() - 2, condecshare.length());

				/*
				 * String msisdnshre = condecshare.substring(condecshare.length() -
				 * Integer.valueOf(msisdnlen), condecshare.length()-2);
				 */

				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(msisdnlen) - 2);

				LoggingThread lt42 = new LoggingThread(
						"[" + mertxnID + "]" + "validatedevfin condecshare :" + condecshare);
				lt42.start();
				// Logging.getLogger().info("validatedevfin condecshare :" + condecshare);

				if (aDevShare.contentEquals(share1) && condecshare.contentEquals(aDeviceFin)) {
					respObj.setMsisdn(mEncDecObj.decrypt(msisdn));
					LoggingThread lt43 = new LoggingThread(
							"[" + mertxnID + "]" + "validatedevfin :" + mEncDecObj.encrypt(respObj.getMsisdn()));
					lt43.start();
					// Logging.getLogger().info("validatedevfin :" +
					// mEncDecObj.encrypt(respObj.getMsisdn()));
				} else {
					respObj.setMsisdn("");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		} else {
			LoggingThread lt44 = new LoggingThread("[" + mertxnID + "]" + "authEntity : null for txnID :" + acpTxnID);
			lt44.start();
			// Logging.getLogger().info("authEntity : null for txnID :" + acpTxnID);
		}
		return respObj;
	}

	private String sendShare(String aTransID, HttpServletRequest request, HttpServletResponse response) {

		String lDevicefin = "";
		String lMsisdn = "0";

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
		String mertxnID = authReqDetail.getMerTxnID();

		try {
			String newTxnID = getTransID();

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");

			lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "df");
			lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			LoggingThread lt55 = new LoggingThread(
					"[" + mertxnID + "]" + "sendShare:" + "lDevicefin: " + mEncDecObj.encrypt(lDevicefin));
			lt55.start();
			// Logging.getLogger().info("sendShare:" + "lDevicefin: " +
			// mEncDecObj.encrypt(lDevicefin));

			String tlen = "", mlen = "";

			if (aTransID.length() < 10) {
				tlen = "0" + aTransID.length();
			} else {
				tlen = "" + aTransID.length();
			}

			if (lMsisdn.length() < 10) {
				mlen = "0" + lMsisdn.length();
			} else {
				mlen = "" + lMsisdn.length();
			}

			String encval = lDevicefin + lMsisdn + mlen + aTransID + tlen;

			String mEncDf = mEncDecObj.encrypt(encval);
			LoggingThread lt56 = new LoggingThread("[" + mertxnID + "]" + "sendShare:" + "mEncDf: " + mEncDf);
			lt56.start();
			// Logging.getLogger().info("sendShare:" + "mEncDf: " + mEncDf);

			int len = mEncDf.length();

			int devlength = len / 3;

			String s1 = mEncDf.substring(0, devlength - 1);
			String s2 = mEncDf.substring(devlength - 1, 2 * devlength - 1);
			String s3 = mEncDf.substring(2 * devlength - 1, len);

			String EncString1 = "";
			String EncString2 = "";
			String EncString3 = "";
			try {
				EncString1 = mEncDecObj.encrypt(s1);
				EncString2 = mEncDecObj.encrypt(s2);
				EncString3 = mEncDecObj.encrypt(s3);
			} catch (Exception e) {
				e.printStackTrace();
			}

			// Logging.getLogger().info("Crypto Share 1 : " + EncString1);
			// Logging.getLogger().info("Crypto Share 2 : " + EncString2);
			// Logging.getLogger().info("Crypto Share 3 : " + EncString3);

			LoggingThread lt57 = new LoggingThread("[" + mertxnID + "]" + "Crypto Share 1 : " + EncString1
					+ ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3);
			lt57.start();

			AuthShareEntity mEntity = new AuthShareEntity();

			mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn));
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

			// mAuthsharedbrepoImpl.saveauthsharetodb(mEntity);
			mAuthDbService.saveShare(mEntity);

			authReqDetail.setNewTxnID(newTxnID);

			// CDRLogging.getCDRWriter().logCDR(authReqDetail, mEncDecObj.encrypt(lMsisdn),
			// SUCCESS, "YES");

			AuthWebResp resp = new AuthWebResp();

			String shareval = newTxnID.length() + newTxnID + EncString1;
			LoggingThread lt58 = new LoggingThread("[" + mertxnID + "]" + "**shareval--> " + shareval);
			lt58.start();
			// Logging.getLogger().info("**shareval--> " + shareval);
			String encshare = mEncDecObj.encrypt(shareval);

			Cookie cookie = new Cookie("authshare", encshare);
			cookie.setDomain(System.getenv("DOMAIN_NAME"));
			cookie.setPath(request.getContextPath());
			cookie.setMaxAge(60 * 60 * 24 * 30);
			response.addCookie(cookie);

			resp.setStatus(SUCCESS);
			resp.setToken(newTxnID);
			resp.setTxnID(authReqDetail.getMerTxnID());
			resp.setMsisdn(mEncDecObj.encrypt(lMsisdn));

			String redirectUrl = "";

			if (!authReqDetail.isNoconsent()) {
				String reqTime = CommonHelper.getFormattedDateString();

				String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
				redisMessagePublisher.publish(message);

				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", aTransID);

				mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

				redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS + "&mertxnid="
						+ authReqDetail.getMerTxnID();
			} else {

				redirectUrl = lRedirectUrl + "msisdn=" + lMsisdn + "&status=" + SUCCESS + "&mertxnid="
						+ authReqDetail.getMerTxnID();
				redirectUrl = lMsisdn;
			}
			sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn, authReqDetail.getSecMsisdn());
			// saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

			MDC.clear();
			return redirectUrl;
		} catch (Exception e) {
			e.printStackTrace();
			sendClientResp(aTransID, authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
			return null;
		}
	}

	public SecureImageResponse sendImageReq(String aTransID, String aMsisdn, String aMid, HttpServletRequest aRequest,
			HttpServletResponse response, String seckey, boolean otpimg, String otp) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
		String mertxnID = authReqDetail.getMerTxnID();
		SecureImageResponse lImageRs = new SecureImageResponse();
		try {

			LoggingThread lt59 = new LoggingThread("[" + mertxnID + "]" + "getsecure-img:" + "txnID: " + aTransID
					+ ",msisdn:" + mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid);
			lt59.start();
//			Logging.getLogger().info(
//					"getsecure-img:" + "txnID: " + aTransID + ",msisdn:" + mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid);

			if (!TextUtils.isEmpty(aMid)) {
				StringBuilder imageStr = new StringBuilder();

				String browserAgent = aRequest.getHeader("user-agent");
				String size = mImgSize;
				String mobileIp = aRequest.getRemoteAddr() != null ? aRequest.getRemoteAddr() : "null";
				String serviceId = "null";
				String orgId = aMid;
				String imsi = "null";
				String circleId = "null";
				String imei = "null";
				String channel = "WAP";
				String acpt = aRequest.getHeader("accept") != null ? aRequest.getHeader("accept") : "null";
				String sip = "null";
				String xfip = aRequest.getHeader("X-Forwarded-For") != null ? aRequest.getHeader("X-Forwarded-For")
						: "null";
				String itpe = "3b";
				String t1 = "null";
				String t2 = aMsisdn;
				String t3 = "null";
				String ts = String.valueOf(System.currentTimeMillis());

				if (otpimg) {
					if (otp != null) {
						itpe = "8d";
						t3 = otp;
					} else {
						itpe = "8c";
					}
				}

				if (t2.contains("null")) {
					itpe = "1c";
				}

				String dataToBeHashed = aTransID + ts + size + mobileIp + aMsisdn + browserAgent + serviceId + orgId
						+ imsi + circleId + imei + channel + acpt + sip + xfip + itpe + t1 + t2 + t3;
				String sig = CommonHelper.generateSign(seckey, dataToBeHashed);

				HttpPost httpPost = new HttpPost(mImageReqUrl);
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
				httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));
				httpPost.setHeader("origin", "https://junosecure");
				RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
						.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
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
				// lImageRs.setOptxn(aTransID);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return lImageRs;
	}

	private void displayImage(SecureImageResponse mImageResp, HttpServletRequest request,
			HttpServletResponse response) {

		String img1 = mImageResp.getImage1();
		String img2 = mImageResp.getImage2();
		String txt = mImageResp.getPimage();
		String txnID = mImageResp.getOptxn();
		String pshare = "YES";

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

		RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/aoc.jsp");

		request.setAttribute("img1", img1);
		request.setAttribute("img2", img2);
		request.setAttribute("optxn", txnID);
		request.setAttribute("pshare", pshare);
		request.setAttribute("pimg", txt);
		request.setAttribute("simcnt", authReqDetail.getSimcount());
		request.setAttribute("meroptxn", authReqDetail.getMerTxnID());
		request.setAttribute("header", webparam.getHtext());
		request.setAttribute("hcolor", webparam.getHcolor());
		request.setAttribute("desc1", webparam.getDesdata1());
		request.setAttribute("desc2", webparam.getDesdata2());
		request.setAttribute("footer", webparam.getFtext());
		request.setAttribute("imgurl", webparam.getLogoimg());
		request.setAttribute("multi", 1);
		request.setAttribute("imgstr", webparam.getImgstr());
		request.setAttribute("t", mSessionTimeout);
		request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

		try {
			rd.forward(request, response);
		} catch (ServletException | IOException e) {
			Logging.getLogger().info("Exception--" + e.getMessage());
		}
	}

	@RequestMapping(value = "/setBualist")
	public @ResponseBody String setMIDList(@RequestParam(value = "sbuaList", required = false) List<String> value) {
		try {
			LoggingThread lt60 = new LoggingThread("*****SBuaList value : " + value + "*****");
			lt60.start();
			// Logging.getLogger().info("*****SBuaList value : " + value + "*****");

			if (value.size() == 0 || value.equals("") || value == null) {
				mSBuaList.clear();
			} else {
				mSBuaList.clear();
				mSBuaList.addAll(value);
			}
		} catch (Exception e) {
			Logging.getLogger().error("Exception in SBuaList:", e);
			return FAILURE;
		}
		return SUCCESS_RESPONSE;
	}

	@RequestMapping(value = "/authresp")
	public @ResponseBody void Authentication(@RequestParam("resp") String Status, HttpServletRequest request,
			HttpServletResponse response) {

		TxnResp tResp = gson.fromJson(Status, TxnResp.class);

		// Logging.getLogger().info("Authentication resp status" + tResp.getStatus());
		// Logging.getLogger().info("Authentication resp txnid" + tResp.getMertxnid());
		// Logging.getLogger().info("Authentication resp pmdn" + tResp.getPmdn());
		// Logging.getLogger().info("Authentication resp smdn" + tResp.getSmdn());
		// Logging.getLogger().info("Authentication resp smdn" + tResp.getAstxnid());

		LoggingThread lt61 = new LoggingThread("Authentication resp status" + tResp.getStatus()
				+ "Authentication resp txnid" + tResp.getMertxnid() + "Authentication resp pmdn" + tResp.getPmdn()
				+ "Authentication resp smdn" + tResp.getSmdn() + "Authentication resp smdn" + tResp.getAstxnid());
		lt61.start();

		return;
	}

	@RequestMapping(value = "/userinfo")
	public @ResponseBody MobResp getMobile(@RequestParam("token") String Token, @RequestParam("mertxnid") String txnID,
			@RequestParam("status") String status, HttpServletRequest request, HttpServletResponse response) {

		String lMobileNumber = "0";
		String optxn = "";

		MobResp mResp = new MobResp();

		LoggingThread lt62 = new LoggingThread("[" + txnID + "]" + "Authentication resp token" + Token);
		lt62.start();
		// Logging.getLogger().info("Authentication resp token" + Token);
		try {

			AuthWebResp resp = mTokenRespRepoImpl.getValueFromAshiledReqRedisRepo(Token + "resp");
			if (resp != null) {
				lMobileNumber = mEncDecObj.decrypt(resp.getMsisdn());
				LoggingThread lt63 = new LoggingThread(
						"[" + txnID + "]" + "Authentication lMobileNumber" + lMobileNumber);
				lt63.start();
				// Logging.getLogger().info("Authentication lMobileNumber" + lMobileNumber);

				optxn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(Token + "new");

				AuthReqDetail validationDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(optxn + "req");
				if (validationDetail != null) {
					CDRLoggingThread clt = new CDRLoggingThread(validationDetail, resp.getMsisdn(), SUCCESS, "YES");
					clt.start();
					// CDRLogging.getCDRWriter().logCDR(validationDetail, resp.getMsisdn(), SUCCESS,
					// "YES");

					mResp.setPmdn(lMobileNumber);
					mResp.setStatus(SUCCESS);
					mResp.setMertxnid(txnID);
					mResp.setSmdn(validationDetail.getSecMsisdn());
					mResp.setAstxnid(optxn);
				} else {
					CDRLoggingThread clt = new CDRLoggingThread(validationDetail, resp.getMsisdn(), "NULL", "FAIL");
					clt.start();
					// CDRLogging.getCDRWriter().logCDR(validationDetail, resp.getMsisdn(), "NULL",
					// "FAIL");
					mResp.setPmdn("");
					mResp.setStatus(SESSION_TIME_OUT);
					mResp.setMertxnid(txnID);
					mResp.setSmdn("");
					mResp.setAstxnid(optxn);
				}

				deleteredis(optxn);

				mTokenRespRepoImpl.deleteValueFromAshiledReqRedisRepo(Token + "resp");
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(Token + "new");

			} else {
				mResp.setPmdn(lMobileNumber);
				mResp.setStatus(status);
				mResp.setMertxnid(txnID);
				mResp.setSmdn("0");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return mResp;
	}

	@RequestMapping(value = "/sendmdn")
	public @ResponseBody void displayOTP(@RequestParam("mdnum") String aesplatform,
			@RequestParam("txnid") String aTransID, @RequestParam("param5") String param5,
			@RequestParam("mertxnid") String merTxnID, HttpServletRequest request, HttpServletResponse response) {

		String lMobileNumber = "";

		ImageValidationResponse mImgResp = null;
		StringBuilder imageStr = new StringBuilder();
		String headerName = null;
		String headerValue = null;

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		String dataHashed = aTransID + param5;
		String hash = "";
		try {
			hash = CommonHelper.generateSign(authReqDetail.getSeckey(), dataHashed);
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		MDC.put(LOG4J_MDC_TOKEN, merTxnID);

		LoggingThread lt64 = new LoggingThread("[" + merTxnID + "]" + "displayOTP txnID" + aTransID);
		lt64.start();
		// Logging.getLogger().info("displayOTP txnID" + aTransID);

		try {
			String decrypted_aesdata = null;

			aesplatform = (aesplatform != null && !aesplatform.equalsIgnoreCase(""))
					? URLDecoder.decode(aesplatform, "UTF-8")
					: "";
			if (aesplatform != null && aesplatform.split("::").length == 3) {
				AesEncryptDecrypt aesEncryptDecrypt = new AesEncryptDecrypt(128, 100);
				// Logging.getLogger().info("*********************AES Encrypted_platform from JS
				// - " + aesplatform);
				String iv = aesplatform.split("\\::")[0];
				String salt = aesplatform.split("\\::")[1];
				String ciphertext = aesplatform.split("\\::")[2];

//				Logging.getLogger().info("*********************AES encrypted value of aesplatform --> salt :" + " "
//						+ salt + ", iv : " + iv + ", ciphertext : " + ciphertext);
				decrypted_aesdata = aesEncryptDecrypt.decrypt(salt, iv, aTransID, ciphertext);
				// Logging.getLogger().info("*********************AES Decrypted platform from JS
				// - " + lMobileNumber);

				LoggingThread lt65 = new LoggingThread(
						"[" + merTxnID + "]" + "*********************AES Encrypted_platform from JS - " + aesplatform
								+ "*********************AES encrypted value of aesplatform --> salt :" + " " + salt
								+ ", iv : " + iv + ", ciphertext : " + ciphertext
								+ "*********************AES Decrypted platform from JS - " + lMobileNumber);
				lt65.start();

			}

			lMobileNumber = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[0], "UTF-8")
					: "null";
			String platform = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[1], "UTF-8")
					: "null";
			String scn_Size = decrypted_aesdata != null ? decrypted_aesdata.split("\\*")[2] : "null";
			String nav_bua = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[3], "UTF-8")
					: "null";

			String remoteIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null ? request.getHeader("X-FORWARDED-FOR")
					: "null";
			String clientIP = request.getHeader("CLIENT_IP") != null ? request.getHeader("CLIENT_IP") : "null";
			String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
			String acpt = request.getHeader("accept");
			String userAgent = request.getHeader("user-agent");
			String mip = Stream.of(xforwardedIP, remoteIp, clientIP)
					.filter(s -> s != null && !s.isEmpty() && !s.equalsIgnoreCase("null"))
					.collect(Collectors.joining("-"));

			LoggingThread lt66 = new LoggingThread("[" + merTxnID + "]" + "*** sendmdn Parameters *** purchaseId : "
					+ aTransID + ", UserAgent : " + userAgent + ", remoteIp : " + remoteIp + ", X-forwardedIP : "
					+ xforwardedIP + ", clientIP : " + clientIP + ", Referer : " + referer + ", acpt : " + acpt
					+ ", param5 : " + param5 + "\n" + "sendmdn lMobileNumber" + lMobileNumber);
			lt66.start();
//			Logging.getLogger()
//					.info("*** sendmdn Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
//							+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
//							+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);

			// Logging.getLogger().info("sendmdn lMobileNumber" + lMobileNumber);

			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				LoggingThread lt67 = new LoggingThread(
						"[" + merTxnID + "]" + "**HEADER --> " + headerName + " : " + headerValue);
				lt67.start();
				// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
			}

			HttpPost httpPost = new HttpPost(mChkImgReqUrl);
			List<NameValuePair> params = new ArrayList<>();
			params.add(new BasicNameValuePair("optxn", aTransID));
			params.add(new BasicNameValuePair("param5", param5));
			params.add(new BasicNameValuePair("sig", hash));
			params.add(new BasicNameValuePair("bua", nav_bua));
			params.add(new BasicNameValuePair("ip", mip));
			params.add(new BasicNameValuePair("plf", platform));
			params.add(new BasicNameValuePair("srnsize", scn_Size));

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));
			httpPost.setHeader("origin", "https://junosecure");
			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
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

			if (mImgResp == null) {
				LoggingThread lt68 = new LoggingThread("[" + merTxnID + "]" + "displayImage fail : ");
				lt68.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
				clt.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
				sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
			} else if (mImgResp != null && mImgResp.getStatusCode().contentEquals("JS201")
					&& mImgResp.getResult().contentEquals("YES")) {

				LoggingThread lt69 = new LoggingThread("[" + merTxnID + "]" + "displayOTP mobilenum" + lMobileNumber);
				lt69.start();
				// Logging.getLogger().info("displayOTP mobilenum" + lMobileNumber);

				if (lMobileNumber.equals("0")) {
					displayMdnpage(aTransID, request, response, false);
				} else {

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "mn", lMobileNumber);

					AuthMobDFEntity lMobData = mAuthDbService.getByMsisdn(lMobileNumber + authReqDetail.getCpID());

					if (authReqDetail.isMulitdevice()) {

						if (!sendrimsg(aTransID, lMobileNumber, authReqDetail.getSmsurl())) {
							LoggingThread lt70 = new LoggingThread("[" + merTxnID + "]" + "Send msg fail : ");
							lt70.start();
							// Logging.getLogger().info("Send msg fail : ");
							CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
							clt.start();
							// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
							sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
							return;
						} else {
							authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMobileNumber));
							authReqDetail.setSecMsisdn(mEncDecObj.encrypt("0"));
							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);
						}

						WebDesignParam webparam = mWebDesignParamRepoImpl
								.getValueFromWebDesignparamRepo(aTransID + "web");

						RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/authowait.jsp");
						request.setAttribute("t", mMultiAuthTimeout);
						request.setAttribute("optxn", aTransID);
						request.setAttribute("header", webparam.getHtext());
						request.setAttribute("hcolor", webparam.getHcolor());
						request.setAttribute("desc1",
								"We have sent an url via SMS to your mobile phone. check sms notification received. "
										+ "Click the url to Authorize the device to access the account");
						request.setAttribute("desc2", "Steps to secure Authorization");
						request.setAttribute("footer", webparam.getFtext());
						request.setAttribute("imgstr", webparam.getGifstr());

						try {
							rd.forward(request, response);
						} catch (ServletException | IOException e) {
							Logging.getLogger().info("Exception--" + e.getMessage());
						}

					} else {

						if (authReqDetail.isCliOtp()) {
							getClientOtp(aTransID, lMobileNumber, request, response);
						} else {

							if (authReqDetail.isOtpflow()) {
								SecureImageResponse authRespdetail = new SecureImageResponse();

								authRespdetail = sendImageReq(aTransID, lMobileNumber, authReqDetail.getCpID(), request,
										response, authReqDetail.getSeckey(), true, null);

								if (authRespdetail != null && authRespdetail.getStatusCode() != null
										&& authRespdetail.getStatusCode().contains("201")) {
									displayOtpImage(authRespdetail, lMobileNumber, request, response, 4, true);
									LoggingThread lt71 = new LoggingThread(
											"[" + merTxnID + "]" + "displayImage over : ");
									lt71.start();
									// Logging.getLogger().info("displayImage over : ");
								} else {
									LoggingThread lt72 = new LoggingThread(
											"[" + merTxnID + "]" + "displayImage fail : ");
									lt72.start();
									// Logging.getLogger().info("displayImage fail : ");
									CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR,
											"NA");
									clt.start();
									// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
									sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
								}
							} else {
								takeConsent(aTransID, authReqDetail.getCpID(), request, response,
										authReqDetail.getSeckey());
							}
						}
					}
				}
			} else {
				LoggingThread lt73 = new LoggingThread("[" + merTxnID + "]" + "displayImage user cancel : ");
				lt73.start();
				// Logging.getLogger().info("displayImage user cancel : ");
				CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, USER_CANCLED, "NA");
				clt.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, USER_CANCLED, "NA");
				sendResponse(authReqDetail, USER_CANCLED, "", request, response);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		MDC.clear();
	}

	private boolean sendrimsg(String aTransID, String lMobileNumber, String url) {

		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
			String lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			String enctxnID = mEncDecObj.encrypt(aTransID);

			String message = "Please click the link to authorize " + lMsisdn + " Device as your secondary devie "
					+ " https://" + System.getenv("DOMAIN_NAME") + "/Ashield/authorize?txnID=" + enctxnID;
			StringBuilder imageStr = new StringBuilder();

			HttpPost httpPost = null;

			if (TextUtils.isEmpty(url)) {
				httpPost = new HttpPost(mSendOTPUrl);
				url = mSendOTPUrl;
			} else {
				httpPost = new HttpPost(url);
			}

			List<NameValuePair> params = new ArrayList<>();
			if (url.contains(SMS_COUNTRY)) {
				params.add(new BasicNameValuePair("User", "JunoTele"));
				params.add(new BasicNameValuePair("Passwd", "Jun0@SMSC"));
				params.add(new BasicNameValuePair("Sid", "ASHELD"));
				params.add(new BasicNameValuePair("Mobilenumber", lMsisdn));
				params.add(new BasicNameValuePair("Message", message));
				params.add(new BasicNameValuePair("Mtype", "N"));
				params.add(new BasicNameValuePair("DR", "Y"));
			} else if (url.contains(BRILIENT)) {
				params.add(new BasicNameValuePair("action", "send-sms"));
				params.add(new BasicNameValuePair("api_key", "QVNoaWVsZDpAYXNoaWVsdiZ0eQ=="));
				params.add(new BasicNameValuePair("from", "8809638097774"));
				params.add(new BasicNameValuePair("to", lMsisdn));
				params.add(new BasicNameValuePair("sms", message));
			}

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
				LoggingThread lt74 = new LoggingThread(
						"[" + authReqDetail.getMerTxnID() + "]" + "send sms resp : " + imageStr.toString());
				lt74.start();
				// Logging.getLogger().info("send sms resp : " + imageStr.toString());
				return true;
			} else {
				Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private void getClientOtp(String aTransID, String lMobileNumber, HttpServletRequest request,
			HttpServletResponse response) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		String otp = getOtpfromClient(lMobileNumber, authReqDetail.getMerTxnID());

		SecureImageResponse authRespdetail = new SecureImageResponse();

		authRespdetail = sendImageReq(aTransID, lMobileNumber, authReqDetail.getCpID(), request, response,
				authReqDetail.getSeckey(), true, otp);

		if (authRespdetail != null && authRespdetail.getStatusCode() != null
				&& authRespdetail.getStatusCode().contains("201")) {
			displayOtpImage(authRespdetail, lMobileNumber, request, response, otp.length(), false);
			LoggingThread lt75 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]" + "displayImage over : ");
			lt75.start();
			// Logging.getLogger().info("displayImage over : ");
		} else {
			LoggingThread lt76 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]" + "displayImage fail : ");
			lt76.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
		}
	}

	private String getOtpfromClient(String lMobileNumber, String merTxnID) {
		return "123456";
	}

	private void displayOtpImage(SecureImageResponse mImageResp, String mobilenum, HttpServletRequest request,
			HttpServletResponse response, int clkcount, boolean sendMsg) {

		String img1 = mImageResp.getImage1();
		String img2 = mImageResp.getImage2();
		String txt = mImageResp.getPtext();
		String txnID = mImageResp.getOptxn();
		String pshare = mImageResp.getPimage();
		boolean showotp = false;

		WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");
		if (authReqDetail != null && webparam != null) {

			try {
				if (sendMsg) {
					showotp = sendotpmsg(txt, mobilenum, authReqDetail.getSmsurl());
				} else {
					showotp = true;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			if (showotp) {
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
				request.setAttribute("desc1", webparam.getDesotp1());
				request.setAttribute("desc2", webparam.getDesotp2());
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
			LoggingThread lt77 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]" + "displayImage fail : ");
			lt77.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
		}
	}

	private boolean sendotpmsg(String txt, String mobilenum, String url) {

		String message = "Your OTP is " + txt + " This OTP is valid only for 10 minutes";
		StringBuilder imageStr = new StringBuilder();
		try {
			HttpPost httpPost = null;

			if (TextUtils.isEmpty(url)) {
				httpPost = new HttpPost(mSendOTPUrl);
				url = mSendOTPUrl;
			} else {
				httpPost = new HttpPost(url);
			}

			List<NameValuePair> params = new ArrayList<>();
			if (url.contains(SMS_COUNTRY)) {
				params.add(new BasicNameValuePair("User", "JunoTele"));
				params.add(new BasicNameValuePair("Passwd", "Jun0@SMSC"));
				params.add(new BasicNameValuePair("Sid", "ASHELD"));
				params.add(new BasicNameValuePair("Mobilenumber", mobilenum));
				params.add(new BasicNameValuePair("Message", message));
				params.add(new BasicNameValuePair("Mtype", "N"));
				params.add(new BasicNameValuePair("DR", "Y"));
			} else if (url.contains(BRILIENT)) {
				message = "Your confidential one time password for mobile number authentication is " + txt
						+ ", valid for 3 min. Do not share this OTP to anyone for security reasons";
				params.add(new BasicNameValuePair("action", "send-sms"));
				params.add(new BasicNameValuePair("api_key", "QVNoaWVsZDpAYXNoaWVsdiZ0eQ=="));
				params.add(new BasicNameValuePair("from", "8809638097774"));
				params.add(new BasicNameValuePair("to", mobilenum));
				params.add(new BasicNameValuePair("sms", message));
			}

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
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
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private void sendClientResp(String txnID, String mertxnID, String resp, String pmdn, String smdn) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		TxnResp mResp = new TxnResp();

		StringBuilder imageStr = new StringBuilder();
		mResp.setStatus(resp != null ? resp : "0");
		mResp.setMertxnid(mertxnID != null ? mertxnID : "null");
		mResp.setPmdn(pmdn != null ? pmdn : "0");
		mResp.setSmdn(smdn != null ? smdn : "0");
		mResp.setAstxnid(txnID != null ? txnID : "0");

		String resps = gson.toJson(mResp);

		try {
			if (authReqDetail != null && authReqDetail.getClientURl() != null) {

				String clientUrl = authReqDetail.getClientURl();

				// Logging.getLogger().info("ClientURl : " + clientUrl);
				// Logging.getLogger().info("ClientURl resp: " + resps);

				LoggingThread lt79 = new LoggingThread("[" + authReqDetail.getMerTxnID() + "]" + "ClientURl : "
						+ clientUrl + ", ClientURl resp: " + resps);
				lt79.start();

				CloseableHttpClient client = HttpClients.createDefault();
				CloseableHttpResponse imgresponse = null;

				RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
						.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

				if (authReqDetail.getCpID().contentEquals("024")) {

					StringBuilder UrlBuilder = new StringBuilder();

					UrlBuilder.append(clientUrl);
					UrlBuilder.append("uniqueCode=");
					UrlBuilder.append(mertxnID != null ? mertxnID : "null");
					UrlBuilder.append("&mobileNumber=");
					UrlBuilder.append(pmdn != null ? pmdn : "0");
					UrlBuilder.append("&virtualMobileNo=");
					UrlBuilder.append(txnID != null ? txnID : "0");

					String httpURl = UrlBuilder.toString();

					HttpGet httpget = new HttpGet(httpURl);

					httpget.setConfig(conf);

					imgresponse = client.execute(httpget);

				} else {
					HttpPost httpPost = new HttpPost(clientUrl);

					StringEntity mEntity = new StringEntity(resps);
					httpPost.setEntity(mEntity);
					httpPost.setHeader("Content-Type", "application/json");
					httpPost.setHeader("Accept", "application/json");

					// List<NameValuePair> params = new ArrayList<>();
					// params.add(new BasicNameValuePair("resp", resps));

					// httpPost.setEntity(new
					// UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));

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
				LoggingThread lt80 = new LoggingThread(
						"[" + authReqDetail.getMerTxnID() + "]" + "sendclientresp : " + imageStr.toString());
				lt80.start();
				// Logging.getLogger().info("sendclientresp : " + imageStr.toString());
				// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(txnID + "req");
				// deleteredis(txnID);
			} else {
				LoggingThread lt81 = new LoggingThread(
						"[" + authReqDetail.getMerTxnID() + "]" + "sendclientresp : " + "Client Url not set");
				lt81.start();
				// Logging.getLogger().info("sendclientresp : " + "Client Url not set");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void saveShareVal(AuthReqDetail authReqDetail, String newTxnID, String encString1,
			HttpServletRequest request, HttpServletResponse response) {

		StringBuilder imageStr = new StringBuilder();

		try {

			String lSaveShareUrl = authReqDetail.getShareurl() + "/setShare";

			HttpPost httpPost = new HttpPost(lSaveShareUrl);
			// HttpPost httpPost=new HttpPost(mSaveShareUrl);
			List<NameValuePair> params = new ArrayList<>();

			params.add(new BasicNameValuePair("mid", authReqDetail.getCpID()));
			params.add(new BasicNameValuePair("txnId", newTxnID));
			params.add(new BasicNameValuePair("share", encString1));

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
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
			LoggingThread lt82 = new LoggingThread(
					"[" + authReqDetail.getMerTxnID() + "]" + "saveShareVal : " + imageStr.toString());
			lt82.start();
			// Logging.getLogger().info("saveShareVal : " + imageStr.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String getShareVal(String newTxnID, String aShareUrl, HttpServletRequest request,
			HttpServletResponse response) {

		StringBuilder imageStr = new StringBuilder();

		try {

			String lGetShareUrl = aShareUrl + "/getShare";

			HttpPost httpPost = new HttpPost(lGetShareUrl);

			// HttpPost httpPost=new HttpPost(mGetShareUrl);
			List<NameValuePair> params = new ArrayList<>();

			params.add(new BasicNameValuePair("txnId", newTxnID));

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
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
			LoggingThread lt83 = new LoggingThread("getShareVal : " + imageStr.toString());
			lt83.start();
			// Logging.getLogger().info("getShareVal : " + imageStr.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return imageStr.toString();
	}

	private void deleteredis(String aTransID) {

		if (mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req") != null) {
			mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "dffin") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "dffin");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "opn");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "chan");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "rdu");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "mn");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "action");
		}

		if (mMCDiscoverRespRespoImpl.getValueFromAshiledMCRedisRepo(aTransID + "_MC") != null) {
			mMCDiscoverRespRespoImpl.deleteValueFromAshiledMCRedisRepo(aTransID + "_MC");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "seskey") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "seskey");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "refid") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "refid");
		}

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "locret") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "locret");
		}
	}
}
