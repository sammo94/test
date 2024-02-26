package com.ashield.webapps;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
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

import com.ashield.datapojo.AccountInfoEntity;
import com.ashield.datapojo.AppBotRequest;
import com.ashield.datapojo.AuthMobDFEntity;
import com.ashield.datapojo.AuthReqDetail;
import com.ashield.datapojo.AuthReqValidObj;
import com.ashield.datapojo.AuthShareEntity;
import com.ashield.datapojo.AuthWebResp;
import com.ashield.datapojo.DiscoveryResponse;
import com.ashield.datapojo.ImageValidationResponse;
import com.ashield.datapojo.ImgKeyEntity;
import com.ashield.datapojo.OptVebdorEntity;
import com.ashield.datapojo.PriSecDFEntity;
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
import com.ashield.redisrepo.WebDesignparamRepoImpl;
import com.ashield.utils.AesEncryptDecrypt;
import com.ashield.utils.AshieldEncDec;
import com.ashield.utils.CommonHelper;
import com.ashield.utils.Constants;
import com.github.tsohr.JSONObject;
import com.google.gson.Gson;

@Controller
public class AuthMoControler implements Constants {

	@Autowired
	DbService mAuthDbService;

	@Autowired
	AuthTransactionIDRepoImpl mMCTrackTransRespoImpl;

	@Autowired
	AuthReqTransactionIDRepoImpl mReqTrackTransRespoImpl;

	@Autowired
	AuthwebRespTokenRepoImpl mTokenRespRepoImpl;

	@Autowired
	AshieldEncDec mEncDecObj;

	@Autowired
	WebDesignparamRepoImpl mWebDesignParamRepoImpl;

	@Autowired
	private RedisMessagePublisher redisMessagePublisher;

	@Value("${ashield.authbot.url}")
	String mAuthBotUrl;

	@Value("${mchttpTimeout}")
	int mcHttpTimeout;

	@Value("${ashield.authreq.valid.time}")
	String mValidTime;

	@Value("${ashield.appbot.appid}")
	String mAuthAppBotmid;

	@Value("${ashield.appbot.appidkey}")
	String mAuthAppBotkey;

	@Value("${ashield.authappbot.url}")
	String mAuthAppBotUrl;

	@Value("${ashield.getimg.intern.url}")
	String mGetImgUrl;

	@Value("${ashield.prime.num.url}")
	String mMultiFlowUrl;

	@Value("${ashield.session.time}")
	int mSessionTimeout;

	@Value("${ashield.imgSize}")
	String mImgSize;

	@Value("${ashield.getimg.url}")
	String mImageReqUrl;

	@Value("${ashield.dispimgmdn.url}")
	String mImageReqMOUrl;

	@Value("${ashield.dispimgemail.url}")
	String mImageReqEmailUrl;

	@Value("${ashield.chkimg.url}")
	String mChkImgReqUrl;

	@Value("${ashield.sendotp.intern.url}")
	String mSendOTPUrl;

	@Value("${ashield.multi.auth.time}")
	int mMultiAuthTimeout;

	private List<String> mSBuaList;

	Gson gson = new Gson();

	@RequestMapping(value = "/AsAuthBan")
	@ResponseBody
	String AshieldAuthentication(@RequestParam(value = "mTxnID", required = true) String aenccpTxnID,
			@RequestParam(value = "mID", required = true) String acpID,
			@RequestParam(value = "mRdu", required = true) String acpRdu,
			@RequestParam(value = "sign", required = true) String aSignature,
			@RequestParam(value = "raddr", required = false) String aRemotaddr,
			@RequestParam(value = "channel", defaultValue = "inapp") String aChannel,
			@RequestParam(value = "df", required = true) String aDeviceFin,
			@RequestParam(value = "eshare", required = true) String aDevShare,
			@RequestParam(value = "mMerTxnID", required = true) String aMerTxnID,
			@RequestParam(value = "ntype", required = true) String aNetType,
			@RequestParam(value = "simcnt", required = false, defaultValue = "1") int aSimCount,
			@RequestParam(value = "isAuth", required = false) String isAuthenticate,
			@RequestParam(value = "ts", required = false) String timestamp,
			@RequestParam(value = "ipne", required = false, defaultValue = "false") boolean isIphone,
			@RequestParam(value = "isVPN", required = false) String isVPNClent,
			@RequestParam(value = "isprime", required = false, defaultValue = "false") boolean isPrimeNum,
			@RequestParam(value = "isemail", required = false, defaultValue = "false") boolean isEmail,
			@RequestParam(value = "opn", required = false) String aOpn, HttpServletRequest request,
			HttpServletResponse response) {

		Gson gson = new Gson();

		String lRetResp = "";

		String headerName = null;
		String headerValue = null;

		long startTime = System.currentTimeMillis();

		String remoteAddr = "";
		if (aRemotaddr != null && aRemotaddr.length() > 1) {
			remoteAddr = aRemotaddr;
		} else {
			remoteAddr = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
		}

		String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null ? request.getHeader("X-FORWARDED-FOR")
				: "null";
		String userAgent = request.getHeader("user-agent");

		if (!xforwardedIP.contains("null")) {
			remoteAddr = xforwardedIP;
		}

		String aDecDeviceFin = "";
		String acpTxnID = "";
		try {
			aDecDeviceFin = mEncDecObj.decrypt(aDeviceFin, isIphone);
			acpTxnID = mEncDecObj.decrypt(aenccpTxnID, isIphone);
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		MDC.put(LOG4J_MDC_TOKEN, acpTxnID);

		String dataHashed = acpID + acpTxnID + acpRdu;

		LoggingThread lt1 = new LoggingThread("remoteAddr : " + remoteAddr + ", CPID=" + acpID + ", CPTXNID=" + acpTxnID
				+ ", CPRDU=" + acpRdu + ", DataHashed=" + dataHashed + ", Sign=" + aSignature + ", df=" + aDeviceFin
				+ ", eshare=" + aDevShare + ", MerTxnID=" + aMerTxnID + ", netType=" + aNetType + ", simcount="
				+ aSimCount + ", authtype=" + isAuthenticate + ", Channel=" + aChannel + ", isVPNClent=" + isVPNClent
				+ ", isprimeNum=" + isPrimeNum + ", Opn=" + aOpn);
		lt1.start();
//		Logging.getLogger()
//				.info("remoteAddr : " + remoteAddr + ", CPID=" + acpID + ", CPTXNID=" + acpTxnID + ", CPRDU=" + acpRdu
//						+ ", DataHashed=" + dataHashed + ", Sign=" + aSignature + ", df=" + aDeviceFin + ", eshare="
//						+ aDevShare + ", MerTxnID=" + aMerTxnID + ", netType=" + aNetType + ", simcount=" + aSimCount
//						+ ", authtype=" + isAuthenticate + ", Channel=" + aChannel + ", isVPNClent=" + isVPNClent
//						+ ", isprimeNum=" + isPrimeNum + ", Opn=" + aOpn);

		Enumeration<String> headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			headerName = headerNames.nextElement();
			Enumeration<String> headers = request.getHeaders(headerName);
			while (headers.hasMoreElements()) {
				headerValue = headers.nextElement();
			}
			LoggingThread lt2 = new LoggingThread("**HEADER --> " + headerName + " : " + headerValue);
			lt2.start();
			// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
		}

		String reqTime = CommonHelper.getFormattedDateString();

		SecureImageResponse authRespdetail = new SecureImageResponse();
		authRespdetail.setOptxn(acpTxnID);

		WebDesignParam webparam = new WebDesignParam();

		AuthReqDetail authReqDetail = new AuthReqDetail();
		try {
			authReqDetail.setCpID(acpID);
			authReqDetail.setStartTime(reqTime);
			authReqDetail.setCpRdu(acpRdu);
			authReqDetail.setCpTxnID(acpTxnID);
			authReqDetail.setDevshare(aDevShare);
			authReqDetail.setDf(aDeviceFin);
			authReqDetail.setMerTxnID(aMerTxnID);
			authReqDetail.setSimcount(aSimCount);
			authReqDetail.setIPhone(isIphone);
			authReqDetail.setSecTxnID("");
			authReqDetail.setAuthorize(false);
			authReqDetail.setTakeprime(isPrimeNum);
			authReqDetail.setChannel(aChannel);
			authReqDetail.setBua(userAgent);
			authReqDetail.setMip(xforwardedIP);
			authReqDetail.setEmail(isEmail);

		} catch (Exception e) {
			e.printStackTrace();
		}

		if (TextUtils.isEmpty(aOpn)) {
			authReqDetail.setOpnName("null");
		} else {
			authReqDetail.setOpnName(aOpn);
		}

		if (isVPNClent.contains(VPN) || isAuthenticate.contains(VPN)) {
			authReqDetail.setVpnflag(true);
		} else {
			authReqDetail.setVpnflag(false);
		}

		try {

			String operatorSecretKey = "";
			boolean emailsupport = false;
			long startTime_db = System.currentTimeMillis();

			SignKeyEntity signEnt = mAuthDbService.getByMid(acpID);

			ImgKeyEntity imgEnt = mAuthDbService.getImgByMid(acpID);

			AccountInfoEntity accEnt = mAuthDbService.getByCustomerID(acpID);

			String encKey = "";
			if (accEnt != null) {
				encKey = accEnt.getApiKey();
				// operatorSecretKey = mEncDecObj.decrypt(encKey, isIphone);
				operatorSecretKey = accEnt.getApiKey();

				authReqDetail.setSeckey(operatorSecretKey);

				LoggingThread lt3 = new LoggingThread("OrgID Key found : " + encKey);
				lt3.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
			} else {
				LoggingThread lt4 = new LoggingThread("OrgID not found : " + operatorSecretKey);
				lt4.start();
				// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return lRetResp;
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

				emailsupport = signEnt.isEnableEmailOtp();
				// emailsupport = false;

				LoggingThread lt5 = new LoggingThread("OrgID Key found : " + encKey);
				lt5.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
			} else {
				LoggingThread lt6 = new LoggingThread("OrgID not found : " + operatorSecretKey);
				lt6.start();
				// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return lRetResp;
			}

			LoggingThread lt7 = new LoggingThread(
					"DB Fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_db));
			lt7.start();
			// Logging.getLogger().info("DB Fetch ElapsedTime: " +
			// (System.currentTimeMillis() - startTime_db));

			if (isEmail && !emailsupport) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_EMAIL_SUP);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_EMAIL_SUP, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}

			if (TextUtils.isEmpty(acpTxnID)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPTXNID, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}
			if (TextUtils.isEmpty(acpRdu)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPRDU);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPRDU, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}

			if (!validateSignature(operatorSecretKey, aSignature, dataHashed)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SIGN);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_SIGN, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}

			if (!TextUtils.isEmpty(timestamp)) {
				long reqtimediff = startTime - Long.parseLong(timestamp);
				// Logging.getLogger().info("Time Difference is - " + reqtimediff);
				long minutes = TimeUnit.MILLISECONDS.toMinutes(reqtimediff);
				// Logging.getLogger().info("Time Difference in min - " + minutes);

				LoggingThread lt8 = new LoggingThread(
						"Time Difference is - " + reqtimediff + ", Time Difference in min - " + minutes);
				lt8.start();

				if (minutes > Integer.parseInt(mValidTime)) {
					getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_SRC, INVALID_ZERO,
							INVALID_ZERO);
					return lRetResp;
				}
			}

			AuthReqDetail authReqDetail_dup = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(acpTxnID + "req");

			if (authReqDetail_dup != null) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, DUPLICATE_REQ);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), DUPLICATE_REQ, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}

			String browserAgent = request.getHeader("user-agent");
			String mobileIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			String acpt = request.getHeader("accept") != null ? request.getHeader("accept") : "null";
			String msisdn = "null";
			String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
			String xRequestedWithReferer = request.getHeader("x-requested-with") != null
					? request.getHeader("x-requested-with")
					: "null";

			String botResp = getBotAnalyze(acpTxnID, mobileIp, msisdn, browserAgent, acpID, acpt, referer,
					xRequestedWithReferer, aChannel);

			String appbotkey = mEncDecObj.decrypt(mAuthAppBotkey, isIphone);

			getAPPBotAnalyze(acpTxnID, mobileIp, msisdn, browserAgent, mAuthAppBotmid, acpt, referer,
					xRequestedWithReferer, aChannel, aDeviceFin, appbotkey);

			if (!botResp.contentEquals(DEFAULT_RESP)) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, BLOCK);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), BLOCK, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}

			if (webparam != null) {
				webparam.setCpID(acpID);
				webparam.setCpTxnID(acpTxnID);
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

				/*
				 * Logging.getLogger().info("webparam : " + signEnt.getDesdata1() +
				 * signEnt.getDesdata2() + signEnt.getDesotp1() + signEnt.getDesotp2() +
				 * signEnt.getDeswifi1() + signEnt.getDeswifi2() + signEnt.getFtext() +
				 * signEnt.getHcolor() + signEnt.getHtext() + signEnt.isMclkflag() +
				 * signEnt.isWififlag() + signEnt.getImgurl() + signEnt.getAvtimgurl() +
				 * signEnt.getCliUrl() + signEnt.getRUrl() + signEnt.getSignkey());
				 */
			}

			mWebDesignParamRepoImpl.saveToWebDesignparamRepo(acpTxnID + "web", webparam);

		} catch (Exception e) {
			e.printStackTrace();
		}

		AuthReqValidObj msisdnObj = validatedevfin(acpTxnID, aDecDeviceFin, aDevShare, isIphone,
				authReqDetail.isMulitdevice(), authReqDetail.getShareurl(), request, response);

		try {
			if (msisdnObj.isStatus()) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, DUPLICATE_REQ);
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), DUPLICATE_REQ, INVALID_ZERO,
						INVALID_ZERO);
				return lRetResp;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		try {

			if (TextUtils.isEmpty(msisdnObj.getMsisdn())) {
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", aOpn);
				String lDeviceFin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "df");

//				Logging.getLogger().info("lDeviceFin repo resp :" + mEncDecObj.encrypt(lDeviceFin, isIphone));
//				Logging.getLogger().info("aDeviceFin passed value :" + mEncDecObj.encrypt(aDecDeviceFin, isIphone));

				LoggingThread lt9 = new LoggingThread(
						"lDeviceFin repo resp :" + mEncDecObj.encrypt(lDeviceFin, isIphone)
								+ ", aDeviceFin passed value :" + mEncDecObj.encrypt(aDecDeviceFin, isIphone));
				lt9.start();

				if (!TextUtils.isEmpty(lDeviceFin) && lDeviceFin.contentEquals(aDecDeviceFin)) {
					String lWifiMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "mn");

					LoggingThread lt10 = new LoggingThread("lWifiMsisdn :" + lWifiMsisdn);
					lt10.start();
					// Logging.getLogger().info("lWifiMsisdn :" + lWifiMsisdn);

					if (TextUtils.isEmpty(lWifiMsisdn)) {

						if (isEmail) {
							String getEmilImgUrl = mImageReqEmailUrl + "?mTxnID=" + acpTxnID;
							authRespdetail.setUrl(getEmilImgUrl);
							authRespdetail.setStatusCode(SUCCESS);

							String message = "ASHIELD" + acpTxnID + "#" + reqTime;
							redisMessagePublisher.publish(message);
							authReqDetail.setTelco("Wifi");
							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");

						} else if (authReqDetail.isOtpflow()) {
							String getMdnImgUrl = mImageReqMOUrl + "?mTxnID=" + acpTxnID;
							authRespdetail.setUrl(getMdnImgUrl);
							authRespdetail.setStatusCode(SUCCESS);

							String message = "ASHIELD" + acpTxnID + "#" + reqTime;
							redisMessagePublisher.publish(message);
							authReqDetail.setTelco("Wifi");
							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");

						} else {
							authRespdetail.setStatusCode(MSG_REC_FAIL);
							getLogErrorMsg(authRespdetail, gson, authReqDetail, MSG_REC_FAIL);
							sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SESSION_TIME_OUT,
									INVALID_ZERO, INVALID_ZERO);
						}
					} else {
						if (!authReqDetail.isMulitdevice()) {
							AuthMobDFEntity lMobData = mAuthDbService.getByMsisdn(lWifiMsisdn + acpID);

							if (lMobData != null && !lMobData.getDevicefin()
									.contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
								LoggingThread lt11 = new LoggingThread("DF not match : " + lMobData.getDevicefin());
								lt11.start();
								// Logging.getLogger().info("DF not match : " + lMobData.getDevicefin());
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "action", "rereg");
							} else if (lMobData != null) {
								LoggingThread lt12 = new LoggingThread("DF match : " + lMobData.getDevicefin());
								lt12.start();
								// Logging.getLogger().info("DF match : " + lMobData.getDevicefin());
							} else {
								LoggingThread lt13 = new LoggingThread("NO DF Data : ");
								lt13.start();
								// Logging.getLogger().info("NO DF Data : ");
							}
						}

						String message = "ASHIELD" + acpTxnID + "#" + reqTime;
						redisMessagePublisher.publish(message);
						authReqDetail.setTelco("Wifi");
						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", lWifiMsisdn);
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");

						if (authReqDetail.isTakeprime()) {
							String redirectUrl = mMultiFlowUrl + "?transID=" + acpTxnID;
							authRespdetail.setDispImgurl(redirectUrl);
							authRespdetail.setUrl("");
						} else {
							String displayImgUrl = mGetImgUrl + "?mTxnID=" + acpTxnID + "&mID=" + acpID;
							authRespdetail.setDispImgurl(displayImgUrl);
							authRespdetail.setUrl("");
							LoggingThread lt14 = new LoggingThread(
									" Display image over WIFI authRespdetail" + authRespdetail.getUrl());
							lt14.start();
//							Logging.getLogger()
//									.info(" Display image over WIFI authRespdetail" + authRespdetail.getUrl());
						}
					}
				} else {

					if (!TextUtils.isEmpty(lDeviceFin)) {
						String valu[] = aDecDeviceFin.split("&");
						String simID = "";
						String devID = "";

						for (String val : valu) {
							String key = val.substring(0, val.indexOf("="));
							if (key.contentEquals("deviceid")) {
								devID = val.substring(val.indexOf("=") + 1, val.length());
							} else if (key.contentEquals("simid")) {
								simID = val.substring(val.indexOf("=") + 1, val.length());
							}
						}

						if (!lDeviceFin.contains(simID) && !lDeviceFin.contains(devID)) {
							authRespdetail.setStatusCode(INVALID_DF);
							getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF);
							/*
							 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
							 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
							 */
						} else if (!lDeviceFin.contains(simID)) {
							authRespdetail.setStatusCode(INVALID_DF);
							getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF_SIM);
							/*
							 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
							 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
							 */
						} else {
							authRespdetail.setStatusCode(INVALID_DF);
							getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF_DEVICE);
							/*
							 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
							 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
							 */
						}

					} else {
						authRespdetail.setStatusCode(INVALID_CPTXNID);
						getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
						sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPTXNID,
								INVALID_ZERO, INVALID_ZERO);
					}
				}
			} else {

				String message = "ASHIELD" + acpTxnID + "#" + reqTime;
				redisMessagePublisher.publish(message);

				authReqDetail.setTelco("Auth");

				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

				if (isAuthenticate != null && (isAuthenticate.contains("YES") || isAuthenticate.contains("yes")
						|| isAuthenticate.contains("Yes"))) {
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", msisdnObj.getMsisdn());
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

					if (authReqDetail.isTakeprime() && authReqDetail.isMulitdevice()) {
						String redirectUrl = mMultiFlowUrl + "?transID=" + acpTxnID;
						authRespdetail.setDispImgurl(redirectUrl);
						authRespdetail.setUrl("");
					} else {
						lRetResp = sendShare(acpTxnID, request, response);
						authRespdetail.setUrl(lRetResp);
					}

				} else if (isAuthenticate != null && (isAuthenticate.contains("SUB") || isAuthenticate.contains("sub")
						|| isAuthenticate.contains("Sub"))) {

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", msisdnObj.getMsisdn());
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "action", "sub");

					String displayImgUrl = mGetImgUrl + "?mTxnID=" + acpTxnID + "&mID=" + acpID;
					authRespdetail.setDispImgurl(displayImgUrl);
					authRespdetail.setUrl("");

				} else {
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "mn", msisdnObj.getMsisdn());
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");
					String displayImgUrl = mGetImgUrl + "?mTxnID=" + acpTxnID + "&mID=" + acpID;
					authRespdetail.setDispImgurl(displayImgUrl);
					authRespdetail.setUrl("");

					LoggingThread lt15 = new LoggingThread(
							" Display image over authRespdetail" + authRespdetail.getUrl());
					lt15.start();
					// Logging.getLogger().info(" Display image over authRespdetail" +
					// authRespdetail.getUrl());
				}
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		MDC.clear();
		try {
			lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return lRetResp;
	}

	@RequestMapping(value = "/dispmdnotp")
	public @ResponseBody void dispmdnpag(@RequestParam(value = "mTxnID", required = true) String aTransID,
			HttpServletRequest request, HttpServletResponse response) {

		LoggingThread lt16 = new LoggingThread("dispmdnotp : ");
		lt16.start();
		// Logging.getLogger().info("dispmdnotp : ");

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		if (authReqDetail != null) {
			authReqDetail.setTelco("OTP");
			displayMdnpage(aTransID, request, response, false);
		} else {
			LoggingThread lt17 = new LoggingThread("dispmdnotp fail : ");
			lt17.start();
			// Logging.getLogger().info("dispmdnotp fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendClientResp(aTransID, "", SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
		}
	}

	@RequestMapping(value = "/dispemailotp")
	public @ResponseBody void dispemailpag(@RequestParam(value = "mTxnID", required = true) String aTransID,
			HttpServletRequest request, HttpServletResponse response) {

		LoggingThread lt18 = new LoggingThread("dispemailpag : ");
		lt18.start();
		// Logging.getLogger().info("dispemailpag : ");

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		if (authReqDetail != null) {
			authReqDetail.setTelco("OTP");
			displayEmailpage(aTransID, request, response);
		} else {
			LoggingThread lt19 = new LoggingThread("dispmdnotp fail : ");
			lt19.start();
			// Logging.getLogger().info("dispmdnotp fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendClientResp(aTransID, "", SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
		}
	}

	@RequestMapping(value = "/web-bng-authen")
	public @ResponseBody void WebAuthenticate(@RequestParam("mertxnid") String mertxnID,
			@RequestParam("mid") String mID, @RequestParam("ts") String timestamp,
			@RequestParam(value = "authtype", required = false) String authtype,
			@RequestParam(value = "redurl", required = false) String aRedURl,
			@RequestParam(value = "isemail", required = false, defaultValue = "false") boolean isEmail,
			@RequestParam("sign") String signature, HttpServletRequest request, HttpServletResponse response) {

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

			LoggingThread lt20 = new LoggingThread("WebAuthenticate " + " starttime: " + startTime + " mID:" + mID
					+ " mertxnID:" + mertxnID + " timestamp: " + timestamp + " authtype:" + authtype + " aRedURl:"
					+ aRedURl + ", isemail:" + isEmail + " hash: " + signature + " ** hashstring: " + dataHashed);
			lt20.start();
//			Logging.getLogger()
//					.info("WebAuthenticate " + " starttime: " + startTime + " mID:" + mID + " mertxnID:" + mertxnID
//							+ " timestamp: " + timestamp + " authtype:" + authtype + " aRedURl:" + aRedURl
//							+ ", isemail:" + isEmail + " hash: " + signature + " ** hashstring: " + dataHashed);

			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				LoggingThread lt21 = new LoggingThread("**HEADER --> " + headerName + " : " + headerValue);
				lt21.start();
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
			authReqDetail.setEmail(isEmail);

			String operatorSecretKey = "";
			boolean emailsupport = false;
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

				LoggingThread lt22 = new LoggingThread("OrgID Key found : " + encKey);
				lt22.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
			} else {
				LoggingThread lt23 = new LoggingThread("OrgID not found : " + operatorSecretKey);
				lt23.start();
				// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sendResponse(authReqDetail, INVALID_CPID, INVALID_TOKEN, request, response);
				return;
			}

			if (signEnt != null) {

				lRdUrl = signEnt.getTokenRedirectUrl();
				authReqDetail.setCpRdu(lRdUrl);

				authReqDetail.setSeckey(operatorSecretKey);

				authReqDetail.setOtpflow(signEnt.isEnableOtpFlow());
				authReqDetail.setClientURl(signEnt.getIdentityCallbackUrl());
				authReqDetail.setCliOtp(!signEnt.isGenerateOtp());

				// authReqDetail.setNoconsent(signEnt.isNoconsent());
				authReqDetail.setNoconsent(false);

				// authReqDetail.setSmsurl(signEnt.getSmsurl());

				authReqDetail.setMulitdevice(signEnt.isMultiDevice());

				/*
				 * authReqDetail.setDemography(signEnt.isDemography());
				 * authReqDetail.setDiUrl(signEnt.getDiurl());
				 * authReqDetail.setShareurl(signEnt.getShareurl());
				 * authReqDetail.setSmsurl(signEnt.getSmsurl());
				 */

				emailsupport = signEnt.isEnableEmailOtp();
				// emailsupport = false;

				LoggingThread lt24 = new LoggingThread("OrgID Key found : " + encKey + "- url = " + lRdUrl);
				lt24.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey + "- url = " +
				// lRdUrl);
			} else {
				LoggingThread lt25 = new LoggingThread("OrgID not found : " + operatorSecretKey);
				lt25.start();
				// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sendResponse(authReqDetail, INVALID_CPID, INVALID_TOKEN, request, response);
				return;
			}
			LoggingThread lt26 = new LoggingThread(
					"DB Fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_db));
			lt26.start();
			// Logging.getLogger().info("DB Fetch ElapsedTime: " +
			// (System.currentTimeMillis() - startTime_db));

			if (isEmail && !emailsupport) {
				LoggingThread lt27 = new LoggingThread("INVALID: Email Support ");
				lt27.start();
				// Logging.getLogger().info("INVALID: Email Support ");
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_EMAIL_SUP);
				sendResponse(authReqDetail, INVALID_CPTXNID, INVALID_TOKEN, request, response);
				return;
			}

			if (TextUtils.isEmpty(mertxnID)) {
				LoggingThread lt28 = new LoggingThread("INVALID: mertxnID ");
				lt28.start();
				// Logging.getLogger().info("INVALID: mertxnID ");
				getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
				sendResponse(authReqDetail, INVALID_CPTXNID, INVALID_TOKEN, request, response);
				return;
			}

			if (!TextUtils.isEmpty(aRedURl)) {
				if (!aRedURl.contains("?")) {
					aRedURl = aRedURl + "?";
				}
				// Logging.getLogger().info("aRedURl: " + aRedURl);
				// Logging.getLogger().info("lRdUrl: " + lRdUrl);

				LoggingThread lt29 = new LoggingThread("aRedURl: " + aRedURl + ", lRdUrl:  " + lRdUrl);
				lt29.start();

				if (!aRedURl.contains(lRdUrl.substring(0, lRdUrl.length() - 1))) {
					LoggingThread lt30 = new LoggingThread("INVALID: aRedURl ");
					lt30.start();
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

			LoggingThread lt31 = new LoggingThread(
					"ipAddress - " + ipAddress + ", userAgent-" + userAgent + ", accept-" + accept);
			lt31.start();
			// Logging.getLogger().info("ipAddress - " + ipAddress + ", userAgent-" +
			// userAgent + ", accept-" + accept);

			long reqtimediff = startTime - Long.parseLong(timestamp);
			// Logging.getLogger().info("Time Difference is - " + reqtimediff);
			long minutes = TimeUnit.MILLISECONDS.toMinutes(reqtimediff);
			// Logging.getLogger().info("Time Difference in min - " + minutes);

			LoggingThread lt32 = new LoggingThread(
					"Time Difference is - " + reqtimediff + ", Time Difference in min - " + minutes);
			lt32.start();

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

			String mCookieValue = "";
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				for (Cookie c : cookies) {
					if (c.getName().equals("authshare")) {
						mCookieValue = c.getValue();
					}
				}
			}
			LoggingThread lt33 = new LoggingThread(" mCookieValue:" + mCookieValue);
			lt33.start();
			// Logging.getLogger().info(" mCookieValue:" + mCookieValue);

			String asTxnID = "";
			String asShare = "";

			if (!TextUtils.isEmpty(mCookieValue)) {
				mCookieValue = mEncDecObj.decrypt(mCookieValue);
				String txnlenght = mCookieValue.substring(0, 2);
				asTxnID = mCookieValue.substring(2, Integer.parseInt(txnlenght) + 2);
				asShare = mCookieValue.substring(2 + Integer.parseInt(txnlenght), mCookieValue.length());

				LoggingThread lt34 = new LoggingThread(
						"txnlenght - " + txnlenght + "asTxnID - " + asTxnID + ", share-" + asShare);
				lt34.start();
				// Logging.getLogger().info("txnlenght - " + txnlenght + "asTxnID - " + asTxnID
				// + ", share-" + asShare);
			}
			deviceFin = userAgent + accept;

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

	private void getLogErrorMsg(SecureImageResponse authRespdetail, Gson gson, AuthReqDetail authDetail,
			String statusCode) {
		authRespdetail.setStatusCode(statusCode);
		CDRLoggingThread clt = new CDRLoggingThread(authDetail, "null", statusCode, "NA");
		clt.start();
		// CDRLogging.getCDRWriter().logCDR(authDetail, "null", statusCode, "NA");
		LoggingThread lt35 = new LoggingThread("authResp" + gson.toJson(authRespdetail, SecureImageResponse.class));
		lt35.start();
		// Logging.getLogger().info("authResp" + gson.toJson(authRespdetail,
		// SecureImageResponse.class));
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

		try {
			List<PriSecDFEntity> mPmdnlist = mAuthDbService.getBypMdn(pmdn);

			LoggingThread lt36 = new LoggingThread("mPmdnlist count : " + mPmdnlist.size());
			lt36.start();
			// Logging.getLogger().info("mPmdnlist count : " + mPmdnlist.size());

		} catch (Exception e) {
			e.printStackTrace();
		}

		String resps = gson.toJson(mResp);
		try {
			if (authReqDetail != null) {

				String clientUrl = authReqDetail.getClientURl();

				if (clientUrl != null) {

					// Logging.getLogger().info("ClientURl : " + clientUrl);
					// Logging.getLogger().info("ClientURl resp: " + resps);

					LoggingThread lt37 = new LoggingThread("ClientURl : " + clientUrl + ", ClientURl resp: " + resps);
					lt37.start();

					CloseableHttpClient client = HttpClients.createDefault();
					CloseableHttpResponse imgresponse = null;

					RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
							.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

					HttpPost httpPost = new HttpPost(clientUrl);

					StringEntity mEntity = new StringEntity(resps);
					httpPost.setEntity(mEntity);
					httpPost.setHeader("Content-Type", "application/json");
					httpPost.setHeader("Accept", "application/json");

					httpPost.setConfig(conf);

					imgresponse = client.execute(httpPost);

					if (imgresponse.getStatusLine().getStatusCode() == 200) {
						BufferedReader br = new BufferedReader(
								new InputStreamReader(imgresponse.getEntity().getContent()));
						String readLine;
						while (((readLine = br.readLine()) != null)) {
							imageStr.append(readLine);
						}
					} else {
						Logging.getLogger().error(imgresponse.toString());
						System.out.println(imgresponse);
					}
					// Logging.getLogger().info("sendclientresp : " + resps);
					// Logging.getLogger().info("sendclientresp : " + imageStr.toString());
					LoggingThread lt38 = new LoggingThread(
							"sendclientresp : " + resps + ", sendclientresp : " + imageStr.toString());
					lt38.start();
				} else {
					LoggingThread lt39 = new LoggingThread("sendclientresp : " + "Client Url not set");
					lt39.start();
					// Logging.getLogger().info("sendclientresp : " + "Client Url not set");
				}
			} else {
				LoggingThread lt40 = new LoggingThread("sendclientresp : " + "Client Url not set");
				lt40.start();
				// Logging.getLogger().info("sendclientresp : " + "Client Url not set");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	boolean validateSignature(String operatorSecretKey, String hash, String dataHashed)
			throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		boolean result = true;
		String hashres = CommonHelper.generateSign(operatorSecretKey, dataHashed);
		// Logging.getLogger().info("datatohashmc : " + dataHashed);
		// Logging.getLogger().info("hashres : " + hashres);

		LoggingThread lt41 = new LoggingThread("datatohashmc : " + dataHashed + ", hashres : " + hashres);
		lt41.start();

		if (!hashres.contentEquals(hash)) {
			result = false;
		}
		return result;
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
				// System.out.println(imgresponse);
			}
			resp = respStr.toString();
			LoggingThread lt42 = new LoggingThread("BotRespVal : " + resp);
			lt42.start();
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
			LoggingThread lt43 = new LoggingThread("AppBotRespVal : " + resp);
			lt43.start();
			// Logging.getLogger().info("AppBotRespVal : " + resp);

		} catch (Exception e) {
			ErrorLogging.getLogger().info("Auth APP Bot error " + e.getMessage());
		}
		return resp;
	}

	private AuthReqValidObj validatedevfin(String acpTxnID, String aDeviceFin, String aDevShare, boolean isIphone,
			boolean multidev, String aShareUrl, HttpServletRequest request, HttpServletResponse response) {

		AuthReqValidObj respObj = new AuthReqValidObj();

		AuthShareEntity authEntity = mAuthDbService.getByNewtxnID(acpTxnID);

		if (authEntity != null) {

			String share3 = ""; // getShareVal(acpTxnID, aShareUrl, request, response);

			long startTime_url = System.currentTimeMillis();
			// Logging.getLogger().info("Share from url: " + share3);
			// Logging.getLogger().info("Share URL fetch ElapsedTime: " +
			// (System.currentTimeMillis() - startTime_url));

			LoggingThread lt44 = new LoggingThread("Share from url: " + share3 + ", Share URL fetch ElapsedTime: "
					+ (System.currentTimeMillis() - startTime_url));
			lt44.start();

			String share1 = authEntity.getShare1();
			String share2 = authEntity.getShare2();
			String msisdn = authEntity.getMsisdn();
			String opn = authEntity.getOpn();
			String mID = authEntity.getMid();
			boolean authed = authEntity.isAuthed();

			if (TextUtils.isEmpty(share3)) {
				share3 = authEntity.getShare3();
			}

			respObj.setStatus(authed);

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", opn);

			if (!authed) {
				authEntity.setAuthed(true);
				mAuthDbService.saveShare(authEntity);
			}

			String decShare1 = "";
			String decShare2 = "";
			String decShare3 = "";
			String condecshare = "";

			try {

				String decMsisdn = mEncDecObj.decrypt(msisdn, isIphone);

				AuthMobDFEntity mModData = mAuthDbService.getByMsisdn(decMsisdn + mID);

				if (mModData != null) {
					LoggingThread lt45 = new LoggingThread("msisdn def :" + mModData.getDevicefin());
					lt45.start();
					// Logging.getLogger().info("msisdn def :" + mModData.getDevicefin());
				}

				decShare1 = mEncDecObj.decrypt(share1, isIphone /* , mEncDecObj.decrypt(mEncKey1) */);
				decShare2 = mEncDecObj.decrypt(share2, isIphone /* , mEncDecObj.decrypt(mEncKey2) */);
				decShare3 = mEncDecObj.decrypt(share3, isIphone /* , mEncDecObj.decrypt(mEncKey3) */);
				String decr = decShare1 + decShare2 + decShare3;
				condecshare = mEncDecObj.decrypt(decr, isIphone /* , mEncDecObj.decrypt(mEncKey4) */);

				String txnidLen = condecshare.substring(condecshare.length() - 2, condecshare.length());

				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(txnidLen) - 2);

				String msisdnlen = condecshare.substring(condecshare.length() - 2, condecshare.length());

				String msisdnshre = condecshare.substring(condecshare.length() - Integer.valueOf(msisdnlen),
						condecshare.length() - 2);

				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(msisdnlen) - 2);

				// Logging.getLogger().info("msisdnshre :" + msisdnshre);

				if ((multidev || (mModData != null && mModData.getDevicefin().contentEquals(aDeviceFin)))
						&& aDevShare.contentEquals(share1) && condecshare.contentEquals(aDeviceFin)) {
					respObj.setMsisdn(mEncDecObj.decrypt(msisdn, isIphone));
					LoggingThread lt46 = new LoggingThread(
							"validatedevfin :" + mEncDecObj.encrypt(respObj.getMsisdn(), isIphone));
					lt46.start();
					// Logging.getLogger().info("validatedevfin :" +
					// mEncDecObj.encrypt(respObj.getMsisdn(), isIphone));
				} else {
					respObj.setMsisdn("");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

		} else {
			LoggingThread lt47 = new LoggingThread("authEntity : null for txnID :" + acpTxnID);
			lt47.start();
			// Logging.getLogger().info("authEntity : null for txnID :" + acpTxnID);
		}
		return respObj;
	}

	public String getTransID() {

		UUID uuid = UUID.randomUUID();

		return uuid.toString() + "saas";
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
			lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			LoggingThread lt48 = new LoggingThread("sendShare:" + "lDevicefin: " + mEncDecObj.encrypt(lDevicefin));
			lt48.start();
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

			LoggingThread lt49 = new LoggingThread("encval:" + encval);
			lt49.start();
			// Logging.getLogger().info("encval:" + encval);

			String mEncDf = mEncDecObj.encrypt(encval, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey4) */);
			LoggingThread lt50 = new LoggingThread("sendShare:" + "mEncDf: " + mEncDf);
			lt50.start();
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
				EncString1 = mEncDecObj.encrypt(s1, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey1) */);
				EncString2 = mEncDecObj.encrypt(s2, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey2) */);
				EncString3 = mEncDecObj.encrypt(s3, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey3) */);
			} catch (Exception e) {
				e.printStackTrace();
			}

			// Logging.getLogger().info("Crypto Share 1 : " + EncString1);
			// Logging.getLogger().info("Crypto Share 2 : " + EncString2);
			// Logging.getLogger().info("Crypto Share 3 : " + EncString3);

			LoggingThread lt51 = new LoggingThread("Crypto Share 1 : " + EncString1 + ", Crypto Share 2 : " + EncString2
					+ ", Crypto Share 3 : " + EncString3);
			lt51.start();

			AuthShareEntity mEntity = new AuthShareEntity();

			mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()));
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

			boolean isVPNClient = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "vpn") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "vpn").equals("YES");

			LoggingThread lt52 = new LoggingThread(
					"isVPNClient : " + isVPNClient + ", authReqDetail.isVpnflag() :" + authReqDetail.isVpnflag());
			lt52.start();
//			Logging.getLogger()
//					.info("isVPNClient : " + isVPNClient + ", authReqDetail.isVpnflag() :" + authReqDetail.isVpnflag());

			if (authReqDetail.isVpnflag() && isVPNClient) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "vpn");

				if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(lMsisdn + "vpnreq") != null) {
					authReqDetail.setVpnServerReq(SUCCESS);
					String reqTime = CommonHelper.getFormattedDateString();

					String message = "VPNASHIELD" + lMsisdn + "#" + reqTime;
					redisMessagePublisher.publish(message);

					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(lMsisdn + "vpnres", authReqDetail);
				} else {
					LoggingThread lt53 = new LoggingThread("NO_VPN_DATA");
					lt53.start();
					// Logging.getLogger().info("NO_VPN_DATA");
					authReqDetail.setVpnServerReq(NO_VPN_DATA);
				}
			}

			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail,
					mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, "YES");
			clt.start();
//			CDRLogging.getCDRWriter().logCDR(authReqDetail, mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()),
//					SUCCESS, "YES");

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

			String redirectUrl = "";
			if (wap) {

				AuthWebResp resp = new AuthWebResp();

				String shareval = newTxnID.length() + newTxnID + EncString1;
				LoggingThread lt54 = new LoggingThread("**shareval--> " + shareval);
				lt54.start();
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
			} else {

				redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone())
						+ "&txnid=" + newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result=" + "YES"
						+ "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn=" + lOpn
						+ "&secmsisdn=" + mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone());
			}
			// saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

			sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn, authReqDetail.getSecMsisdn());
			if (!wap) {
				deleteredis(aTransID);
			}
			MDC.clear();
			return redirectUrl;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private void displayEmailpage(String txnID, HttpServletRequest request, HttpServletResponse response) {

		SecureImageResponse authRespdetail = new SecureImageResponse();

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		authRespdetail = sendImageReq(txnID, "null", authReqDetail.getCpID(), request, response,
				authReqDetail.getSeckey(), false, null);

		if (authRespdetail != null && authRespdetail.getStatusCode() != null
				&& authRespdetail.getStatusCode().contains("201")) {

			WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");
			RequestDispatcher rd = null;

			rd = request.getRequestDispatcher("/WEB-INF/jsp/email.jsp");

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
			request.setAttribute("desc1", "Enter Email address");
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

			LoggingThread lt56 = new LoggingThread("displayImage over : ");
			lt56.start();
			// Logging.getLogger().info("displayImage over : ");
		} else {
			LoggingThread lt57 = new LoggingThread("displayImage fail : ");
			lt57.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
					INVALID_ZERO);
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
				rd = request.getRequestDispatcher("/WEB-INF/jsp/mdnmo.jsp");
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

			LoggingThread lt58 = new LoggingThread("displayImage over : ");
			lt58.start();
			// Logging.getLogger().info("displayImage over : ");
		} else {
			LoggingThread lt59 = new LoggingThread("displayImage fail : ");
			lt59.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
			sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
					INVALID_ZERO);
		}
	}

	public SecureImageResponse sendImageReq(String aTransID, String aMsisdn, String aMid, HttpServletRequest aRequest,
			HttpServletResponse response, String operatorSecretKey, boolean otpimg, String otp) {

		SecureImageResponse lImageRs = new SecureImageResponse();
		try {

			LoggingThread lt60 = new LoggingThread(
					"getsecure-img:" + "txnID: " + aTransID + ",msisdn:" + mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid);
			lt60.start();
//			Logging.getLogger().info(
//					"getsecure-img:" + "txnID: " + aTransID + ",msisdn:" + mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid);

			if (!TextUtils.isEmpty(aMid)) {
				StringBuilder imageStr = new StringBuilder();

				String browserAgent = aRequest.getHeader("user-agent");
				String size = mImgSize;
				String mobileIp = aRequest.getHeader("X-Forwarded-For") != null ? aRequest.getHeader("X-Forwarded-For")
						: "null";
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
				String sig = CommonHelper.generateSign(operatorSecretKey, dataToBeHashed);

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
			ErrorLogging.getLogger().info("Get Img error " + e.getMessage());
		}

		return lImageRs;
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
			boolean otpflow = authReqDetail.isOtpflow();
			DiscoveryResponse lDiscRep = null;
			String resp = "";

			AuthReqValidObj msisdnObj = validatedevfin(asTxnID, devicefin, asShare, false,
					authReqDetail.isMulitdevice(), shareUrl, request, response);

			if (msisdnObj.isStatus()) {
				getLogErrorMsg(authRespdetail, gson, authReqDetail, DUPLICATE_REQ);
				sendResponse(authReqDetail, DUPLICATE_REQ, INVALID_TOKEN, request, response);
				return;
			}

			if (TextUtils.isEmpty(msisdnObj.getMsisdn())) {

				if (authReqDetail.isEmail()) {
					authReqDetail.setTelco("Email");
					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");
					displayEmailpage(asTxnID, request, response);
				} else if (otpflow) {
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

			} else {

				authReqDetail.setTelco("Auth");
				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(asTxnID + "req", authReqDetail);

				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "chan", "wap");
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "df", devicefin);
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "mn", msisdnObj.getMsisdn());
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(asTxnID + "rdu", asRedUrl);

				if (authtype != null && (authtype.contains("YES") || authtype.contains("yes"))) {

					resp = sendShare(asTxnID, request, response);
					if (!authReqDetail.isNoconsent()) {
						response.sendRedirect(resp);
					}

				} else {
					takeConsent(asTxnID, aMid, request, response, authReqDetail.getSeckey());
				}
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void takeConsent(String asTxnID, String aMid, HttpServletRequest request, HttpServletResponse response,
			String seckey) {

		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(asTxnID + "req");

			SecureImageResponse authRespdetail = new SecureImageResponse();

			String msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(asTxnID + "mn");

			authRespdetail = sendImageReq(asTxnID, msisdn, aMid, request, response, seckey, false, null);

			if (authRespdetail != null && authRespdetail.getStatusCode() != null
					&& authRespdetail.getStatusCode().contains("201")) {
				displayImage(authRespdetail, request, response);
				LoggingThread lt61 = new LoggingThread("displayImage over : ");
				lt61.start();
				// Logging.getLogger().info("displayImage over : ");
			} else {
				LoggingThread lt62 = new LoggingThread("displayImage fail : ");
				lt62.start();
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

	@RequestMapping(value = "/sendemail")
	public @ResponseBody void displayemailOTP(@RequestParam("mdnum") String aesplatform,
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

		LoggingThread lt63 = new LoggingThread("displayOTP txnID" + aTransID);
		lt63.start();
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

				LoggingThread lt64 = new LoggingThread("*********************AES Encrypted_platform from JS - "
						+ aesplatform + ", *********************AES encrypted value of aesplatform --> salt :" + " "
						+ salt + ", iv : " + iv + ", ciphertext : " + ciphertext
						+ ", *********************AES Decrypted platform from JS - " + lMobileNumber);
				lt64.start();

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

			LoggingThread lt65 = new LoggingThread("*** sendmdn Parameters *** purchaseId : " + aTransID
					+ ", UserAgent : " + userAgent + ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP
					+ ", clientIP : " + clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : "
					+ param5 + "\n" + "sendmdn lMobileNumber" + lMobileNumber);
			lt65.start();
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
				LoggingThread lt66 = new LoggingThread("**HEADER --> " + headerName + " : " + headerValue);
				lt66.start();
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
				LoggingThread lt67 = new LoggingThread("displayImage fail : ");
				lt67.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
				clt.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
				sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
			} else if (mImgResp != null && mImgResp.getStatusCode().contentEquals("JS201")
					&& mImgResp.getResult().contentEquals("YES")) {

				LoggingThread lt68 = new LoggingThread("displayOTP mobilenum" + lMobileNumber);
				lt68.start();
				// Logging.getLogger().info("displayOTP mobilenum" + lMobileNumber);

				if (lMobileNumber.equals("0")) {
					displayEmailpage(aTransID, request, response);
				} else {

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "mn", lMobileNumber);

					if (authReqDetail.isCliOtp()) {
						getClientOtp(aTransID, lMobileNumber, request, response);
					} else {

						if (authReqDetail.isOtpflow()) {
							SecureImageResponse authRespdetail = new SecureImageResponse();

							authRespdetail = sendImageReq(aTransID, "null", authReqDetail.getCpID(), request, response,
									authReqDetail.getSeckey(), false, null);

							if (authRespdetail != null && authRespdetail.getStatusCode() != null
									&& authRespdetail.getStatusCode().contains("201")) {

								String otp = CommonHelper.getOtp();
								boolean sendemail = sendEmail(lMobileNumber, otp);

								if (sendemail) {

									authRespdetail.setPtext(otp);

									displayOtpImage(authRespdetail, lMobileNumber, request, response, 4, false);
									LoggingThread lt69 = new LoggingThread("displayImage over : ");
									lt69.start();
									// Logging.getLogger().info("displayImage over : ");
								} else {
									LoggingThread lt70 = new LoggingThread("Send Email fail : ");
									lt70.start();
									// Logging.getLogger().info("Send Email fail : ");
									CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR,
											"NA");
									clt.start();
									// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
									sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
								}
							} else {
								LoggingThread lt71 = new LoggingThread("displayImage fail : ");
								lt71.start();
								// Logging.getLogger().info("displayImage fail : ");
								CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
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
			} else {
				LoggingThread lt72 = new LoggingThread("User Canceled request : ");
				lt72.start();
				// Logging.getLogger().info("User Canceled request : ");
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

	private boolean sendEmail(String lMobileNumber, String otp) {

		try {

			String body = "<p>Dear user,</p>" + "<p>Greetings from Zee5</p>"
					+ "<p>Your Register /Login One Time Password (OTP) is: <b>" + otp + "</b></p>"
					+ "<p>Please note that this Password is valid for" + "3 Min" + "and will expire after this period."
					+ "<p>Thank you for registering / login request.</p><br><br><p>** "
					+ "This is an auto-generated email. Please do not reply to this email.**</p>";

			Properties props = new Properties();
			props.put("mail.smtp.auth", "true");
			props.put("mail.smtp.starttls.enable", "true");
			props.put("mail.smtp.host", "smtp.gmail.com");
			props.put("mail.smtp.port", "587");

			Session session = Session.getInstance(props, new javax.mail.Authenticator() {
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication("info@ashield.co", "Inf0_@2!20");
				}
			});

			Message msg = new MimeMessage(session);
			msg.setFrom(new InternetAddress("info@ashield.co", false));

			msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(lMobileNumber));
			msg.setSubject("Login OTP");
			msg.setContent(body, "text/html");
			msg.setSentDate(new Date());

			Transport.send(msg);

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@RequestMapping(value = "/sendmomdn")
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

		LoggingThread lt73 = new LoggingThread("displayOTP txnID" + aTransID);
		lt73.start();
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

				LoggingThread lt74 = new LoggingThread("*********************AES Encrypted_platform from JS - "
						+ aesplatform + ", *********************AES encrypted value of aesplatform --> salt :" + " "
						+ salt + ", iv : " + iv + ", ciphertext : " + ciphertext
						+ ", *********************AES Decrypted platform from JS - " + lMobileNumber);
				lt74.start();

			}

			String MobileNumber = decrypted_aesdata != null
					? URLDecoder.decode(decrypted_aesdata.split("\\*")[0], "UTF-8")
					: "null";
			String platform = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[1], "UTF-8")
					: "null";
			String scn_Size = decrypted_aesdata != null ? decrypted_aesdata.split("\\*")[2] : "null";
			String nav_bua = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[3], "UTF-8")
					: "null";

			StringBuilder mobileBuilder = new StringBuilder();

			mobileBuilder.append("88").append(MobileNumber);

			lMobileNumber = mobileBuilder.toString();

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

			LoggingThread lt75 = new LoggingThread("*** sendmdn Parameters *** purchaseId : " + aTransID
					+ ", UserAgent : " + userAgent + ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP
					+ ", clientIP : " + clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : "
					+ param5 + "\n" + "sendmdn lMobileNumber" + lMobileNumber);
			lt75.start();
//			Logging.getLogger()
//					.info("*** sendmdn Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
//							+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
//							+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);
//
//			Logging.getLogger().info("sendmdn lMobileNumber" + lMobileNumber);

			Enumeration<String> headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				LoggingThread lt76 = new LoggingThread("**HEADER --> " + headerName + " : " + headerValue);
				lt76.start();
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
				LoggingThread lt77 = new LoggingThread("displayImage fail : ");
				lt77.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
				clt.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
				sendResponse(authReqDetail, SERVER_ERROR, "", request, response);
			} else if (mImgResp != null && mImgResp.getStatusCode().contentEquals("JS201")
					&& mImgResp.getResult().contentEquals("YES")) {

				LoggingThread lt78 = new LoggingThread("displayOTP mobilenum" + lMobileNumber);
				lt78.start();
				// Logging.getLogger().info("displayOTP mobilenum" + lMobileNumber);

				if (lMobileNumber.equals("880")) {
					displayMdnpage(aTransID, request, response, false);
				} else {

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "mn", lMobileNumber);

					AuthMobDFEntity lMobData = mAuthDbService.getByMsisdn(lMobileNumber + authReqDetail.getCpID());

					if (lMobData != null && lMobData.getChannel().contentEquals("inapp")
							&& authReqDetail.isMulitdevice()) {

						if (!sendrimsg(aTransID, lMobileNumber, authReqDetail.getSmsurl())) {
							LoggingThread lt79 = new LoggingThread("Send msg fail : ");
							lt79.start();
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

								authRespdetail = sendImageReq(aTransID, "null", authReqDetail.getCpID(), request,
										response, authReqDetail.getSeckey(), false, null);

								if (authRespdetail != null && authRespdetail.getStatusCode() != null
										&& authRespdetail.getStatusCode().contains("201")) {

									authRespdetail.setPtext(CommonHelper.getOtp());

									displayOtpImage(authRespdetail, lMobileNumber, request, response, 4, true);
									LoggingThread lt80 = new LoggingThread("displayImage over : ");
									lt80.start();
									// Logging.getLogger().info("displayImage over : ");
								} else {
									LoggingThread lt81 = new LoggingThread("displayImage fail : ");
									lt81.start();
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
				LoggingThread lt83 = new LoggingThread("User canceled : ");
				lt83.start();
				// Logging.getLogger().info("User canceled : ");
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
					return true;
				}
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

		authRespdetail = sendImageReq(aTransID, "null", authReqDetail.getCpID(), request, response,
				authReqDetail.getSeckey(), false, otp);

		if (authRespdetail != null && authRespdetail.getStatusCode() != null
				&& authRespdetail.getStatusCode().contains("201")) {

			authRespdetail.setPtext(otp);

			displayOtpImage(authRespdetail, lMobileNumber, request, response, otp.length(), false);
			LoggingThread lt84 = new LoggingThread("displayImage over : ");
			lt84.start();
			// Logging.getLogger().info("displayImage over : ");
		} else {
			LoggingThread lt85 = new LoggingThread("displayImage fail : ");
			lt85.start();
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

			authReqDetail.setSenotp(txt);

			mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);
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
				RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/inotp.jsp");

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
			LoggingThread lt86 = new LoggingThread("displayImage fail : ");
			lt86.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt.start();
		//	CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
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
				LoggingThread lt87 = new LoggingThread("send sms resp : " + imageStr.toString());
				lt87.start();
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

		if (mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web") != null) {
			mWebDesignParamRepoImpl.deleteValueFromWebDesignparamRepo(aTransID + "web");
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
