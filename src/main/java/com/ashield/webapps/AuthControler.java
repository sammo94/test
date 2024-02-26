package com.ashield.webapps;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.ashield.config.SetMerConfig;
import com.ashield.datapojo.AccountInfoEntity;
import com.ashield.datapojo.AppBotRequest;
import com.ashield.datapojo.AsAuthPojo;
import com.ashield.datapojo.AuthMobDFEntity;
import com.ashield.datapojo.AuthMobResp;
import com.ashield.datapojo.AuthMobTxnEntity;
import com.ashield.datapojo.AuthRegistryDoc;
import com.ashield.datapojo.AuthReqDetail;
import com.ashield.datapojo.AuthReqValidObj;
import com.ashield.datapojo.AuthShareEntity;
import com.ashield.datapojo.AuthStatus;
import com.ashield.datapojo.AuthTxnRec;
import com.ashield.datapojo.AuthWebResp;
import com.ashield.datapojo.DemoGraphyResp;
import com.ashield.datapojo.DiscoveryResponse;
import com.ashield.datapojo.GetNumberPojo;
import com.ashield.datapojo.GetTxnIdPojo;
import com.ashield.datapojo.ImageValidationResponse;
import com.ashield.datapojo.ImgKeyEntity;
import com.ashield.datapojo.InfobipCallbackResponse;
import com.ashield.datapojo.OptVebdorEntity;
import com.ashield.datapojo.PriSecDFEntity;
import com.ashield.datapojo.RegId;
import com.ashield.datapojo.RegTxnRec;
import com.ashield.datapojo.SecureImageResponse;
import com.ashield.datapojo.SetMsisdnPojo;
import com.ashield.datapojo.SignKeyEntity;
import com.ashield.datapojo.Smsc;
import com.ashield.datapojo.TokenResponse;
import com.ashield.datapojo.TransIDReq;
import com.ashield.datapojo.TxnResp;
import com.ashield.datapojo.UserInfoResponse;
import com.ashield.datapojo.WebAuthSign;
import com.ashield.datapojo.WebDesignParam;
import com.ashield.dbservice.DbService;
import com.ashield.logThread.CDRLoggingThread;
import com.ashield.logThread.ErrorLoggingThread;
import com.ashield.logThread.LoggingErrorThread;
import com.ashield.logThread.LoggingThread;
import com.ashield.logThread.TimeDiffLogThread;
import com.ashield.logging.CDRasAuth;
import com.ashield.logging.CDRgetNumber;
import com.ashield.logging.CDRgetTxnId;
import com.ashield.logging.CDRsetMsisdn;
import com.ashield.logging.Logging;
import com.ashield.redisque.RedisMessagePublisher;
import com.ashield.redisrepo.AuthReqTransactionIDRepoImpl;
import com.ashield.redisrepo.AuthStatusRespRepoImpl;
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
public class AuthControler implements Constants {

	@Autowired
	MCDiscoverRespRespoImpl mMCDiscoverRespRespoImpl;

	@Autowired
	DbService mAuthDbService;

	@Autowired
	AuthTransactionIDRepoImpl mMCTrackTransRespoImpl;

	@Autowired
	AuthReqTransactionIDRepoImpl mReqTrackTransRespoImpl;

	@Autowired
	AuthwebRespTokenRepoImpl mTokenRespRepoImpl;

	@Autowired
	AuthStatusRespRepoImpl authStatusRespRepoImpl;

	@Autowired
	AshieldEncDec mEncDecObj;

	@Autowired
	WebDesignparamRepoImpl mWebDesignParamRepoImpl;

	@Value("${ashield.infodiscover.url}")
	String mInfoDiscoverUrl;

	@Value("${ashield.discover.url}")
	String mDiscoverUrl;

	@Value("${ashield.redirect.url}")
	String mRedirectUrl;

	@Value("${ashield.inb.redirect.url}")
	String mInbRedirectUrl;

	@Value("${ashield.zom.redirect.url}")
	String mZomRedirectUrl;

	@Value("${ashield.mobcon.clientid}")
	String mMCClientID;

	@Value("${ashield.mobcon.clientsec}")
	String mMCClientSec;

	@Value("${ashield.getimg.url}")
	String mImageReqUrl;

	@Value("${ashield.imgSize}")
	String mImgSize;

	@Value("${ashield.chkimg.url}")
	String mChkImgReqUrl;

	@Value("${mchttpTimeout}")
	int mcHttpTimeout;

	@Value("${ashield.enc.key1}")
	String mEncKey1;

	@Value("${ashield.enc.key2}")
	String mEncKey2;

	@Value("${ashield.enc.key3}")
	String mEncKey3;

	@Value("${ashield.enc.key4}")
	String mEncKey4;

	@Value("${ashield.getimg.intern.url}")
	String mGetImgUrl;

	@Value("${ashield.share.url}")
	String mShareUrl;

	@Value("${ashield.share.appid}")
	String mShareAppID;

	@Value("${ashield.authreq.valid.time}")
	String mValidTime;

	@Value("${ashield.authbot.url}")
	String mAuthBotUrl;

	@Value("${ashield.saveshare.url}")
	String mSaveShareUrl;

	@Value("${ashield.getshare.url}")
	String mGetShareUrl;

	@Value("${ashield.sendotp.intern.url}")
	String mSendOTPUrl;

	@Value("${ashield.prime.num.url}")
	String mMultiFlowUrl;

	@Value("${ashield.dgraphyinitotp.url}")
	String mDGiOtpUrl;

	@Value("${ashield.dgraphyvalotp.url}")
	String mDGvOtpUrl;

	@Value("${ashield.dgraphylurl.url}")
	String mDGlocUrl;

	@Value("${ashield.dgraphyiurl.url}")
	String mDGideUrl;

	@Value("${ashield.initotp.cliname}")
	String mZoClientName;

	@Value("${ashield.zom.secclientid}")
	String mZomClientID;

	@Value("${ashield.zom.secclientsec}")
	String mZomClientSec;

	@Value("${ashield.zom.dgsecclientid}")
	String mZomClientDGID;

	@Value("${ashield.zom.dgsecclientsec}")
	String mZomClientDGSec;

	@Value("${ashield.zom.clientid}")
	String mZomClientIDen;

	@Value("${ashield.zom.dgclientid}")
	String mZomClientDGIDen;

	@Value("${ashield.session.time}")
	int mSessionTimeout;

	@Value("${ashield.dispdemo.intern.url}")
	String mDispDemoUrl;

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

	@Value("${ashield.authappbot.url}")
	String mAuthAppBotUrl;

	@Value("${ashield.appbot.appid}")
	String mAuthAppBotmid;

	@Value("${ashield.appbot.appidkey}")
	String mAuthAppBotkey;

	@Value("${ashield.verify.intern.url}")
	String mVeriMobUrl;

	@Value("${ashield.inb.secclientid}")
	String mInbClientID;

	@Value("${ashield.inb.secclientsec}")
	String mInbClientSec;

	@Value("${ashield.inb.clientid}")
	String mInbClientIDdes;

	@Value("${ashield.inb.callback.url}")
	String mInbCallbackUrl;

	@Value("${txnIDSuffix}")
	String txnIDSuffix;

	@Value("${file.location}")
	String confileloc;

	@Value("${txnID.time}")
	int txnID_time;

	@Value("${dup.req.max.time.diff}")
	int dup_req_max_time_diff;

	@Autowired
	private RedisMessagePublisher redisMessagePublisher;

	@Autowired
	static WebAuthSign webAuthSign;

	Gson gson = new Gson();

	@PostConstruct
	public void initialize() {
		SetMerConfig.confileloc = confileloc;
		updateMerConfig();
		try {
			prepareSmscs(MID_BAJAJ);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("initialization block error: " + e);
		}
	}

	// SMSC distribution preparation
	private Smsc[] smscs = null;
	private static String MID_BAJAJ = "024";

	// Need to prepare 100 counter array
	// Sort the item by percentage
	// find the position by dividing 100 / percentage
	// iterate through 100 for that many positions and fill
	private void prepareSmscs(String mid) throws Exception {
		smscs = new Smsc[100];
		ArrayList<Smsc> sl = new ArrayList();
		// Bajaj merchant config
		SetMerConfig.setMerConfig(mid);
		sl = SetMerConfig.getSmscs();
		// SMSC list is unavailable
		// For now silently returning
		// Later may need to throw exception
		// Atleast one SMSC must present
		if (null == sl || sl.isEmpty()) {
			throw new Exception("SMSC Unavailable. One SMSC must be added");
		}
		sl.sort(new Comparator<Smsc>() {

			@Override
			public int compare(Smsc o1, Smsc o2) {
				return o1.getPercentage() - o2.getPercentage();
			}

		});
		for (Smsc s : sl) {
			if (0 >= s.getPercentage()) {
				continue;
			}
			float offset = 100.0f / s.getPercentage();
			int pos = (int) offset;
			for (int count = 1; count <= s.getPercentage(); count++) {
				pos = (int) (count * offset) - 1;
				// We process reverse for proper distribution
				while (pos >= 0 && null != smscs[pos]) {
					pos--;
				}
				if (pos >= 0) {
					smscs[pos] = s;
				}
			}
		}
		// Check any position is empty.
		// If empty then problem in input percentage or logic
		// Must Manually verify the distribution
		for (int count = 0; count < 100; count++) {
			if (null == smscs[count]) {
				// System.out.println("Empty position " + count);
				throw new Exception("SMSC Distribution percentage wrong");
			} else {
//					System.out.println("Operator in position " + count + " :  " + smscs[count].getOperator());
			}
		}
	}

	// This counter is used to find the proper smsc based on distribution
	// Since we support 100% and 0-99 in smscs array this counter grows till 99
	// then reset back to 0 for properly using the smsc
	private int txnReqCount = 0;

	// This constructor code is specific to Bajaj
	// In prepare smscs config is loaded and smscs distribution is prepared
	// The logic is added considering we support only one MID in Bajaj cluster
	// This design will be revisited in other cluster/repo based on multi MID
	// support
//	public AuthControler() throws Exception {
//		prepareSmscs();
//	}

	@RequestMapping(value = "/getTxnID")
	public @ResponseBody String getTransactionID(@RequestParam(value = "df", required = true) String aDeviceFin,
			@RequestParam(value = "ipne", required = false, defaultValue = "false") boolean isIphone,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request) {

		GetTxnIdPojo CdrInfo = new GetTxnIdPojo();
		CdrInfo.setApiName("getTxnID");
		StringBuilder sb = new StringBuilder();
		long reqtime = System.currentTimeMillis();
		TimeDiffLogThread td1 = new TimeDiffLogThread("getTxnIDapi");
		td1.setCurrentTimeMillis(reqtime);
		String lTxnID = getTransID();
		String encTranID = "";
//		String reqTime = CommonHelper.getFormattedDateString();
		CdrInfo.setReqTS(new Timestamp(System.currentTimeMillis()));
		String headerName = null;
		String headerValue = null;
		String resp = SERVER_ERROR;
		String aDecReq = "";
		TransIDReq lTrReq = null;
		JSONObject myobj = null;
		AuthMobTxnEntity mobTxnEntity = null;
		TimeDiffLogThread td2 = null;
		try {

			boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true")) ? true
					: false;

//			long startTime = System.currentTimeMillis();

			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "DF from SDK to getTxnID API: "
					+ aDeviceFin + "\n");

			if (!loadtest) {

				aDecReq = mEncDecObj.decrypt(aDeviceFin, isIphone);

				encTranID = mEncDecObj.encrypt(lTxnID, isIphone);

				lTrReq = gson.fromJson(aDecReq, TransIDReq.class);

				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "getTransactionID lTxnID:"
						+ lTxnID + "-- encTranID:" + encTranID + ", reqParam " + allReqParams.toString() + "\n");

				String mid = lTrReq.getMid();

				CdrInfo.setMid(lTrReq.getMid());
				CdrInfo.setDf(lTrReq.getDf());
				CdrInfo.setOpn1(lTrReq.getOpn1());
				CdrInfo.setOpn2(lTrReq.getOpn2());
				CdrInfo.setSimCount(lTrReq.getSimcnt() + "");
				CdrInfo.setNType(lTrReq.getNtype());
				CdrInfo.setRegnum(lTrReq.getRegnum());
				CdrInfo.setPurpose(lTrReq.getPurpose());
				CdrInfo.setSelectedSim("");
				CdrInfo.setMobileDataStatus("");
				CdrInfo.setCauseOfReRegTrigger("");
				CdrInfo.setTransactionType("");
				CdrInfo.setRegNumMatch("");
				CdrInfo.setEnvironment("");
				CdrInfo.setCircle("");

				CdrInfo.setDeviceTimestamp(lTrReq.getTsp());

				if (TextUtils.isEmpty(mid)) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "NO MID" + "\n");
					return SERVER_ERROR;
				}

				SetMerConfig.setMerConfig(mid);

				if (!WebAuthSign.midfound) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "MID:" + mid
							+ " not found" + "\n");
					return INVALID_CPID;
				}
				Enumeration<String> headerNames = request.getHeaderNames();
				String headerNamesinfo = "";
				while (headerNames.hasMoreElements()) {
					headerName = headerNames.nextElement();
					Enumeration<String> headers = request.getHeaders(headerName);
					while (headers.hasMoreElements()) {
						headerValue = headers.nextElement();
					}
					if (headerName.equals("user-agent") && !WebAuthSign.debug) {
						headerValue = mEncDecObj.encrypt(headerValue);
					}
					headerNamesinfo = headerNamesinfo + "**getTxnID HEADER --> " + headerName + " : " + headerValue
							+ ", ";
					if (headerName != null && headerName.equals("user-agent")) {
						CdrInfo.setBua(headerValue);
					}
					if (headerName != null && headerName.equals("x-forwarded-for")) {
						CdrInfo.setIP(headerValue);
					}
					if (headerName != null && headerName.equals("x-sdk-ver")) {
						CdrInfo.setSdkVersion(headerValue);
					}

					// Logging.getLogger().info("**getTxnID HEADER --> " + headerName + " : " +
					// headerValue);
				}
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + headerNamesinfo + "\n");
				String df = lTrReq.getDf();

				myobj = new JSONObject();
				String operatorSecretKey = WebAuthSign.signkey;
				operatorSecretKey = mEncDecObj.decrypt(operatorSecretKey);
				String longcod = WebAuthSign.longcode;
				String flowType = WebAuthSign.flowtype;
				String mermsg = WebAuthSign.mermsg;
				Smsc smsc = null;
				if (MID_BAJAJ.equals(mid)) {
					// By assuming worst case scenario adding synchronized block
					// Since there are no other synchronized block using this as object
					synchronized (this) {
						// Override default longcode
						smsc = this.smscs[this.txnReqCount];
						if (null != smsc) {
							longcod = smsc.getLongCode();

						}
						if (99 == this.txnReqCount) {
							this.txnReqCount = 0;
						} else {
							this.txnReqCount++;
						}
					}
				}
				String txnID = encTranID;
				if (mermsg != null && !(mermsg.equals("")))
					txnID = mermsg + "-" + encTranID;
				myobj.put("txnid", encTranID);
				myobj.put("seckey", operatorSecretKey);
				myobj.put("longcode", longcod);
				myobj.put("flowtype", flowType);
				myobj.put("mermsg", txnID);

				CdrInfo.setFlowType(flowType);
				CdrInfo.setLongCode(longcod);
				CdrInfo.setAShieldTxnId(lTxnID);
				CdrInfo.setMerTxnId(lTxnID);

				lTrReq.setStatus("SUCCESS");
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] "
						+ "getTxnID resp to SDK before encrypt: txnid: " + encTranID + ", seckey: " + operatorSecretKey
						+ ", longcode: " + longcod + ", flowtype: " + flowType + ", merchant message: " + txnID + "\n");
				resp = mEncDecObj.encrypt(myobj.toString(), isIphone);
				try {
					RegTxnRec regTxnRec = null;
					String regnum = lTrReq.getRegnum();
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] regnum: " + regnum + "\n");
					if (10 == regnum.length()) {
						regnum = "91" + regnum;
					}
					// In worst case expecting regnum as empty.
					RegId rid = new RegId(mEncDecObj.encrypt(lTrReq.getDf()), mid);
					Optional<AuthRegistryDoc> opArd = mAuthDbService.findById(rid);
					AuthRegistryDoc ard = null;

					if (null == opArd || !opArd.isPresent()) {
						ard = new AuthRegistryDoc();
						ard.setId(rid);
						ard.setCreatedAt(new Date());
						regTxnRec = new RegTxnRec();
						regTxnRec.setTotal(1);
						ard.setRegTxn(regTxnRec);

					} else {
						ard = opArd.get();
						regTxnRec = ard.getRegTxn();
						regTxnRec.setTotal(1 + regTxnRec.getTotal());
					}
					if (null != lTrReq.getStatus()) {
						ard.setStatusCode(lTrReq.getStatus());
					}
					ard.setPurpose(lTrReq.getPurpose());
					ard.setRegnum(regnum);
					ard.setState(AuthRegistryDoc.REG_INITIATED);
					ard.setTxnId(lTxnID);
					// Set the flow from configuratino
					int ft = Integer.parseInt(flowType);
					ard.setAuthFlow(ft);
					ard.setApi(AuthRegistryDoc.API_GETTXNID);
					regTxnRec.setTxnId(lTxnID);
					regTxnRec.setReq(df);
					regTxnRec.setOpn1(lTrReq.getOpn1());
					regTxnRec.setOpn2(lTrReq.getOpn2());
					regTxnRec.setNtype(lTrReq.getNtype());
					regTxnRec.setSimcnt(lTrReq.getSimcnt());

					mobTxnEntity = new AuthMobTxnEntity();
					mobTxnEntity.setTxnid(lTxnID);
					mobTxnEntity.setEncTxnId(encTranID);
					mobTxnEntity.setMid(mid);
					mobTxnEntity.setReq(df);
					mobTxnEntity.setSmshlc(longcod.hashCode());
					// This if can be optimized will do later
					if (null != smsc) {
						regTxnRec.setSmsopr(smsc.getOperator());
						mobTxnEntity.setSmsopr(smsc.getOperator());
					}
					if (null != lTrReq.getMerTxnId()) {
						regTxnRec.setMerTxnId(lTrReq.getMerTxnId());
						mobTxnEntity.setMerTxnId(lTrReq.getMerTxnId());
					}
					regTxnRec.setUpdatedAt(new Date());
					regTxnRec.setStatus("initiated");
					ard.setUpdatedAt(new Date());
					mAuthDbService.saveAuthRegDoc(ard);
				} catch (Exception e) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] Exception occured"
							+ e.toString() + "\n");
				}

				mobTxnEntity.setCreatedAt(new Date());
				mobTxnEntity.setStatus("initiated");
				mobTxnEntity.setDf(lTrReq.getDf());
				td2 = new TimeDiffLogThread("AuthMobTxnEntity", "write");
				td2.setCurrentTimeMillis(System.currentTimeMillis());
				mAuthDbService.saveMob(mobTxnEntity);
				td2.setCurrentTimeMillis2(System.currentTimeMillis());
				String tdresp = td2.start();
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + tdresp + "\n");
//				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(lTxnID + "df", lTrReq.getDf());
				mMCTrackTransRespoImpl.saveToAshieldAuthRepoWithTimeout(lTxnID + "df", lTrReq.getDf());
				mMCTrackTransRespoImpl.saveTxnID(lTxnID + "id", encTranID);
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] "
						+ "TxnID is stored in redis and valid for " + txnID_time + " seconds" + "\n");
			} else {
				resp = lTxnID;
			}

		} catch (Exception e) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "Exception in getTxnID API: "
					+ e + "\n");
			return SERVER_ERROR;
		} finally {

			CdrInfo.setStatus(lTrReq.getStatus());
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "freeMemory :"
					+ Runtime.getRuntime().freeMemory() + ", totalMemory:" + Runtime.getRuntime().totalMemory()
					+ ", maxMemory:" + Runtime.getRuntime().maxMemory() + "\n");
//			LoggingThread lt = new LoggingThread(
//					" [" + lTxnID + "] " + "freeMemory :" + Runtime.getRuntime().freeMemory() + ", totalMemory:"
//							+ Runtime.getRuntime().totalMemory() + ", maxMemory:" + Runtime.getRuntime().maxMemory());
//			lt.start();
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String getTxnIDrespTime = td1.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + getTxnIDrespTime);
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();

			CdrInfo.setProcessingTime((td1.getCurrentTimeMillis2() - td1.getCurrentTimeMillis()));
			CDRgetTxnId.getCDRWriter().logCDR(CdrInfo);
			myobj = null;
			mobTxnEntity = null;
			td1 = null;
			td2 = null;
			sb = null;
			lt = null;
		}

		return resp;
	}

	public String getTransID() {
		String key1 = genKey();
		String[] split1 = key1.split("-");
		String key2 = genKey();
		String[] split2 = key2.split("-");
		String uuid = System.currentTimeMillis() + split1[0] + split2[1] + split1[4] + split2[3];
		return uuid + txnIDSuffix;
	}

	private String genKey() {
		UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}

	// This will be used when AsAuth invoked after successful registration with prev
	// approach
	// Coming for reauth with new approach
	private AuthRegistryDoc createAuthRegDocFromAsAuth(String txnId) {
		AuthRegistryDoc ard = null;
		// First check for registration completion flow because that collection is small
		AuthMobTxnEntity mobTxn = mAuthDbService.getByTxnId(txnId);
		if (null != mobTxn) {
			// Create the ard using this
			String encDf = null;
			try {
				encDf = mEncDecObj.encrypt(mobTxn.getDf());
			} catch (Exception e) {
				return null;
			}
			RegId rid = new RegId(encDf, mobTxn.getMid());
			ard = new AuthRegistryDoc();
			ard.setId(rid);
			ard.setCreatedAt(new Date());
			RegTxnRec regTxnRec = new RegTxnRec();
			regTxnRec.setTotal(1);
			ard.setRegTxn(regTxnRec);
			ard.setTxnId(txnId);
			// For telco flow this is not applicable
			ard.setAuthFlow(1);
			ard.setApi(AuthRegistryDoc.API_ASAUTH);
			regTxnRec.setTxnId(txnId);
			regTxnRec.setReq(mobTxn.getReq());
			regTxnRec.setSmsopr(mobTxn.getSmsopr());
			regTxnRec.setMerTxnId(mobTxn.getMerTxnId());
			regTxnRec.setUpdatedAt(new Date());
			String status = mobTxn.getStatus();

			if ("completed".equals(status)) {
				regTxnRec.setCompleted(1);
				ard.setState(AuthRegistryDoc.SMS_RECEIVED);
			} else {
				if ("expired".equals(status)) {
					regTxnRec.setExpired(1);
				}
				ard.setState(AuthRegistryDoc.REG_INITIATED);
				// SMS expired so we can ignore this
				// From next time we can handle
			}
			regTxnRec.setStatus(status);
			ard.setUpdatedAt(new Date());
			return ard;
		}
		// If the txnId is not found in mobtxn collection then this could be
		// Possilbe AsAuth Request so check the authshare collection
		AuthShareEntity authEntity = mAuthDbService.getByNewtxnID(txnId);
		if (null != authEntity) {
			RegId rid = new RegId(authEntity.getDevicefin(), authEntity.getMid());
			ard = new AuthRegistryDoc();
			ard.setId(rid);
			ard.setState(AuthRegistryDoc.AUTH_SUCCESS);
			ard.setOpn(authEntity.getOpn());
			ard.setMerTxnId(authEntity.getMertxnid());
			String msisdn = "";
			try {
				msisdn = mEncDecObj.decrypt(authEntity.getMsisdn());
			} catch (Exception e) {

			}
			ard.setMsisdn(msisdn);
			AuthTxnRec atr = new AuthTxnRec();
			ard.setTxnId(txnId);
			atr.setTxnId(txnId);
			atr.setS2(authEntity.getShare2());
			atr.setS3(authEntity.getShare3());
			atr.setTimestamp(authEntity.getTimestamp());
			atr.setPasskey(authEntity.getPasskey());
			atr.setUpdatedAt(new Date());
			ard.setAuthTxn(atr);
		}
		return ard;
	}

	// This will be used when setmsisdn or AsAuth is invoked with getTxnID response
	// i.e. registration flow APIs
	private AuthRegistryDoc createAuthRegDocFromSetmsisdn(String txnId, String encTxnId, String msisdn) {
		StringBuilder sb = new StringBuilder();
		AuthRegistryDoc ard = null;
		AuthMobTxnEntity mobTxn = mAuthDbService.getByTxnId(txnId);
		if (null == mobTxn) {
			// This can happen in below scenarios
			// New registration request came and this txnID overwritten in ard but sms for
			// 1st request
			// is coming now only
			return null;
		}
		String encDf = null;
		try {
			encDf = mEncDecObj.encrypt(mobTxn.getDf());
		} catch (Exception exp) {
			return null;
		}
		String status = "completed";
		// We can replace this with db itself
		String redisTxnID = mMCTrackTransRespoImpl.getTxnID(txnId + "id");
		if (!encTxnId.equals(redisTxnID)) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnId + "] "
					+ "TxnID not found in redis and authentication data not stored in DB" + "\n");
		} else {
			status = "completed";
		}
		// Create new entry from mob txn entity
		RegId rid = new RegId(encDf, mobTxn.getMid());
		Optional<AuthRegistryDoc> opArd = mAuthDbService.findById(rid);
		RegTxnRec regTxnRec = null;
		if (null == opArd || !opArd.isPresent()) {
			ard = new AuthRegistryDoc();
			ard.setId(rid);
			ard.setCreatedAt(new Date());
			ard.setState(AuthRegistryDoc.REG_INITIATED);
			regTxnRec = new RegTxnRec();
			regTxnRec.setTotal(1);
			ard.setRegTxn(regTxnRec);
		} else {
			ard = opArd.get();
			regTxnRec = ard.getRegTxn();
			// Already entry is there.
			// This can happen in below scenarios
			// 1. New registration request came and this txnID overwritten but sms for 1st
			// request
			// is coming now only

			// 2. AsAuth for registration request came after getTxnID but setmsisdn coming
			// now only
			// Waiting for setmsisdn
			if (MSG_REC_FAIL.equals(ard.getStatusCode())) {

			} else {
				return null;
			}
		}
		ard.setTxnId(txnId);
		// FOr telco flow this is not applicable
		ard.setAuthFlow(1);
		ard.setApi(AuthRegistryDoc.API_SETMSISDN);
		regTxnRec.setTxnId(txnId);
		regTxnRec.setReq(mobTxn.getReq());
		regTxnRec.setSmsopr(mobTxn.getSmsopr());
		regTxnRec.setMerTxnId(mobTxn.getMerTxnId());
		regTxnRec.setUpdatedAt(mobTxn.getCreatedAt());
		regTxnRec.setStatus(status);
		ard.setUpdatedAt(new Date());
		return ard;
	}

	private AuthTxnRec createAuthTxn(AuthRegistryDoc ard, String aTransID, String acpRdu) throws Exception {
		AuthTxnRec atr = new AuthTxnRec();
		StringBuilder sb = new StringBuilder();
		String lDevicefin = "";
		try {
			lDevicefin = mEncDecObj.decrypt(ard.getId().getDf());
		} catch (Exception e) {

		}
		String lMsisdn = ard.getMsisdn();
		String redirectUrl = "";

		try {
			String newTxnID = getTransID();

			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "sendShare:" + "lDevicefin: "
					+ mEncDecObj.encrypt(lDevicefin) + "\n");

			String tlen = "";
			String mlen = "";

			if (newTxnID.length() < 10) {
				tlen = "0" + newTxnID.length();
			} else {
				tlen = "" + newTxnID.length();
			}

			String lMsisdnP = mEncDecObj.encrypt(lMsisdn, false);
			mlen = lMsisdnP.length() + "";
			String passkey = genKey();
			String[] passval = passkey.split("-");
			String lDevicefinP = lDevicefin + passval[0];
			mlen = mlen + passval[2];
			String aTransIDP = newTxnID + passval[3];
			tlen = tlen + passval[4];
			int plen = passkey.length();
			long timestamp = System.currentTimeMillis();

			String encval = timestamp + lDevicefinP + mlen + passkey + aTransIDP + tlen + plen + lMsisdnP + passval[1];

			String mEncDf = mEncDecObj.encrypt(encval, false);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "sendShare:" + "mEncDf: "
					+ mEncDf + "\n");
			int len = mEncDf.length();

			int devlength = len / 3;

			String s1 = mEncDf.substring(0, devlength - 1);
			String s2 = mEncDf.substring(devlength - 1, 2 * devlength - 1);
			String s3 = mEncDf.substring(2 * devlength - 1, len);

			String encS1 = "";
			String encS2 = "";
			String encS3 = "";
			try {
				encS1 = mEncDecObj.encrypt(s1, false);
				encS2 = mEncDecObj.encrypt(s2, false);
				encS3 = mEncDecObj.encrypt(s3, false);
			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E45: " + e + "\n");
				lt.start();
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Crypto Share 1 : " + encS1
					+ ", Crypto Share 2 : " + encS2 + ", Crypto Share 3 : " + encS3 + "\n");

			ard.setTxnId(newTxnID);
			atr.setTxnId(newTxnID);
			atr.setS2(encS2);
			atr.setS3(encS3);
			atr.setTimestamp(timestamp);
			atr.setPasskey(passkey);
			atr.setUpdatedAt(new Date());

			TimeDiffLogThread td = new TimeDiffLogThread("AuthShareEntity", "write");
			td.setCurrentTimeMillis(System.currentTimeMillis());
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			String shareWrite = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "shares into DB, "
					+ shareWrite + "\n");

			redirectUrl = acpRdu + "msisdn=" + mEncDecObj.encrypt(lMsisdn, false) + "&txnid=" + newTxnID + "&status="
					+ SUCCESS + "&eshare=" + encS1 + "&result=" + "YES" + "&mtxnid=" + ard.getMerTxnId() + "&atxnid="
					+ aTransID + "&opn=" + ard.getOpn() + "&secmsisdn=" + mEncDecObj.encrypt(ard.getRegnum(), false);
			atr.setResp(redirectUrl);

		} catch (Exception e) {

		} finally {
		}

		return atr;
	}

	private boolean validateShare(String share, AuthRegistryDoc ard) throws Exception {
		AuthTxnRec atr = ard.getAuthTxn();
		StringBuilder sb = new StringBuilder();
		boolean isIphone = false;
		boolean valid = false;
		String aDeviceFin = "";
		try {
			aDeviceFin = mEncDecObj.decrypt(ard.getId().getDf());
		} catch (Exception e) {

		}
		String msisdn = ard.getMsisdn();
		msisdn = mEncDecObj.encrypt(msisdn, false);
		String acpTxnID = atr.getTxnId();
		String share1 = share;
		String share2 = atr.getS2();
		String share3 = atr.getS3();
		String opn = ard.getOpn();
		String mID = ard.getId().getMid();
		long timestamp = atr.getTimestamp();
		String passkey = atr.getPasskey();
		String[] passval = passkey.split("-");
		String lDevicefinP = aDeviceFin + passval[0];
		String mlen = msisdn.length() + passval[2];
		String aTransIDP = acpTxnID + passval[3];
		String tlen = "";
		tlen = acpTxnID.length() + passval[4];
		int plen = passkey.length();
		String lval = timestamp + lDevicefinP + mlen + passkey + aTransIDP + tlen + plen + msisdn + passval[1];

		String encval = "";
		try {
			encval = mEncDecObj.encrypt(lval, isIphone);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "lval: " + encval + "\n");

		String decShare1 = "";
		String decShare2 = "";
		String decShare3 = "";
		String condecshare = "";

		try {

			String decMsisdn = msisdn; // mEncDecObj.decrypt(msisdn, isIphone);

			decShare1 = mEncDecObj.decrypt(share1);
			decShare2 = mEncDecObj.decrypt(share2);
			decShare3 = mEncDecObj.decrypt(share3);
			String decr = decShare1 + decShare2 + decShare3;

			if (WebAuthSign.debug) {
				encval = mEncDecObj.decrypt(encval, isIphone);
				decr = mEncDecObj.decrypt(decr, isIphone);
			}
			if (encval.contentEquals(decr)) {
				valid = true;
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
					+ "validatedevfin() lgenerated: " + encval + ", from DB: " + decr + "\n");

		} catch (Exception e) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "e.printStackTrace():" + e
					+ "\n");
		}
		return valid;
	}

	@RequestMapping(value = "/AsAuth")
	@ResponseBody
	String AsAuthNew(@RequestParam(value = "mTxnID", required = true) String aenccpTxnID,
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
			@RequestParam(value = "opn", required = false) String aOpn,
			@RequestParam(value = "loc", required = false) String aLocation,
			@RequestParam(value = "purpose", required = false) String purpose,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request, HttpServletResponse response) {

		// Introducing test scenarios for testing all cases
		// While going live this condition must be removed
		if (0 == WebAuthSign.controlFlow || (4 == WebAuthSign.controlFlow && null != aDevShare
				&& ("0".equals(aDevShare) || aDevShare.isEmpty()))) {
			// Registration completion flow with a old setup or full old setup flow
			// reg/reauth
		return AshieldAuthentication(aenccpTxnID, acpID, acpRdu, aSignature, aRemotaddr, aChannel, aDeviceFin,
					aDevShare, aMerTxnID, aNetType, aSimCount, isAuthenticate, timestamp, isIphone, isVPNClent,
					isPrimeNum, aOpn, aLocation, allReqParams, request, response);

		}
		String resp = "";
		String regnum = "";
		String encregnum = "";
		String acpTxnID = "";
		SecureImageResponse authRespdetail = new SecureImageResponse();
		StringBuilder sb = new StringBuilder();
		long startTime = System.currentTimeMillis();
		String sdk_ver = "0.0";
		AuthRegistryDoc ard = null;
		TimeDiffLogThread td1 = new TimeDiffLogThread("AsAuthapi");
		td1.setCurrentTimeMillis(startTime);
		AsAuthPojo CdrInfo = new AsAuthPojo();
	    CdrInfo.setReqTS(new Timestamp(System.currentTimeMillis()));
	    CdrInfo.setApiName("AsAuth");
		CdrInfo.setMerTxnId(aMerTxnID);
		CdrInfo.setMid(acpID);
		CdrInfo.setOpn1(aOpn);
		CdrInfo.setOpn2("");
		CdrInfo.setSimCount(aSimCount + "");
        CdrInfo.setSelectedSim("");
		CdrInfo.setDf(aDeviceFin);
		CdrInfo.setNType(aNetType);
		CdrInfo.setMobileDataStatus("");
		CdrInfo.setCauseOfReRegTrigger("");
		CdrInfo.setLongCode("");
		CdrInfo.setEnvironment("");
		CdrInfo.setCircle("");
		if (timestamp != null && !timestamp.isEmpty()) {
			CdrInfo.setDeviceTimestamp(new Timestamp(Long.valueOf(timestamp)) + "");
		}
		if (aDevShare != null && (!aDevShare.isEmpty() || !aDevShare.equals("0"))) {
			CdrInfo.setTransactionType("Auth");
		} else {
			CdrInfo.setTransactionType("Regi");
		}

		String statusCode = BAD_REQUEST;
		int newState = AuthRegistryDoc.AUTH_FAILURE;
		try {
			String remoteAddr = "";
			if (aRemotaddr != null && aRemotaddr.length() > 1) {
				remoteAddr = aRemotaddr;
			} else {
				remoteAddr = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
			}

			String xforwardedIP = request.getHeader("X-FORWARDED-FOR");
			String userAgent = request.getHeader("user-agent");
			CdrInfo.setBua(userAgent);
			if (null != xforwardedIP) {
				if (xforwardedIP.contains(":")) {
					xforwardedIP = xforwardedIP.substring(0, xforwardedIP.indexOf(":") - 1);
				}
				remoteAddr = xforwardedIP;
			}
			CdrInfo.setIP(xforwardedIP);
			String aDecDeviceFin = "";

			if (!WebAuthSign.debug) {
				remoteAddr = mEncDecObj.encrypt(remoteAddr);
			}

			acpTxnID = mEncDecObj.decrypt(aenccpTxnID);
			String dataHashed = acpID + acpTxnID + acpRdu;
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
					+ "Data received from SDK to AsAuth-API: remoteAddr : " + remoteAddr + ", CPID=" + acpID
					+ ", CPTXNID=" + acpTxnID + ", CPRDU=" + acpRdu + ", DataHashed=" + dataHashed + ", Sign="
					+ aSignature + ", df=" + aDeviceFin + ", eshare=" + aDevShare + ", MerTxnID=" + aMerTxnID
					+ ", netType=" + aNetType + ", simcount=" + aSimCount + ", authtype=" + isAuthenticate
					+ ", Channel=" + aChannel + ", isVPNClent=" + isVPNClent + ", isprimeNum=" + isPrimeNum + ", Opn="
					+ aOpn + ", location=" + aLocation + ", reqParam " + allReqParams.toString() + "\n");
			CdrInfo.setAShieldTxnId(acpTxnID);
			Enumeration<String> headerNames = request.getHeaderNames();
			String headersInfo = "";
			String headerName;
			String headerValue = "";
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				if ((headerName.equals("x-forwarded-for") || headerName.equals("user-agent")) && !WebAuthSign.debug) {
					headerValue = mEncDecObj.encrypt(headerValue);
				}
				if (headerName.equals("x-original-url")) {
					String[] split = headerValue.split("regnum=");
					encregnum = mEncDecObj.encrypt(split[1]);
					headerValue = split[0] + "regnum=" + encregnum;
				}
				headersInfo = headersInfo + "**HEADER --> " + headerName + " : " + headerValue + ", ";
				if (headerName.equals("x-sdk-ver")) {
					CdrInfo.setSdkVersion(headerValue);
				}
				if (headerName.equals("x-sdk-type")) {
					CdrInfo.setSdkType(headerValue);
					sdk_ver = headerValue;
				}
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + headersInfo + "\n");
			if (allReqParams.containsKey("regnum")) {
				regnum = allReqParams.get("regnum");
				if (regnum == null) {
					CdrInfo.setRegnum("NA");
				} else {
					if (10 == regnum.length()) {
						regnum = "91" + regnum;
					}
					encregnum = mEncDecObj.encrypt(regnum);
					CdrInfo.setRegnum(encregnum);
				}
			}
			authRespdetail.setOptxn(acpTxnID);
			// Nothing is set
			if (TextUtils.isEmpty(acpTxnID)) {
				statusCode = INVALID_CPTXNID;
				authRespdetail.setStatusCode(INVALID_CPTXNID);
				// String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
				// INVALID_CPTXNID);
				// sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
				// + log + "\n");
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			}
			// Check the duplicate request
			// Will use redis for this
			String checkTxnInProgress = mMCTrackTransRespoImpl.getTxnID(acpTxnID);
			if (null != checkTxnInProgress && !checkTxnInProgress.isEmpty()) {
				statusCode = DUPLICATE_REQ;
				authRespdetail.setStatusCode(DUPLICATE_REQ);
				// String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
				// INVALID_CPTXNID);
				// sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
				// + log + "\n");
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			}
			// This will be used to track the duplicate requests across instances
			// If we use hashmap then it will not be possible
			// Storing this state in db is meaningless so must use redis only
			// Within ms this redis entry will be cleaned up
			mMCTrackTransRespoImpl.saveTxnID(acpTxnID, acpTxnID);

			if (TextUtils.isEmpty(acpRdu)) {
				statusCode = INVALID_CPRDU;
				authRespdetail.setStatusCode(INVALID_CPRDU);
				// String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
				// INVALID_CPRDU);
				// sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
				// + log + "\n");
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			}
			// This must be retrieved from Merchant config DB
			String operatorSecretKey = mEncDecObj.decrypt(WebAuthSign.signkey); // "c042f1d545907066a18fa5416d04a12e";
			Object[] validateSignature = validateSignature(operatorSecretKey, aSignature, dataHashed, acpTxnID);
			boolean validSig = (boolean) validateSignature[0];
			sb.append(validateSignature[1].toString() + "\n");
			if (!validSig) {
				statusCode = INVALID_SIGN;
				authRespdetail.setStatusCode(INVALID_SIGN);
//			String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SIGN);
//			sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			}
			// Validate timestamp But why do we need this
			// This is possible if the client date time is different
			// from server one this must not be done
			if (false && !TextUtils.isEmpty(timestamp)) {
				long reqtimediff = startTime - Long.parseLong(timestamp);
				long minutes = TimeUnit.MILLISECONDS.toMinutes(reqtimediff);
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Time Difference is - "
						+ reqtimediff + "Time Difference in min - " + minutes + "\n");
				if (minutes > Integer.parseInt(mValidTime)) {
					authRespdetail.setStatusCode(INVALID_SRC);
//				String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
//				sb.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
					resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					return resp;
				}
			}
			RegTxnRec regTxnRec = null;
			RegId rid = new RegId(aDeviceFin, acpID);
			Optional<AuthRegistryDoc> opArd = mAuthDbService.findByRegTxnId(rid, acpTxnID);

			if (!opArd.isPresent()) {
				// To support the existing registered users need to have a fallback flow
				ard = createAuthRegDocFromAsAuth(acpTxnID);
				if (null == ard) {
					statusCode = BAD_REQUEST;
					authRespdetail.setStatusCode(BAD_REQUEST);
//			String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
//			sb.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
					resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);

					return resp;
				}
			} else {
				ard = opArd.get();
			}
			ard.setRdu(acpRdu);
			ard.setApi(AuthRegistryDoc.API_ASAUTH);
			ard.setRegnum(regnum);
			ard.setPurpose(purpose);
			ard.setMerTxnId(aMerTxnID);
			ard.setOpn(aOpn);
			ard.setNtype(aNetType);
			regTxnRec = ard.getRegTxn();
			int authFlow = ard.getAuthFlow();
			if (AuthRegistryDoc.REG_INITIATED == ard.getState()) {
				// 2 possibilities
				// Wait for the timeout and send AS102
				// Or send AS306 for resetting the request
				long timeOffset = System.currentTimeMillis() - regTxnRec.getUpdatedAt().getTime();
				// Convert to seconds and check
				if ((timeOffset / 1000) < 20) {
					newState = AuthRegistryDoc.REG_INITIATED;
					statusCode = MSG_REC_FAIL;
					authRespdetail.setStatusCode(MSG_REC_FAIL);
				} else {
					newState = AuthRegistryDoc.REG_FAILURE;
					// Reset the session and initiate new reg
					statusCode = ALTERNATE_NUM;
					authRespdetail.setStatusCode(ALTERNATE_NUM);
				}
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			}
			if (AuthRegistryDoc.TELCO_FAILED == ard.getState()) {
				newState = AuthRegistryDoc.REG_FAILURE;
				statusCode = HE_FAIL;
				authRespdetail.setStatusCode(HE_FAIL);
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			}
			if (AuthRegistryDoc.SMS_RECEIVED == ard.getState() || AuthRegistryDoc.TELCO_SUCCESS == ard.getState()) {
				// This is reg completion flow. Shares wont be available
				long createShareTime = System.currentTimeMillis();
				AuthTxnRec old = ard.getAuthTxn();
				AuthTxnRec atr = createAuthTxn(ard, acpTxnID, acpRdu);
//				atr.setSimcnt(aSimCount);
//				atr.setNtype(aNetType);
//				atr.setOpn(aOpn);
				if (null != old) {
					atr.setSuccess(old.getSuccess() + 1);
				}
				sb.append(atr.getResp() + "\n");
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "sendShare ElapsedTime : " + (System.currentTimeMillis() - createShareTime) + "\n");
				authRespdetail.setUrl(atr.getResp());
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "Reg successful. Response to AsAuth-API: " + authRespdetail.getUrl() + "\n");
				newState = AuthRegistryDoc.REG_SUCCESS;
				ard.setAuthTxn(atr);
				regTxnRec.setSuccess(1 + regTxnRec.getSuccess());
				ard.setUpdatedAt(new Date());
				statusCode = SUCCESS;
				if (ard.getRegnum() != null && ard.getRegnum().equals("NA")) {
					if (ard.getRegnum() != null && (ard.getRegnum().equals(ard.getMsisdn()))) {
						CdrInfo.setRegNumMatch("RegNum-matched");
					} else {
						CdrInfo.setRegNumMatch("RegNum-mismatched");
					}
				} else {
					CdrInfo.setRegNumMatch("NA");
				}
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return resp;
			} else if (AuthRegistryDoc.AUTH_SUCCESS == ard.getState()
					|| AuthRegistryDoc.REG_SUCCESS == ard.getState()) {
				// This is reauth flow. Shares will be available
				// Must validate the shares
				AuthTxnRec old = ard.getAuthTxn();

				// Validate the shares
				boolean invalid = (null == aDevShare || aDevShare.isEmpty() || "0".equals(aDevShare));
				boolean valid = false;
				if (!invalid) {
					valid = validateShare(aDevShare, ard);
				}
				if (!valid) {
					statusCode = SHARE_FAIL;
					// TODO : Finalize the error code
					authRespdetail.setStatusCode(SHARE_FAIL);
					resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					return resp;
				}
				long createShareTime = System.currentTimeMillis();
				AuthTxnRec atr = createAuthTxn(ard, acpTxnID, acpRdu);
				atr.setSimcnt(aSimCount);

				if (null != old) {
					atr.setSuccess(old.getSuccess() + 1);
				}
				sb.append(atr.getResp() + "\n");
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "sendShare ElapsedTime : " + (System.currentTimeMillis() - createShareTime) + "\n");
				authRespdetail.setUrl(atr.getResp());
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "Auth successful. Response to AsAuth-API: " + authRespdetail.getUrl() + "\n");
				newState = AuthRegistryDoc.AUTH_SUCCESS;
				ard.setAuthTxn(atr);
				ard.setUpdatedAt(new Date());
				statusCode = SUCCESS;
				resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
			} else {
				// Below code is only for local testing

				/*
				 * if (AuthRegistryDoc.FLOW_TELCO == authFlow && AuthRegistryDoc.REG_INITIATED
				 * == ard.getState()) { ard.setState(AuthRegistryDoc.TELCO_INITIATED); String
				 * lAuthrizeurl = "http://192.168.1.176:9090/Ashield/tokenReqZom?" +
				 * "sesID=64330E9C-65DA-4F53-9F04-D402E7039034&" + "txnID=" + ard.getTxnId() +
				 * "&" + "status=SUCCESS&" + "detmsg=MDNHINT_VERIFIED";
				 * ard.setTelcoUrl(lAuthrizeurl); ard.setUpdatedAt(new Date());
				 * mAuthDbService.saveAuthRegDoc(ard);
				 * 
				 * authRespdetail.setUrl(lAuthrizeurl); authRespdetail.setStatusCode(SUCCESS);
				 * resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				 * 
				 * return resp; }
				 */

				// There is a possibility that this one is completion of telco flow
				if (AuthRegistryDoc.FLOW_TELCO == authFlow && AuthRegistryDoc.REG_INITIATED == ard.getState()
						&& aNetType.contentEquals("cellular")) {
					newState = AuthRegistryDoc.TELCO_FAILED;
					// Process the telco flow or reject the request
					Object[] processIdeNet = processIdeNet(remoteAddr, acpTxnID);
					String IdeNetResp = (String) processIdeNet[0];
					sb.append(new Timestamp(System.currentTimeMillis()) + processIdeNet[1].toString() + "\n");
					// Will not add else block code to set the failure

					statusCode = DISC_FAIL;
					authRespdetail.setStatusCode(DISC_FAIL);
					if (TextUtils.isEmpty(IdeNetResp)) {
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "IdeNetResp:"
								+ IdeNetResp + "\n");
						return resp;
					}

					JSONObject lIderespJson = new JSONObject(IdeNetResp);
					String status = lIderespJson.getString("status");

					if (!status.contentEquals("SUCCESS")) {
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "status:"
								+ status + "\n");
						return resp;
					}

					String networkProvider = lIderespJson.getString("networkProvider");
					String isCellularNetwork = lIderespJson.getString("isCellularNetwork");
					String isMobile = lIderespJson.getString("isMobile");

					if (!isCellularNetwork.contentEquals("true") || !isMobile.contentEquals("true")) {
						sb.append(System.currentTimeMillis() + " [" + acpTxnID + "] " + "isCellularNetwork:"
								+ isCellularNetwork + "\n");
						sb.append(System.currentTimeMillis() + " [" + acpTxnID + "] " + "isMobile:" + isMobile + "\n");
						return resp;
					}
					TimeDiffLogThread td3 = new TimeDiffLogThread("OptVebdorEntity", "read");
					td3.setCurrentTimeMillis(System.currentTimeMillis());
					OptVebdorEntity data = mAuthDbService.getByOperator(networkProvider, "act");
					td3.setCurrentTimeMillis2(System.currentTimeMillis());
					String dbresp = td3.start();
					sb.append(System.currentTimeMillis() + " [" + acpTxnID + "] " + dbresp + "\n");

					if (data == null || (data != null
							&& (!data.getVertype().contains("VERIFY") || !data.getVendor().contains("Zomigo")))) {
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "data:" + data
								+ "\n");
						return resp;
					}

					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Regby : "
							+ data.getOpt() + ", " + data.getVertype() + ", " + data.getVendor() + ", "
							+ data.getStatus() + "\n");

					Object[] createSession = createSession(acpTxnID);
					String createsesResp = (String) createSession[0];
					sb.append(new Timestamp(System.currentTimeMillis()) + createSession[1].toString() + "\n");
					if (TextUtils.isEmpty(createsesResp)) {
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "createsesResp: "
								+ createsesResp + "\n");
						return resp;
					}
					JSONObject lCrerespJson = new JSONObject(createsesResp);

					String sesstatus = lCrerespJson.getString("status");

					if (sesstatus == null || (sesstatus != null && !sesstatus.contentEquals("SUCCESS"))) {
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "sesstatus: "
								+ sesstatus + "\n");
						return resp;
					}

					String sesID = lCrerespJson.getString("sessionId");

					// to add country code to MDN if RMN is not with country code
					String mdnHint = regnum;
					if (mdnHint.length() == 10) {
						mdnHint = "91" + mdnHint;
					}

					String lAuthrizeurl = mIdeDevUrl + "?sessionId=" + sesID + "&correlationId=" + acpTxnID
							+ "&redirectUrl=" + mZomRedirectUrl + "&mdnHint=" + mdnHint;

					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
							+ "Redirection URL to SDK: " + lAuthrizeurl + "\n");
					newState = AuthRegistryDoc.TELCO_INITIATED;
					ard.setTelcoUrl(lAuthrizeurl);
					ard.setUpdatedAt(new Date());
					ard.setTelcoVeriType("VERIFY");
					ard.setIphone(isIphone);
					authRespdetail.setUrl(lAuthrizeurl);
					statusCode = SUCCESS;
					authRespdetail.setStatusCode(SUCCESS);
					resp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					return resp;

				}

			}
		} catch (Exception exp) {
			exp.printStackTrace();
		} finally {
			if (null != ard) {
				ard.setState(newState);
				ard.setStatusCode(statusCode);
				mAuthDbService.saveAuthRegDoc(ard);
			}
			// Final response to return
			mMCTrackTransRespoImpl.deleteTxnID(acpTxnID);
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String timeDifflog = td1.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + timeDifflog + "\n");
			CdrInfo.setStatus(ard.getStatusCode());
			CdrInfo.setFlowType(ard.getAuthFlow() + "");
			CdrInfo.setProcessingTime(td1.getCurrentTimeMillis2() - td1.getCurrentTimeMillis());
			CdrInfo.setPurpose(purpose);
			CDRasAuth.getCDRWriter().logCDR(CdrInfo);
		}
		return resp;
	}

	@RequestMapping(value = "v1/AsAuth")
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
			@RequestParam(value = "opn", required = false) String aOpn,
			@RequestParam(value = "loc", required = false) String aLocation,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request, HttpServletResponse response) {

		StringBuilder sb2 = new StringBuilder();
		Gson gson = new Gson();
		SetMerConfig.setMerConfig(acpID);
		String lRetResp = "";
		String sdk_ver = "0.0";
		String headerName = null;
		String headerValue = null;
		String acpTxnID = "";
		String mdnHint = "";
		AuthShareEntity asEntity = null;
		WebDesignParam webparam = null;
		AuthReqDetail authReqDetail = null;
		SignKeyEntity signEnt = null;
		String regnum = "";

		long startTime = System.currentTimeMillis();
		String authentication_status = "";

		TimeDiffLogThread td1 = new TimeDiffLogThread("AsAuthapi");
		td1.setCurrentTimeMillis(startTime);

		SecureImageResponse authRespdetail = null;

		try {
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
				if (xforwardedIP.contains(":")) {
					xforwardedIP = xforwardedIP.substring(0, xforwardedIP.indexOf(":") - 1);
				}
				remoteAddr = xforwardedIP;
			}

			String aDecDeviceFin = "";

			boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true")) ? true
					: false;

			try {
				if (!loadtest) {
					aDecDeviceFin = mEncDecObj.decrypt(aDeviceFin, isIphone);
					acpTxnID = mEncDecObj.decrypt(aenccpTxnID, isIphone);
				} else {
					aDecDeviceFin = aDeviceFin;
					acpTxnID = aenccpTxnID;
				}
			} catch (Exception e1) {
				e1.printStackTrace();
			}

			// MDC.put(LOG4J_MDC_TOKEN, acpTxnID);

			if (!WebAuthSign.debug) {
				remoteAddr = mEncDecObj.encrypt(remoteAddr);
				allReqParams.put("regnum", mEncDecObj.encrypt(allReqParams.get("regnum")));
			}

			String dataHashed = acpID + acpTxnID + acpRdu;
			sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
					+ "Data received from SDK to AsAuth-API: remoteAddr : " + remoteAddr + ", CPID=" + acpID
					+ ", CPTXNID=" + acpTxnID + ", CPRDU=" + acpRdu + ", DataHashed=" + dataHashed + ", Sign="
					+ aSignature + ", df=" + aDeviceFin + ", eshare=" + aDevShare + ", MerTxnID=" + aMerTxnID
					+ ", netType=" + aNetType + ", simcount=" + aSimCount + ", authtype=" + isAuthenticate
					+ ", Channel=" + aChannel + ", isVPNClent=" + isVPNClent + ", isprimeNum=" + isPrimeNum + ", Opn="
					+ aOpn + ", location=" + aLocation + ", reqParam " + allReqParams.toString() + "\n");
			if (!WebAuthSign.debug) {
				remoteAddr = mEncDecObj.decrypt(remoteAddr);
				allReqParams.put("regnum", mEncDecObj.decrypt(allReqParams.get("regnum")));
			}
//			LoggingThread lt9 = new LoggingThread(" [" + acpTxnID + "] " + "remoteAddr : " + remoteAddr + ", CPID="
//					+ acpID + ", CPTXNID=" + acpTxnID + ", CPRDU=" + acpRdu + ", DataHashed=" + dataHashed + ", Sign="
//					+ aSignature + ", df=" + aDeviceFin + ", eshare=" + aDevShare + ", MerTxnID=" + aMerTxnID
//					+ ", netType=" + aNetType + ", simcount=" + aSimCount + ", authtype=" + isAuthenticate
//					+ ", Channel=" + aChannel + ", isVPNClent=" + isVPNClent + ", isprimeNum=" + isPrimeNum + ", Opn="
//					+ aOpn + ", location=" + aLocation + ", reqParam " + allReqParams.toString());
//			lt9.start();
//		Logging.getLogger()
//				.info("remoteAddr : " + remoteAddr + ", CPID=" + acpID + ", CPTXNID=" + acpTxnID + ", CPRDU=" + acpRdu
//						+ ", DataHashed=" + dataHashed + ", Sign=" + aSignature + ", df=" + aDeviceFin + ", eshare="
//						+ aDevShare + ", MerTxnID=" + aMerTxnID + ", netType=" + aNetType + ", simcount=" + aSimCount
//						+ ", authtype=" + isAuthenticate + ", Channel=" + aChannel + ", isVPNClent=" + isVPNClent
//						+ ", isprimeNum=" + isPrimeNum + ", Opn=" + aOpn + ", location=" + aLocation + ", reqParam "
//						+ allReqParams.toString());

			if (allReqParams.containsKey("regnum")) {
				regnum = allReqParams.get("regnum");
			}
			asEntity = new AuthShareEntity();
			asEntity.setId(acpTxnID);
			asEntity.setDevicefin(aDecDeviceFin);
			asEntity.setTxnid(acpTxnID);
			asEntity.setMertxnid(aMerTxnID);
			if (null != aOpn) {
				asEntity.setOpn(aOpn);
			}
			asEntity.setMid(acpID);
			asEntity.setAuthed(false);
			asEntity.setTimestamp(System.currentTimeMillis());
			asEntity.setUpdatedAt(new Date());
			asEntity.setRegnum(regnum);

			Enumeration<String> headerNames = request.getHeaderNames();
			String headersInfo = "";
			while (headerNames.hasMoreElements()) {
				headerName = headerNames.nextElement();
				Enumeration<String> headers = request.getHeaders(headerName);
				while (headers.hasMoreElements()) {
					headerValue = headers.nextElement();
				}
				if ((headerName.equals("x-forwarded-for") || headerName.equals("user-agent")) && !WebAuthSign.debug) {
					headerValue = mEncDecObj.encrypt(headerValue);
				}
				if (headerName.equals("x-original-url") && !WebAuthSign.debug) {
					String[] split = headerValue.split("regnum=");
					String encregnum = mEncDecObj.encrypt(split[1]);
					headerValue = split[0] + "regnum=" + encregnum;
				}
				headersInfo = headersInfo + "**HEADER --> " + headerName + " : " + headerValue + ", ";
				if (headerName.equals("x-sdk-ver")) {
					sdk_ver = headerValue;
				}
				// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
			}
			sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + headersInfo + "\n");
//			LoggingThread lt10 = new LoggingThread(headersInfo);
//			lt10.start();

			String reqTime = CommonHelper.getFormattedDateString();

			authRespdetail = new SecureImageResponse();
			authRespdetail.setOptxn(acpTxnID);

			webparam = new WebDesignParam();

			authReqDetail = new AuthReqDetail();
			try {
				authReqDetail.setCpID(acpID);
//				authReqDetail.setStartTime(reqTime);
				authReqDetail.setStartTime(new Timestamp(System.currentTimeMillis()).toString());
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
				authReqDetail.setLocation(aLocation);
				authReqDetail.setRetime(startTime);
				String encregnum = "0";
				try {
					mdnHint = allReqParams.get("regnum");
					encregnum = mEncDecObj.encrypt("91" + mdnHint);
				} catch (Exception e) {
					System.out.println(e);
				}
				authReqDetail.setRegnum(encregnum);

			} catch (Exception e) {
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E1: " + e
						+ "\n");
			}

			if (TextUtils.isEmpty(aOpn)) {
				authReqDetail.setOpnName("null");
			} else {
				authReqDetail.setOpnName(aOpn);
			}

			if ((isVPNClent != null && isVPNClent.contains(VPN))
					|| (isAuthenticate != null && isAuthenticate.contains(VPN))) {
				authReqDetail.setVpnflag(true);
			} else {
				authReqDetail.setVpnflag(false);
			}
			if (!WebAuthSign.midfound) {
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "MID:" + acpID
						+ " not found" + "\n");
				String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
				sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				return lRetResp;
			}

			try {

				String operatorSecretKey = "";
				long startTime_db = System.currentTimeMillis();

				signEnt = new SignKeyEntity();
//				SignKeyEntity signEnt = mAuthDbService.getByMid(acpID);

//				ImgKeyEntity imgEnt = mAuthDbService.getImgByMid(acpID);

//				AccountInfoEntity accEnt = mAuthDbService.getByCustomerID(acpID);

				String encKey = "";
//				if (accEnt != null) {
				// encKey = accEnt.getApiKey();
//					encKey = accEnt.getSignkey();
				encKey = WebAuthSign.signkey;
				// operatorSecretKey = mEncDecObj.decrypt(encKey, isIphone);
				operatorSecretKey = WebAuthSign.signkey;
				authReqDetail.setSeckey(WebAuthSign.signkey);

				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "OrgID Key found : "
						+ encKey + "\n");
//					LoggingThread lt11 = new LoggingThread(" [" + acpTxnID + "] " + "OrgID Key found : " + encKey);
//					lt11.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
//				} else {
//					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "OrgID not found : "
//							+ operatorSecretKey + "\n");
////					LoggingThread lt12 = new LoggingThread(
////							" [" + acpTxnID + "] " + "OrgID not found : " + operatorSecretKey);
////					lt12.start();
//					// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
//					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
//					sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
//					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
//					return lRetResp;
//				}

//				if (signEnt != null) {

				authReqDetail.setMulitdevice(signEnt.isMultiDevice());

				// authReqDetail.setDemography(signEnt.isDemography());
				authReqDetail.setDemography(false);

				authReqDetail.setOtpflow(signEnt.isEnableOtpFlow());
				authReqDetail.setClientURl(signEnt.getIdentityCallbackUrl());
				authReqDetail.setCliOtp(!signEnt.isGenerateOtp());

				authReqDetail.setNoconsent(signEnt.isNoconsent());
				// authReqDetail.setNoconsent(true);

				// set this url
				/*
				 * authReqDetail.setDiUrl(signEnt.getDiurl());
				 * authReqDetail.setShareurl(signEnt.getShareurl());
				 * authReqDetail.setSmsurl(signEnt.getSmsurl());
				 */

				sb2.append(new Timestamp(System.currentTimeMillis()) + (" [" + acpTxnID + "] "
						+ "Merchant Config set successfully." + " Multidevice:" + signEnt.isMultiDevice()
						+ ", Demography:" + false + ", OTP flow:" + signEnt.isEnableOtpFlow() + ", Client url:"
						+ signEnt.getIdentityCallbackUrl() + ", Client otp:" + !signEnt.isGenerateOtp()
						+ ", No-consent:" + signEnt.isNoconsent() + "\n"));
//					LoggingThread lt13 = new LoggingThread(" [" + acpTxnID + "] " + "OrgID Key found : " + encKey);
//					lt13.start();
				// Logging.getLogger().info("OrgID Key found : " + encKey);
//				}
//				else {
//					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "OrgID not found : "
//							+ operatorSecretKey + "\n");
////					LoggingThread lt14 = new LoggingThread(
////							" [" + acpTxnID + "] " + "OrgID not found : " + operatorSecretKey);
////					lt14.start();
//					// Logging.getLogger().info("OrgID not found : " + operatorSecretKey);
//					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPID);
//					sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
//					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
//					return lRetResp;
//				}

				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "DB Fetch ElapsedTime : " + (System.currentTimeMillis() - startTime_db) + "\n");
//				LoggingThread lt15 = new LoggingThread(" [" + acpTxnID + "] " + "DB Fetch ElapsedTime : "
//						+ (System.currentTimeMillis() - startTime_db) + " : txnID : " + acpTxnID);
//				lt15.start();
//			Logging.getLogger().info(
//					"DB Fetch ElapsedTime : " + (System.currentTimeMillis() - startTime_db) + " : txnID : " + acpTxnID);

				if (TextUtils.isEmpty(acpTxnID)) {
					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log + "\n");
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPTXNID,
							INVALID_ZERO, INVALID_ZERO);
					return lRetResp;
				}
				if (TextUtils.isEmpty(acpRdu)) {
					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPRDU);
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log + "\n");
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPRDU, INVALID_ZERO,
							INVALID_ZERO);
					return lRetResp;
				}
				Object[] validateSignature = validateSignature(operatorSecretKey, aSignature, dataHashed, acpTxnID);
				boolean res = (boolean) validateSignature[0];
				sb2.append(validateSignature[1].toString() + "\n");
				if (!res) {
					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SIGN);
					sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_SIGN, INVALID_ZERO,
							INVALID_ZERO);
					return lRetResp;
				}

				if (!TextUtils.isEmpty(timestamp)) {
					long reqtimediff = startTime - Long.parseLong(timestamp);
					// Logging.getLogger().info("Time Difference is - " + reqtimediff);
					long minutes = TimeUnit.MILLISECONDS.toMinutes(reqtimediff);
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
							+ "Time Difference is - " + reqtimediff + "Time Difference in min - " + minutes + "\n");
//					LoggingThread lt16 = new LoggingThread(" [" + acpTxnID + "] " + "Time Difference is - " + reqtimediff
//							+ "Time Difference in min - " + minutes);
//					lt16.start();
					// Logging.getLogger().info("Time Difference in min - " + minutes);

					if (minutes > Integer.parseInt(mValidTime)) {
						String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_SRC);
						sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
						lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
						sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_SRC,
								INVALID_ZERO, INVALID_ZERO);
						return lRetResp;
					}
				}

				AuthReqDetail authReqDetail_dup = mReqTrackTransRespoImpl
						.getValueFromAshiledReqRedisRepo(acpTxnID + "req");

				if (authReqDetail_dup != null && TextUtils.isEmpty(authReqDetail_dup.getTempStatus())) {
					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DUPLICATE_REQ);
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log + "\n");
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), DUPLICATE_REQ, INVALID_ZERO,
							INVALID_ZERO);
					return lRetResp;
				} else if (authReqDetail_dup != null) {
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
							+ "authReqDetail_dup status  - " + authReqDetail_dup.getTempStatus() + "\n");
//					LoggingThread lt17 = new LoggingThread(
//							" [" + acpTxnID + "] " + "authReqDetail_dup status  - " + authReqDetail_dup.getTempStatus());
//					lt17.start();
					// Logging.getLogger().info("authReqDetail_dup status - " +
					// authReqDetail_dup.getTempStatus());
					authReqDetail.setTempStatus(authReqDetail_dup.getTempStatus());
				}

//				String browserAgent = request.getHeader("user-agent");
//				String mobileIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
//				String acpt = request.getHeader("accept") != null ? request.getHeader("accept") : "null";
//				String msisdn = "null";
//				String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
//				String xRequestedWithReferer = request.getHeader("x-requested-with") != null
//						? request.getHeader("x-requested-with")
//						: "null";

//				long startTime_bot = System.currentTimeMillis();

//				boolean flag = true;
//				String botResp = DEFAULT_RESP;

//				ASBotAnalyzeThread aba = new ASBotAnalyzeThread(acpTxnID, mobileIp, msisdn, browserAgent, acpID, acpt,
//						referer, xRequestedWithReferer, aChannel);
//				aba.start();
//
//				ASBotAnalyzeTimer abt = new ASBotAnalyzeTimer(acpTxnID);
//				abt.start();
//				TimeDiffLogThread td = new TimeDiffLogThread("AsAuthappbot");
//				td.setCurrentTimeMillis(System.currentTimeMillis());
//				while (flag) {
//					if (aba.getResp() != null) {
//						botResp = aba.getResp();
//						flag = false;
//					}
//					if (abt.getResp() != null) {
//						botResp = abt.getResp();
//						flag = false;
//					}
//				}
//				td.setCurrentTimeMillis2(System.currentTimeMillis());
//				td.setTxnID(acpTxnID);
//				td.start();

//			String botResp = getBotAnalyze(acpTxnID, mobileIp, msisdn, browserAgent, acpID, acpt, referer,
//					xRequestedWithReferer, aChannel);

//				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
//						+ "getBotAnalyze ElapsedTime : " + (System.currentTimeMillis() - startTime_bot) + " : txnID : "
//						+ acpTxnID + "\n");
//				LoggingThread lt18 = new LoggingThread(" [" + acpTxnID + "] " + "getBotAnalyze ElapsedTime : "
//						+ (System.currentTimeMillis() - startTime_bot) + " : txnID : " + acpTxnID);
//				lt18.start();
//			Logging.getLogger().info("getBotAnalyze ElapsedTime : " + (System.currentTimeMillis() - startTime_bot)
//					+ " : txnID : " + acpTxnID);

				/*
				 * String appbotkey = mEncDecObj.decrypt(mAuthAppBotkey, isIphone);
				 * 
				 * getAPPBotAnalyze(acpTxnID, mobileIp, msisdn, browserAgent, mAuthAppBotmid,
				 * acpt, referer, xRequestedWithReferer, aChannel, aDeviceFin, appbotkey);
				 */

//				if (!botResp.contentEquals(DEFAULT_RESP) && !loadtest) {
//					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, BLOCK);
//					sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
//					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
//				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), BLOCK, INVALID_ZERO,
//						INVALID_ZERO);
//					return lRetResp;
//				}

//				if (webparam != null) {
//					webparam.setCpID(acpID);
//					webparam.setCpTxnID(acpTxnID);
//					webparam.setDesdata1(TextUtils.isEmpty(signEnt.getCpSubheader())
//							? "Authenticate your Mobile Number, Which is displayed on the image"
//							: signEnt.getCpSubheader());
//					webparam.setDesdata2(TextUtils.isEmpty(signEnt.getCpBodyText())
//							? "Please click on YES to confirm your mobile number and accept terms and conditions"
//							: signEnt.getCpBodyText());
//					webparam.setDesotp1(TextUtils.isEmpty(signEnt.getOpSubHeader())
//							? "Authenticate your Mobile Number, Which is displayed on the image"
//							: signEnt.getOpSubHeader());
//					webparam.setDesotp2(TextUtils.isEmpty(signEnt.getOpBodyText())
//							? "Please click on OTP to confirm your mobile number and accept terms and conditions"
//							: signEnt.getOpBodyText());
//					webparam.setDeswifi1("Enter Mobile Number");
//					webparam.setDeswifi2("Click 'Submit' to Process");
//					webparam.setFtext(
//							TextUtils.isEmpty(signEnt.getCpFooter()) ? "Powered By Ashield" : signEnt.getCpFooter());
//					webparam.setHcolor("#000000");
//					webparam.setHtext(TextUtils.isEmpty(signEnt.getCpHeader()) ? "Ashield" : signEnt.getCpHeader());
//					webparam.setMclkflag(signEnt.isCpEnableMultiClick());
//					webparam.setWififlag(signEnt.isEnableOtpFlow());
//					webparam.setLogoimg("");
//					webparam.setAvtimg("");
//
//					if (imgEnt != null) {
//						if (imgEnt.getImgstr() != null) {
//							// webparam.setImgstr(Base64.getEncoder().encodeToString(imgEnt.getImgstr().getData()));
//							webparam.setImgstr(Base64.getEncoder().encodeToString(imgEnt.getImgstr().getBytes()));
//						}
//
//						if (imgEnt.getGifstr() != null) {
//							// webparam.setGifstr(Base64.getEncoder().encodeToString(imgEnt.getGifstr().getData()));
//							webparam.setGifstr(Base64.getEncoder().encodeToString(imgEnt.getGifstr().getBytes()));
//						}
//					}
//
//					/*
//					 * Logging.getLogger().info("webparam : " + signEnt.getDesdata1() +
//					 * signEnt.getDesdata2() + signEnt.getDesotp1() + signEnt.getDesotp2() +
//					 * signEnt.getDeswifi1() + signEnt.getDeswifi2() + signEnt.getFtext() +
//					 * signEnt.getHcolor() + signEnt.getHtext() + signEnt.isMclkflag() +
//					 * signEnt.isWififlag() + signEnt.getImgurl() + signEnt.getAvtimgurl() +
//					 * signEnt.getCliUrl() + signEnt.getRUrl() + signEnt.getSignkey());
//					 */
//				}

				mWebDesignParamRepoImpl.saveToWebDesignparamRepo(acpTxnID + "web", webparam);

			} catch (Exception e) {
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E2: " + e
						+ "\n");
				Logging.getLogger().info("MongoException : ");
				String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, SERVER_ERROR);
				sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
				try {
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				return lRetResp;
			}

			long startTime_fin = System.currentTimeMillis();

//			AuthReqValidObj msisdnObj = validatedevfin(acpTxnID, aDecDeviceFin, aDevShare, isIphone,
//					authReqDetail.isMulitdevice(), authReqDetail.getShareurl(), request, response, loadtest);

			// TODO : Why we need this . This is useless
			Object[] validatedevfin = validatedevfin(acpTxnID, aDecDeviceFin, aDevShare, isIphone,
					authReqDetail.isMulitdevice(), authReqDetail.getShareurl(), request, response, loadtest);
			AuthReqValidObj msisdnObj = (AuthReqValidObj) validatedevfin[0];
			sb2.append(validatedevfin[1].toString() + "\n");
			sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
					+ "validatedevfin ElapsedTime : " + (System.currentTimeMillis() - startTime_fin) + "\n");
//			LoggingThread lt19 = new LoggingThread(" [" + acpTxnID + "] " + "validatedevfin ElapsedTime : "
//					+ (System.currentTimeMillis() - startTime_fin) + " : txnID : " + acpTxnID);
//			lt19.start();
//		Logging.getLogger().info("validatedevfin ElapsedTime : " + (System.currentTimeMillis() - startTime_fin)
//				+ " : txnID : " + acpTxnID);

			try {
				if (msisdnObj.isStatus()) {
					String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DUPLICATE_REQ);
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log + "\n");
					Float sdk_version = Float.valueOf(sdk_ver);
					if (sdk_version < 2.15) {
						String authTS = mMCTrackTransRespoImpl.getAuthTS(acpTxnID + "ts");
						if (authTS == null) {
							SecureImageResponse authRespdetail1 = new SecureImageResponse();
							String encmsisdn = mEncDecObj.encrypt(ALTERNATE_NUM);
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ "Duplicate reauth reauthentication arrived after " + dup_req_max_time_diff
									+ " seconds so response url set in format " + acpRdu + "msisdn=" + encmsisdn
									+ "&optxn=" + acpTxnID + "&atxnid=" + aMerTxnID + "\n");
							authRespdetail1.setUrl(
									acpRdu + "msisdn=" + encmsisdn + "&optxn=" + acpTxnID + "&atxnid=" + aMerTxnID);
							lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail1), isIphone);
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ "AsAuth resp: " + lRetResp + "\n");
							sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), DUPLICATE_REQ,
									INVALID_ZERO, INVALID_ZERO);
							return lRetResp;
						}
					}
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), DUPLICATE_REQ, INVALID_ZERO,
							INVALID_ZERO);
					return lRetResp;
				}
			} catch (Exception e) {
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E3: " + e
						+ "\n");
				Logging.getLogger().info("MongoException : ");
				String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, SERVER_ERROR);
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log + "\n");
				try {
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				return lRetResp;
			}

//			String[] split = aDecDeviceFin.split("pkn=");
//			String[] pkn = split[1].split("&");
//			String encDf = mEncDecObj.encrypt(pkn[0]);
//			if (WebAuthSign.pkn.equalsIgnoreCase("null")) {
//				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
//						+ "Package name not found in DB for mid:" + acpID + " --> " + MISSING_PARAMETER + "\n");
//				String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, BLOCK);
//				sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
//				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
//				return lRetResp;
//			}
//			if (!(WebAuthSign.pkn.equals(encDf))) {
//				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
//						+ "Package name mismatch: " + BLOCK + "\n");
//				String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, BLOCK);
//				sb2.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
//				lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
//				return lRetResp;
//			}

			try {

				if (loadtest) {
					msisdnObj.setMsisdn("9900990099");
				}

				if (TextUtils.isEmpty(msisdnObj.getMsisdn())) {
					if (aNetType.contentEquals("cellular")) {
						String lDeviceFin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "df");
						if (lDeviceFin != null && lDeviceFin.equals(aDecDeviceFin)) {
							TimeDiffLogThread td3 = new TimeDiffLogThread("AuthMobTxnEntity", "read");
							td3.setCurrentTimeMillis(System.currentTimeMillis());
							AuthMobTxnEntity mMobTxnEntity = mAuthDbService.getByTxnId(acpTxnID);
							mMobTxnEntity.setRetrived(mMobTxnEntity != null && !mMobTxnEntity.isRetrived() ? true
									: mMobTxnEntity.isRetrived());
							td3.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntityread = td3.start();
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntityread + "\n");
							TimeDiffLogThread td2 = new TimeDiffLogThread("AuthMobTxnEntity", "write");
							td2.setCurrentTimeMillis(System.currentTimeMillis());
							mMobTxnEntity.setUpdatedAt(new Date());
							mMobTxnEntity.setRetrived(true);
							mAuthDbService.saveMob(mMobTxnEntity);
							td2.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntitywrite = td2.start();

							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntitywrite + "\n");
						} else if (lDeviceFin == null) {
							TimeDiffLogThread td3 = new TimeDiffLogThread("AuthMobTxnEntity", "read");
							td3.setCurrentTimeMillis(System.currentTimeMillis());
							AuthMobTxnEntity mMobTxnEntity = mAuthDbService.getByTxnId(acpTxnID);
							if (mMobTxnEntity != null && !mMobTxnEntity.isRetrived()) {
								lDeviceFin = mMobTxnEntity.getReq();
								mMobTxnEntity.setRetrived(true);
							}
							td3.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntityread = td3.start();
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntityread + "\n");
							TimeDiffLogThread td2 = new TimeDiffLogThread("AuthMobTxnEntity", "write");
							td2.setCurrentTimeMillis(System.currentTimeMillis());
							mMobTxnEntity.setUpdatedAt(new Date());
							mMobTxnEntity.setRetrived(true);
							mAuthDbService.saveMob(mMobTxnEntity);
							td2.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntitywrite = td2.start();

							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntitywrite + "\n");
						}
//						sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
//								+ "lDeviceFin repo resp :" + mEncDecObj.encrypt(lDeviceFin, isIphone)
//								+ "aDeviceFin passed value :" + mEncDecObj.encrypt(aDecDeviceFin, isIphone) + "\n");
//						LoggingThread lt20 = new LoggingThread(" [" + acpTxnID + "] " + "lDeviceFin repo resp :"
//								+ mEncDecObj.encrypt(lDeviceFin, isIphone) + "aDeviceFin passed value :"
//								+ mEncDecObj.encrypt(aDecDeviceFin, isIphone));
//						lt20.start();
//					Logging.getLogger().info("lDeviceFin repo resp :" + mEncDecObj.encrypt(lDeviceFin, isIphone));
//					Logging.getLogger().info("aDeviceFin passed value :" + mEncDecObj.encrypt(aDecDeviceFin, isIphone));
						if (!TextUtils.isEmpty(lDeviceFin) && lDeviceFin.contentEquals(aDecDeviceFin)) {

//							String IdeNetResp = processIdeNet(remoteAddr, acpTxnID);
							Object[] processIdeNet = processIdeNet(remoteAddr, acpTxnID);
							String IdeNetResp = (String) processIdeNet[0];
							sb2.append(new Timestamp(System.currentTimeMillis()) + processIdeNet[1].toString() + "\n");

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

										TimeDiffLogThread td3 = new TimeDiffLogThread("OptVebdorEntity", "read");
										td3.setCurrentTimeMillis(System.currentTimeMillis());
										OptVebdorEntity data = mAuthDbService.getByOperator(networkProvider, "act");
										td3.setCurrentTimeMillis2(System.currentTimeMillis());
										String dbresp = td3.start();
										sb2.append(System.currentTimeMillis() + " [" + acpTxnID + "] " + dbresp + "\n");
										if (data != null) {
											sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
													+ "] " + "Regby : " + data.getOpt() + ", " + data.getVertype()
													+ ", " + data.getVendor() + ", " + data.getStatus() + "\n");
//											LoggingThread lt21 = new LoggingThread(" [" + acpTxnID + "] " + "Regby : "
//													+ data.getOpt() + ", " + data.getVertype() + ", " + data.getVendor()
//													+ ", " + data.getStatus());
//											lt21.start();
//										Logging.getLogger().info("Regby : " + data.getOpt() + ", " + data.getVertype()
//												+ ", " + data.getVendor() + ", " + data.getStatus());
										}

										if (data != null && data.getVertype().contains("HE")
												&& data.getVendor().contains("Zomigo")) {
											sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
													+ "] " + "Regby : " + data.getOpt() + ", " + data.getVertype()
													+ ", " + data.getVendor() + ", " + data.getStatus() + "\n");
//											LoggingThread lt22 = new LoggingThread(" [" + acpTxnID + "] " + "Regby : "
//													+ data.getOpt() + ", " + data.getVertype() + ", " + data.getVendor()
//													+ ", " + data.getStatus());
//											lt22.start();
//										Logging.getLogger().info("Regby : " + data.getOpt() + ", " + data.getVertype()
//												+ ", " + data.getVendor() + ", " + data.getStatus());

											authReqDetail.setVerType("HE");

											mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn",
													networkProvider);
											authReqDetail.setOpnName(networkProvider);

											mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan",
													"inapp");

//											String createsesResp = createSession(acpTxnID);
											Object[] createSession = createSession(acpTxnID);
											String createsesResp = (String) createSession[0];
											sb2.append(new Timestamp(System.currentTimeMillis())
													+ createSession[1].toString() + "\n");
											if (!TextUtils.isEmpty(createsesResp)) {
												JSONObject lCrerespJson = new JSONObject(createsesResp);

												String sesstatus = lCrerespJson.getString("status");

												if (sesstatus.contentEquals("SUCCESS")) {
													String sesID = lCrerespJson.getString("sessionId");

													// to add country code to MDN if RMN is not with country code
													if (mdnHint.length() == 10) {
														mdnHint = "91" + mdnHint;
													}

													String lAuthrizeurl = mIdeDevUrl + "?sessionId=" + sesID
															+ "&correlationId=" + acpTxnID + "&redirectUrl="
															+ mZomRedirectUrl + "&mdnHint=" + mdnHint;

													sb2.append(new Timestamp(System.currentTimeMillis()) + " ["
															+ acpTxnID + "] " + "Redirection URL to SDK: "
															+ lAuthrizeurl + "\n");

													authRespdetail.setUrl(lAuthrizeurl);
													authRespdetail.setStatusCode(SUCCESS);
												} else {
													authRespdetail.setStatusCode(DISC_FAIL);
													authReqDetail.setTempStatus(DISC_FAIL);
													String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
															DISC_FAIL);
													sb2.append(new Timestamp(System.currentTimeMillis()) + " ["
															+ acpTxnID + "] " + log + "\n");
												}
											} else {
												authRespdetail.setStatusCode(DISC_FAIL);
												authReqDetail.setTempStatus(DISC_FAIL);
												String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
														DISC_FAIL);
												sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
														+ "] " + log + "\n");
											}
										} else if (data != null && data.getVertype().contains("VERIFY")
												&& data.getVendor().contains("Zomigo")) {
											sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
													+ "] " + "Regby : " + data.getOpt() + ", " + data.getVertype()
													+ ", " + data.getVendor() + ", " + data.getStatus() + "\n");
//											LoggingThread lt23 = new LoggingThread(" [" + acpTxnID + "] " + "Regby : "
//													+ data.getOpt() + ", " + data.getVertype() + ", " + data.getVendor()
//													+ ", " + data.getStatus());
//											lt23.start();
//										Logging.getLogger().info("Regby : " + data.getOpt() + ", " + data.getVertype()
//												+ ", " + data.getVendor() + ", " + data.getStatus());

											authReqDetail.setVerType("VERIFY");

											mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "veri",
													data.getVertype());

											/*
											 * String getMdnImgUrl = mVeriMobUrl + "?mTxnID=" + acpTxnID; // testing
											 * authRespdetail.setUrl(getMdnImgUrl); // testing
											 * authRespdetail.setStatusCode(SUCCESS); // testing
											 */

											authRespdetail.setStatusCode(DISC_FAIL);
											authReqDetail.setTempStatus(DISC_FAIL);
											String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
											sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
													+ "] " + log + "\n");
										} else if (data != null && data.getVertype().contains("HE")
												&& data.getVendor().contains("Infobip")) {
											sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
													+ "] " + "Regby : " + data.getOpt() + ", " + data.getVertype()
													+ ", " + data.getVendor() + ", " + data.getStatus() + "\n");
//											LoggingThread lt24 = new LoggingThread(" [" + acpTxnID + "] " + "Regby : "
//													+ data.getOpt() + ", " + data.getVertype() + ", " + data.getVendor()
//													+ ", " + data.getStatus());
//											lt24.start();
//										Logging.getLogger().info("Regby : " + data.getOpt() + ", " + data.getVertype()
//												+ ", " + data.getVendor() + ", " + data.getStatus());

											authReqDetail.setVerType("HE");

											mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn",
													networkProvider);
											authReqDetail.setOpnName(networkProvider);

											mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan",
													"inapp");

//											String infotokenResp = processInfoTokenReq(remoteAddr, acpTxnID);
											Object[] processInfoTokenResp = processInfoTokenReq(remoteAddr, acpTxnID);
											String infotokenResp = (String) processInfoTokenResp[0];
											sb2.append(new Timestamp(System.currentTimeMillis())
													+ processInfoTokenResp[1].toString() + "\n");
											if (!TextUtils.isEmpty(infotokenResp)) {
												JSONObject lInfotokJson = new JSONObject(infotokenResp);

												String sesstatus = lInfotokJson.getString("status");

												if (sesstatus.contentEquals("REDIRECT")) {
													String sesID = lInfotokJson.getString("token");

													String lAuthrizeurl = lInfotokJson.getString("deviceRedirectUrl");

													mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "token",
															sesID);

													authRespdetail.setUrl(lAuthrizeurl);
													authRespdetail.setStatusCode(SUCCESS);
												} else {
													authRespdetail.setStatusCode(DISC_FAIL);
													authReqDetail.setTempStatus(DISC_FAIL);
													String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
															DISC_FAIL);
													sb2.append(new Timestamp(System.currentTimeMillis()) + " ["
															+ acpTxnID + "] " + log + "\n");
												}

											} else {
												authRespdetail.setStatusCode(DISC_FAIL);
												authReqDetail.setTempStatus(DISC_FAIL);
												String log = getLogErrorMsg(authRespdetail, gson, authReqDetail,
														DISC_FAIL);
												sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
														+ "] " + log + "\n");
											}

										} else {
											authRespdetail.setStatusCode(DISC_FAIL);
											authReqDetail.setTempStatus(DISC_FAIL);
											String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
											sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID
													+ "] " + log + "\n");
										}
									} else {
										authRespdetail.setStatusCode(DISC_FAIL);
										authReqDetail.setTempStatus(DISC_FAIL);
										String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
										sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
												+ log + "\n");
									}
								} else {
									authRespdetail.setStatusCode(DISC_FAIL);
									authReqDetail.setTempStatus(DISC_FAIL);
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
								}

							} else {
								authRespdetail.setStatusCode(DISC_FAIL);
								authReqDetail.setTempStatus(DISC_FAIL);
								String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, DISC_FAIL);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
										+ "\n");
							}

							if (authRespdetail != null && (authRespdetail.getStatusCode().equals("AS201")
									|| authRespdetail.getStatusCode().equals(DISC_FAIL))) {
								try {

									String message = "ASHIELD" + acpTxnID + "#" + reqTime;
									redisMessagePublisher.publish(message);

									mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

									mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
									mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

									if (aChannel.contentEquals("wap")) {
										sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
												+ "**sendRedirect --> " + authRespdetail.getUrl() + "\n");
//										LoggingThread lt25 = new LoggingThread(
//												" [" + acpTxnID + "] " + "**sendRedirect --> " + authRespdetail.getUrl());
//										lt25.start();
										// Logging.getLogger().info("**sendRedirect --> " + authRespdetail.getUrl());

										response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
										response.setHeader("Location", authRespdetail.getUrl());
										response.sendRedirect(authRespdetail.getUrl());
									}

									lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
									return lRetResp;

								} catch (Exception e) {
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
											+ "Exception E4: " + e + "\n");
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
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
									/*
									 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
									 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
									 */
								} else if (!lDeviceFin.contains(simID)) {
									authRespdetail.setStatusCode(INVALID_DF);
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF_SIM);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
									/*
									 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
									 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
									 */
								} else {
									authRespdetail.setStatusCode(INVALID_DF);
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF_DEVICE);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
									/*
									 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
									 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
									 */
								}

							} else {
								authRespdetail.setStatusCode(INVALID_CPTXNID);
								String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_CPTXNID);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
										+ "\n");
								sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_CPTXNID,
										INVALID_ZERO, INVALID_ZERO);
							}
						}
					} else {

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", aOpn);
						String lDeviceFin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "df");
						// if lDeviceFin is not found in redis check in DB
						AuthMobTxnEntity mMobTxnEntity = null;
						if (lDeviceFin != null && lDeviceFin.equals(aDecDeviceFin)) {
							TimeDiffLogThread td3 = new TimeDiffLogThread("AuthMobTxnEntity", "read");
							td3.setCurrentTimeMillis(System.currentTimeMillis());
							mMobTxnEntity = mAuthDbService.getByTxnId(acpTxnID);
							mMobTxnEntity.setRetrived(mMobTxnEntity != null && !mMobTxnEntity.isRetrived() ? true
									: mMobTxnEntity.isRetrived());
							td3.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntityread = td3.start();
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntityread + "\n");
							TimeDiffLogThread td2 = new TimeDiffLogThread("AuthMobTxnEntity", "write");
							td2.setCurrentTimeMillis(System.currentTimeMillis());
							mMobTxnEntity.setUpdatedAt(new Date());
							mMobTxnEntity.setRetrived(true);
							mAuthDbService.saveMob(mMobTxnEntity);
							td2.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntitywrite = td2.start();

							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntitywrite + "\n");
						} else if (lDeviceFin == null) {
							TimeDiffLogThread td3 = new TimeDiffLogThread("AuthMobTxnEntity", "read");
							td3.setCurrentTimeMillis(System.currentTimeMillis());
							mMobTxnEntity = mAuthDbService.getByTxnId(acpTxnID);
							if (mMobTxnEntity != null && !mMobTxnEntity.isRetrived()) {
								lDeviceFin = mMobTxnEntity.getReq();
								mMobTxnEntity.setRetrived(true);
							}
							td3.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntityread = td3.start();
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntityread + "\n");
							TimeDiffLogThread td2 = new TimeDiffLogThread("AuthMobTxnEntity", "write");
							td2.setCurrentTimeMillis(System.currentTimeMillis());
							mMobTxnEntity.setUpdatedAt(new Date());
							mMobTxnEntity.setRetrived(true);
							mAuthDbService.saveMob(mMobTxnEntity);
							td2.setCurrentTimeMillis2(System.currentTimeMillis());
							String mMobTxnEntitywrite = td2.start();

							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ mMobTxnEntitywrite + "\n");
						}

						sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
								+ "lDeviceFin repo resp :" + mEncDecObj.encrypt(lDeviceFin, isIphone)
								+ ", aDeviceFin passed value :" + mEncDecObj.encrypt(aDecDeviceFin, isIphone) + "\n");
//						LoggingThread lt26 = new LoggingThread(" [" + acpTxnID + "] " + "lDeviceFin repo resp :"
//								+ mEncDecObj.encrypt(lDeviceFin, isIphone) + ", aDeviceFin passed value :"
//								+ mEncDecObj.encrypt(aDecDeviceFin, isIphone));
//						lt26.start();
//					Logging.getLogger().info("lDeviceFin repo resp :" + mEncDecObj.encrypt(lDeviceFin, isIphone));
//					Logging.getLogger().info("aDeviceFin passed value :" + mEncDecObj.encrypt(aDecDeviceFin, isIphone));

						if (!TextUtils.isEmpty(lDeviceFin) && lDeviceFin.contentEquals(aDecDeviceFin)) {
							String lWifiMsisdn = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(acpTxnID + "mn");
							if (lWifiMsisdn == null) {
								lWifiMsisdn = mMobTxnEntity.getMsisdn();
							}
							String lVerifyType = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(acpTxnID + "veri");
							if (TextUtils.isEmpty(lWifiMsisdn) && TextUtils.isEmpty(lVerifyType)) {
								authRespdetail.setStatusCode(MSG_REC_FAIL);
								String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, MSG_REC_FAIL);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
										+ "\n");
								sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
										SESSION_TIME_OUT, INVALID_ZERO, INVALID_ZERO);
							} else if (TextUtils.isEmpty(lWifiMsisdn) && !lVerifyType.contains("Verify")) {
								authRespdetail.setStatusCode(MSG_REC_FAIL);
								String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, MSG_REC_FAIL);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
										+ "\n");
								sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
										SESSION_TIME_OUT, INVALID_ZERO, INVALID_ZERO);
							} else if (TextUtils.isEmpty(lWifiMsisdn) && lVerifyType.contains("Verify")) {

								String message = "ASHIELD" + acpTxnID + "#" + reqTime;
								redisMessagePublisher.publish(message);
								authReqDetail.setTelco("Verify");

								mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "df", aDecDeviceFin);
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "rdu", acpRdu);

								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "chan", "inapp");

								String getMdnImgUrl = mVeriMobUrl + "?mTxnID=" + acpTxnID;
								authRespdetail.setUrl(getMdnImgUrl);

								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
										+ "Move to Verify Flow : " + "\n");
//								LoggingThread lt27 = new LoggingThread(" [" + acpTxnID + "] " + "Move to Verify Flow : ");
//								lt27.start();
								// Logging.getLogger().info("Move to Verify Flow : ");

							} else {

								if (!authReqDetail.isMulitdevice()) {
									TimeDiffLogThread td = new TimeDiffLogThread("AuthMobDFEntity", "read");
									td.setCurrentTimeMillis(System.currentTimeMillis());
									AuthMobDFEntity lMobData = null;
									if (WebAuthSign.debug) {
										lMobData = mAuthDbService.getByMsisdn(lWifiMsisdn + acpID);
									} else {
										lMobData = mAuthDbService.getByMsisdn(mEncDecObj.encrypt(lWifiMsisdn + acpID));
										if (lMobData != null) {
											lMobData.setDevicefin(mEncDecObj.decrypt(lMobData.getDevicefin()));
											lMobData.setMsisdn(mEncDecObj.decrypt(lMobData.getMsisdn()));
										}
									}
									td.setCurrentTimeMillis2(System.currentTimeMillis());
									String dbresp = td.start();
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
											+ dbresp + "\n");
									if (lMobData != null && !lMobData.getDevicefin()
											.contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
										String devicefin1 = lMobData.getDevicefin();
										String devicefin2 = authReqDetail.getDf();
										if (!WebAuthSign.debug) {
											devicefin1 = mEncDecObj.encrypt(devicefin1);
											devicefin2 = mEncDecObj.encrypt(devicefin2);
										}
										sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
												+ "DF not match : " + devicefin1 + ", DF not match : " + devicefin2
												+ "\n");
//										LoggingThread lt28 = new LoggingThread(" [" + acpTxnID + "] " + "DF not match : "
//												+ lMobData.getDevicefin() + "DF not match : " + authReqDetail.getDf());
//										lt28.start();
										// Logging.getLogger().info("DF not match : " + lMobData.getDevicefin());
										// Logging.getLogger().info("DF not match : " + authReqDetail.getDf());
										mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "action", "rereg");
									} else if (lMobData != null) {
										String devicefin1 = lMobData.getDevicefin();
										if (!WebAuthSign.debug) {
											devicefin1 = mEncDecObj.encrypt(devicefin1);
										}
										sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
												+ "DF match : " + devicefin1 + "\n");
//										LoggingThread lt29 = new LoggingThread(
//												" [" + acpTxnID + "] " + "DF match : " + lMobData.getDevicefin());
//										lt29.start();
										// Logging.getLogger().info("DF match : " + lMobData.getDevicefin());
									} else {
										sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
												+ "NO DF Data : " + "\n");
//										LoggingThread lt30 = new LoggingThread(" [" + acpTxnID + "] " + "NO DF Data : ");
//										lt30.start();
										// Logging.getLogger().info("NO DF Data : ");
									}
								}
								String niTime = CommonHelper.getFormattedDateString();
								authReqDetail.setNitime(niTime);

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
								} else if (authReqDetail.isNoconsent()) {
									Object[] sendShare = sendShare(acpTxnID, request, response);
									authentication_status = SUCCESS;
									lRetResp = (String) sendShare[0];
									sb2.append(sendShare[1].toString() + "\n");
//									lRetResp = sendShare(acpTxnID, request, response);
									authRespdetail.setUrl(lRetResp);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
											+ "Reg successful. Response to AsAuth-API: " + authRespdetail.getUrl()
											+ "\n");
//									LoggingThread lt31 = new LoggingThread(" [" + acpTxnID + "] "
//											+ " Registration with no consent" + authRespdetail.getUrl());
//									lt31.start();
									// Logging.getLogger().info(" Registration with no consent" +
									// authRespdetail.getUrl());
								} else {
									String displayImgUrl = mGetImgUrl + "?mTxnID=" + acpTxnID + "&mID=" + acpID;
									authRespdetail.setDispImgurl(displayImgUrl);
									authRespdetail.setUrl("");
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
											+ " Display image over WIFI authRespdetail" + authRespdetail.getUrl()
											+ "\n");
//									LoggingThread lt32 = new LoggingThread(" [" + acpTxnID + "] "
//											+ " Display image over WIFI authRespdetail" + authRespdetail.getUrl());
//									lt32.start();
//								Logging.getLogger()
//										.info(" Display image over WIFI authRespdetail" + authRespdetail.getUrl());
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
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
									/*
									 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
									 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
									 */
								} else if (!lDeviceFin.contains(simID)) {
									authRespdetail.setStatusCode(INVALID_DF);
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF_SIM);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
									/*
									 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
									 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
									 */
								} else {
									authRespdetail.setStatusCode(INVALID_DF);
									String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF_DEVICE);
									sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
											+ "\n");
									/*
									 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
									 * INVALID_CPTXNID, INVALID_ZERO , INVALID_ZERO);
									 */
								}

							} else {
								/*
								 * authRespdetail.setStatusCode(INVALID_CPTXNID); getLogErrorMsg(authRespdetail,
								 * gson, authReqDetail, INVALID_CPTXNID);
								 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
								 * INVALID_CPTXNID , INVALID_ZERO , INVALID_ZERO);
								 */

								authRespdetail.setStatusCode(INVALID_DF);
								String log = getLogErrorMsg(authRespdetail, gson, authReqDetail, INVALID_DF);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + log
										+ "\n");
								sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), INVALID_DF,
										INVALID_ZERO, INVALID_ZERO);
							}
						}
					}
				} else {

					String message = "ASHIELD" + acpTxnID + "#" + reqTime;
					redisMessagePublisher.publish(message);

					authReqDetail.setTelco("Auth");
					String niTime = CommonHelper.getFormattedDateString();
					authReqDetail.setNitime(niTime);

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
							long startTime_share = System.currentTimeMillis();
							Object[] sendShare = sendShare(acpTxnID, request, response);
							authentication_status = SUCCESS;
							lRetResp = (String) sendShare[0];
							sb2.append(sendShare[1].toString() + "\n");
//							lRetResp = sendShare(acpTxnID, request, response);
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ "sendShare ElapsedTime : " + (System.currentTimeMillis() - startTime_share)
									+ "\n");
//							LoggingThread lt33 = new LoggingThread(" [" + acpTxnID + "] " + "sendShare ElapsedTime : "
//									+ (System.currentTimeMillis() - startTime_share) + " : txnID : " + acpTxnID);
//							lt33.start();
//						Logging.getLogger().info("sendShare ElapsedTime : "
//								+ (System.currentTimeMillis() - startTime_share) + " : txnID : " + acpTxnID);
							authRespdetail.setUrl(lRetResp);
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ "ReAuth successful. Response to AsAuth-API: " + authRespdetail.getUrl() + "\n");
						}

					} else if (isAuthenticate != null && (isAuthenticate.contains("SUB")
							|| isAuthenticate.contains("sub") || isAuthenticate.contains("Sub"))) {

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

						if (loadtest) {
							authReqDetail.setTelco("LoadTest");
							String string = takeConsent(acpTxnID, acpID, request, response, authReqDetail.getSeckey());
							sb2.append(
									new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + string + "\n");
							lRetResp = acpTxnID;
						} else {
							authReqDetail.setTelco("Auth");
						}
						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(acpTxnID + "req", authReqDetail);

						sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
								+ " Display image over authRespdetail" + authRespdetail.getUrl() + "\n");
//						LoggingThread lt34 = new LoggingThread(
//								" [" + acpTxnID + "] " + " Display image over authRespdetail" + authRespdetail.getUrl());
//						lt34.start();
						// Logging.getLogger().info(" Display image over authRespdetail" +
						// authRespdetail.getUrl());
					}
				}
			} catch (Exception e1) {
				ErrorLoggingThread elt = new ErrorLoggingThread(
						" [" + acpTxnID + "] " + "Reg Exce :" + e1.getMessage());
				elt.start();
				// ErrorLogging.getLogger().info("Reg Exce :" + e1.getMessage());
				e1.printStackTrace();
			}
			MDC.clear();
			try {
				if (!loadtest) {
					lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail), isIphone);
				}
			} catch (Exception e) {
				ErrorLoggingThread elt = new ErrorLoggingThread(" [" + acpTxnID + "] " + "Enc Exce :" + e.getMessage());
				elt.start();
				// ErrorLogging.getLogger().info("Enc Exce :" + e.getMessage());
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E5: " + e
						+ "\n");
			}

//			LoggingThread lt35 = new LoggingThread(" [" + acpTxnID + "] " + "final ElapsedTime : "
//					+ (System.currentTimeMillis() - startTime) + " : txnID : " + acpTxnID);
//			lt35.start();
//		Logging.getLogger()
//				.info("final ElapsedTime : " + (System.currentTimeMillis() - startTime) + " : txnID : " + acpTxnID);
		} catch (Exception e) {
			sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception in AsAuth API: "
					+ e + "\n");
//			LoggingThread lt35 = new LoggingThread(" [" + acpTxnID + "] " + "Exception in AsAuth API: " + e);
//			lt35.start();
		} finally {
			AuthStatus authStatus = null;
			TimeDiffLogThread td3 = null;
			TimeDiffLogThread td2 = null;
			SecureImageResponse authRespdetail1 = null;
			try {
				if (authentication_status != null && !authentication_status.equals(SUCCESS)) {
					AuthStatus authStatus2 = authStatusRespRepoImpl.getAuthStatus(aMerTxnID + "authStatus");
					if (authStatus2 == null) {
						authStatus = new AuthStatus();
						authStatus.setMertxnID(aMerTxnID);
						authStatus.setStatus(authRespdetail.getStatusCode());
						authStatus.setMsisdn("0");
						authStatusRespRepoImpl.saveAuthStatus(aMerTxnID + "authStatus", authStatus);
					}

					td3 = new TimeDiffLogThread("AuthShareEntity", "read");
					td3.setCurrentTimeMillis(System.currentTimeMillis());
					AuthShareEntity authRes = mAuthDbService.getByTxnID(acpTxnID);
					td3.setCurrentTimeMillis2(System.currentTimeMillis());
					String shareRead = td3.start();
					sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + shareRead + "\n");
					if (authRes == null || (authRes.getStatus() == null || (!authRes.getStatus().equals(SUCCESS)
							&& !authRes.getStatus().equals(authRespdetail.getStatusCode())))) {
						asEntity.setStatus(authRespdetail.getStatusCode());
						asEntity.setUpdatedAt(new Date());
						asEntity.setOpn(aOpn);
						td2 = new TimeDiffLogThread("AuthShareEntity", "write");
						td2.setCurrentTimeMillis(System.currentTimeMillis());
						mAuthDbService.saveShare(asEntity);
						td2.setCurrentTimeMillis2(System.currentTimeMillis());
						String shareWrite1 = td2.start();
						sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + shareWrite1
								+ "\n");
					}

					Float sdk_version = Float.valueOf(sdk_ver);
					if (sdk_version != null && sdk_version < 2.15) {
						if (authRespdetail.getStatusCode().equals("AS101")
								|| authRespdetail.getStatusCode().equals("AS115")) {
							String encmsisdn = mEncDecObj.encrypt(ALTERNATE_NUM);
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ authRespdetail.getStatusCode() + " code occurs and url set in format: " + acpRdu
									+ "msisdn=" + encmsisdn + "&optxn=" + acpTxnID + "&atxnid=" + aMerTxnID + "\n");
							authRespdetail1 = new SecureImageResponse();
							authRespdetail1.setUrl(
									acpRdu + "msisdn=" + encmsisdn + "&optxn=" + acpTxnID + "&atxnid=" + aMerTxnID);
							lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail1), isIphone);
							sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
									+ "AsAuth resp: " + lRetResp + "\n");
						}

						if (authRespdetail.getStatusCode().equals("AS102")) {
							String txnID = mMCTrackTransRespoImpl.getTxnID(acpTxnID + "id");
							if (txnID == null) {
								authRespdetail1 = new SecureImageResponse();
								String encmsisdn = mEncDecObj.encrypt(ALTERNATE_NUM);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
										+ authRespdetail.getStatusCode()
										+ " code occurs and no TxnID found in redis so response url set in format: "
										+ acpRdu + "msisdn=" + encmsisdn + "&optxn=" + acpTxnID + "&atxnid=" + aMerTxnID
										+ "\n");
								authRespdetail1.setUrl(
										acpRdu + "msisdn=" + encmsisdn + "&optxn=" + acpTxnID + "&atxnid=" + aMerTxnID);
								lRetResp = mEncDecObj.encrypt(gson.toJson(authRespdetail1), isIphone);
								sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
										+ "AsAuth resp: " + lRetResp + "\n");
							}

						}
					}
				}
			} catch (Exception e) {
				System.out.println(e);
				sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "Exception in AsAuth API finally: " + e + "\n");
			}
			mdnHint = "";
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String asauthresp = td1.start();
			sb2.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + asauthresp + "\n");
			LoggingThread lt = new LoggingThread(sb2.toString());
			lt.start();
			sb2 = null;
			td1 = null;
			td3 = null;
			authStatus = null;
			authRespdetail1 = null;
			asEntity = null;
			authRespdetail = null;
			webparam = null;
			authReqDetail = null;
			signEnt = null;
			authentication_status = null;
		}
		return lRetResp;

	}

	private String takeConsent(String asTxnID, String aMid, HttpServletRequest request, HttpServletResponse response,
			String seckey) {
		Object[] list = null;
		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(asTxnID + "req");

			SecureImageResponse authRespdetail = new SecureImageResponse();

			String msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(asTxnID + "mn");
			if (msisdn == null) {
				msisdn = "9900990099";
			}

//			authRespdetail = sendImageReq(asTxnID, msisdn, aMid, request, response, seckey, false, null);
			list = sendImageReq(asTxnID, msisdn, aMid, request, response, seckey, false, null);
			authRespdetail = (SecureImageResponse) list[0];
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + asTxnID + "] " + "Exception E6: " + e + "\n");
			lt.start();
		}
		return list[1].toString();
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
				LoggingErrorThread let = new LoggingErrorThread(" [" + acpTxnID + "] " + imgresponse.toString());
				let.start();
				// Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);
			}
			resp = respStr.toString();
			LoggingThread lt36 = new LoggingThread(" [" + acpTxnID + "] " + "AppBotRespVal : " + resp);
			lt36.start();
			// Logging.getLogger().info("AppBotRespVal : " + resp);

		} catch (Exception e) {
			ErrorLoggingThread elt = new ErrorLoggingThread(
					" [" + acpTxnID + "] " + "Auth APP Bot error " + e.getMessage());
			elt.start();
			// ErrorLogging.getLogger().info(" [" + acpTxnID + "] " + "Auth APP Bot error "
			// +
			// e.getMessage());
		}
		return resp;
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
				LoggingErrorThread let = new LoggingErrorThread(" [" + acpTxnID + "] " + imgresponse.toString());
				let.start();
				// Logging.getLogger().error(imgresponse.toString());
				// System.out.println(imgresponse);
			}
			resp = respStr.toString();

			LoggingThread lt37 = new LoggingThread("BotRespVal : " + resp);
			lt37.start();
			// Logging.getLogger().info("BotRespVal : " + resp);

		} catch (Exception e) {
			ErrorLoggingThread elt = new ErrorLoggingThread("Auth Bot error " + e.getMessage());
			elt.start();
			// ErrorLogging.getLogger().info("Auth Bot error " + e.getMessage());
		}

		return resp;
	}

	@RequestMapping(value = "/chkmsisdn")
	@ResponseBody
	String checkMobNum(@RequestParam(value = "txnID", required = true) String aenccpTxnID, HttpServletRequest request,
			HttpServletResponse response) {

		String acpTxnID = "";
		String msisdn = "";
		String resp = "failure";
		boolean ipho = false;

		TimeDiffLogThread td1 = new TimeDiffLogThread("chkmsisdn");
		td1.setCurrentTimeMillis(System.currentTimeMillis());
		try {
			if (aenccpTxnID.contains("ipne")) {
				ipho = true;
				aenccpTxnID = aenccpTxnID.substring(4, aenccpTxnID.length());
			}

			try {
				LoggingThread lt38 = new LoggingThread("checkMobNum:" + "aenccpTxnID: " + aenccpTxnID);
				lt38.start();
				// Logging.getLogger().info("checkMobNum:" + "aenccpTxnID: " + aenccpTxnID);

				try {
					acpTxnID = mEncDecObj.decrypt(aenccpTxnID, ipho);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				MDC.put(LOG4J_MDC_TOKEN, acpTxnID);

				msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "mn");

				if (!TextUtils.isEmpty(msisdn)) {
					resp = "success";
				}

				LoggingThread lt39 = new LoggingThread(" [" + acpTxnID + "] " + "checkMobNum:" + "txnID: " + acpTxnID
						+ ", aMobnum" + mEncDecObj.encrypt(msisdn, ipho));
				lt39.start();
//			Logging.getLogger()
//					.info("checkMobNum:" + "txnID: " + acpTxnID + ", aMobnum" + mEncDecObj.encrypt(msisdn, ipho));
			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "Exception E7: " + e + "\n");
				lt.start();
			}
			MDC.clear();
		} catch (Exception e) {

		} finally {
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			td1.setTxnID(acpTxnID);
			td1.start();
		}
		return resp;
	}

	@RequestMapping(value = "/setmsisdn")
	@ResponseBody
	void setMobNum(@RequestParam(value = "message", required = true) String aenccpTxnID,
			@RequestParam(value = "mobilenumber", required = true) String aMsisdn, HttpServletRequest request,
			HttpServletResponse response) {

		SetMsisdnPojo CdrInfo = new SetMsisdnPojo();
		StringBuilder sb = new StringBuilder();
		String acpTxnID = "";
		boolean ipho = false;
		TimeDiffLogThread td1 = new TimeDiffLogThread("setmsisdnapi");
		td1.setCurrentTimeMillis(System.currentTimeMillis());

		try {
			Timestamp timestamp = new Timestamp(System.currentTimeMillis());
			CdrInfo.setReqTS(timestamp);
			CdrInfo.setApiName("setmsisdn");
			if (aMsisdn != null && !TextUtils.isEmpty(aMsisdn)) {
				CdrInfo.setRegnum(mEncDecObj.encrypt(aMsisdn));
			}
			CdrInfo.setAShieldTxnId(mEncDecObj.decrypt(aenccpTxnID));
			if (aenccpTxnID.contains("ipne")) {
				ipho = true;
				aenccpTxnID = aenccpTxnID.substring(4, aenccpTxnID.length());
			}

			try {
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "setMobNum:"
						+ "aenccpTxnID: " + aenccpTxnID + ", aMid" + mEncDecObj.encrypt(aMsisdn, ipho) + "\n");
//				LoggingThread lt1 = new LoggingThread(
//						"setMobNum:" + "aenccpTxnID: " + aenccpTxnID + ", aMid" + mEncDecObj.encrypt(aMsisdn, ipho));
//				lt1.start();
//			Logging.getLogger()
//					.info("setMobNum:" + "aenccpTxnID: " + aenccpTxnID + ", aMid" + mEncDecObj.encrypt(aMsisdn, ipho));

				try {
					acpTxnID = mEncDecObj.decrypt(aenccpTxnID, ipho);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "setMobNum:" + "txnID: "
						+ acpTxnID + ", aMid" + mEncDecObj.encrypt(aMsisdn, ipho) + "\n");
//				LoggingThread lt2 = new LoggingThread(" [" + acpTxnID + "] " + "setMobNum:" + "txnID: " + acpTxnID
//						+ ", aMid" + mEncDecObj.encrypt(aMsisdn, ipho));
//				lt2.start();
//			Logging.getLogger()
//					.info("setMobNum:" + "txnID: " + acpTxnID + ", aMid" + mEncDecObj.encrypt(aMsisdn, ipho));
			} catch (Exception e) {
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E9: " + e
						+ "\n");
			}

			if (acpTxnID.contains("auth")) {
				CdrInfo.setEnvironment("4da");
			} else if (acpTxnID.contains("saas")) {
				CdrInfo.setEnvironment("saas");
			} else if (acpTxnID.contains("vpn")) {
				CdrInfo.setEnvironment("poc");
			} else {
				CdrInfo.setEnvironment("NA");
				return;
			}
			TimeDiffLogThread td3 = new TimeDiffLogThread("AuthMobTxnEntity", "read");
			td3.setCurrentTimeMillis(System.currentTimeMillis());

			AuthMobTxnEntity mobTxnEntity = mAuthDbService.getByTxnId(acpTxnID);
			td3.setCurrentTimeMillis2(System.currentTimeMillis());
			String mMobTxnEntityread = td3.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + mMobTxnEntityread + "\n");
			if (mobTxnEntity != null && mobTxnEntity.getStatus().equals("completed")) {
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "Duplicated request arrived to setmsisdn API" + "\n");
				CdrInfo.setStatus("Duplicate");
				return;
			}
			if (null == mobTxnEntity) {
				mobTxnEntity = new AuthMobTxnEntity();
			}
			CdrInfo.setLongCode(mobTxnEntity.getSmshlc() + "");
			String status = "expired";
			String redisTxnID = mMCTrackTransRespoImpl.getTxnID(acpTxnID + "id");
			if (!aenccpTxnID.equals(redisTxnID)) {
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "TxnID not found in redis and authentication data not stored in DB" + "\n");
				CdrInfo.setStatus(status);
			} else {
				status = "completed";
				mMCTrackTransRespoImpl.saveToAshieldAuthRepoWithTimeout(acpTxnID + "mn", aMsisdn);
				mobTxnEntity.setMsisdn(aMsisdn);
				CdrInfo.setStatus(status);
			}
			CdrInfo.setMerTxnId("");
			CdrInfo.setSdkVersion("");
			CdrInfo.setSdkType("");
			CdrInfo.setDeviceTimestamp("");
			CdrInfo.setSimCount("");
			CdrInfo.setSelectedSim("");
			CdrInfo.setDf("");
			CdrInfo.setIP("");
			CdrInfo.setBua("");
			CdrInfo.setNType("");
			CdrInfo.setLongCode("");
			CdrInfo.setMid("");
			CdrInfo.setPurpose("");
			CdrInfo.setFlowType("");
			CdrInfo.setOpn1("");
			CdrInfo.setOpn2("");
			CdrInfo.setCauseOfReRegTrigger("");
			CdrInfo.setMobileDataStatus("");
			CdrInfo.setTransactionType("");
			CdrInfo.setRegNumMatch("");

			CdrInfo.setCircle("");
			mobTxnEntity.setTxnid(acpTxnID);
			mobTxnEntity.setRetrived(false);
			mobTxnEntity.setStatus(status);
			mobTxnEntity.setUpdatedAt(new Date());
			RegTxnRec regTxnRec = null;
			Optional<AuthRegistryDoc> opArd = mAuthDbService.findByTxnId(acpTxnID);
			AuthRegistryDoc ard = null;
			status = "expired";
			if (!opArd.isPresent()) {
				ard = createAuthRegDocFromSetmsisdn(acpTxnID, aenccpTxnID, aMsisdn);
			} else {
				ard = opArd.get();
				status = "completed";
			}
			if (null != ard) {
				ard.setApi(AuthRegistryDoc.API_SETMSISDN);
				// We will overwrite this state if and only if REG_INITIATED
				if (AuthRegistryDoc.REG_INITIATED == ard.getState()) {
					ard.setState(AuthRegistryDoc.SMS_RECEIVED);
				}
				regTxnRec = ard.getRegTxn();
				if (null != regTxnRec.getStatus()) {
					status = regTxnRec.getStatus();
				}
				Date regInitiatedAt = regTxnRec.getUpdatedAt();
				long smsTat = System.currentTimeMillis() - regInitiatedAt.getTime();
				regTxnRec.setSmsTat(smsTat);
				if ("completed".equals(status)) {
					regTxnRec.setCompleted(1 + regTxnRec.getCompleted());
				} else {
					regTxnRec.setExpired(1 + regTxnRec.getExpired());
				}
				regTxnRec.setStatus(status);
				ard.setMsisdn(aMsisdn);
				ard.setUpdatedAt(new Date());

				// Introducing test scenarios for testing all cases
				// While going live this condition must be removed
				if (1 == WebAuthSign.controlFlow || 8 == WebAuthSign.controlFlow) {
					mAuthDbService.saveAuthRegDoc(ard);
				}
			} else {
				// 2nd Reg Reg request came and txnID overwritten at client side
				// We cant use the same txnID because potential wrong identification of number
				// is possible. E.g. First request came from different number and SMS delayed
				// Meanwhile user cleared the data and initiated reg request from 2nd number
				// Now MO arrives from 1st number which results in problem
				// So this must be ignored and MO must come for new txnID
			}
			TimeDiffLogThread td2 = new TimeDiffLogThread("AuthMobTxnEntity", "write");
			td2.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveMob(mobTxnEntity);
			td2.setCurrentTimeMillis2(System.currentTimeMillis());
			String mMobTxnEntitywrite = td2.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + mMobTxnEntitywrite + "\n");
		} catch (Exception e) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
					+ "Exception in setmsisdn API : " + e);
		} finally {
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String setmsisdnresptime = td1.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + setmsisdnresptime + "\n");
			LoggingThread lt2 = new LoggingThread(sb.toString());
			lt2.start();
			CdrInfo.setProcessingTime((td1.getCurrentTimeMillis2() - td1.getCurrentTimeMillis()));
			CDRsetMsisdn.getCDRWriter().logCDR(CdrInfo);
		}

	}

	@RequestMapping(value = "/getsecure-img")
	@ResponseBody
	void getSecureImg(@RequestParam(value = "mTxnID", required = true) String acpTxnID,
			@RequestParam(value = "mID", required = true) String acpID, HttpServletRequest request,
			HttpServletResponse response) {

		Object[] list = null;
		StringBuffer sb = new StringBuffer();

		TimeDiffLogThread td1 = new TimeDiffLogThread("getsecure-img");
		td1.setCurrentTimeMillis(System.currentTimeMillis());

		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(acpTxnID + "req");
			sb.append(" [" + acpTxnID + "] " + "getsecure-img:" + "txnID: " + acpTxnID + ", aMid" + acpID + "\n");
//			LoggingThread lt39 = new LoggingThread(
//					" [" + acpTxnID + "] " + "getsecure-img:" + "txnID: " + acpTxnID + ", aMid" + acpID);
//			lt39.start();
			// Logging.getLogger().info("getsecure-img:" + "txnID: " + acpTxnID + ", aMid" +
			// acpID);

			SecureImageResponse authRespdetail = new SecureImageResponse();

			String msisdn = "";
			if (TextUtils.isEmpty(authReqDetail.getSecTxnID())) {
				msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "mn");
			} else {
				if (authReqDetail.getSecMsisdn().contentEquals("0")) {
					msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(acpTxnID + "mn");
				} else {
					msisdn = authReqDetail.getSecMsisdn();
				}

			}

//			authRespdetail = sendImageReq(acpTxnID, msisdn, acpID, request, response, authReqDetail.getSeckey(), false,
//					null);
			list = sendImageReq(acpTxnID, msisdn, acpID, request, response, authReqDetail.getSeckey(), false, null);
			authRespdetail = (SecureImageResponse) list[0];
			sb.append(list[1] + "\n");

			if (authRespdetail != null && authRespdetail.getStatusCode() != null
					&& authRespdetail.getStatusCode().contains("201")) {
				String log = displayImage(authRespdetail, request, response);
				sb.append(log + "\n");
				sb.append(" [" + acpTxnID + "] " + "displayImage over : " + "\n");
//				LoggingThread lt40 = new LoggingThread(" [" + acpTxnID + "] " + "displayImage over : ");
//				lt40.start();
				// Logging.getLogger().info("displayImage over : ");
			} else {
				LoggingThread lt41 = new LoggingThread(" [" + acpTxnID + "] " + "displayImage fail : ");
				lt41.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt1 = new CDRLoggingThread(authReqDetail,
						mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
				clt1.start();
//				CDRLogging.getCDRWriter().logCDR(authReqDetail, mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()),
//						SERVER_ERROR, "NA");
				String redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + acpTxnID + "&status="
						+ SERVER_ERROR + "&eshare=null";

				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", redirectUrl);
				response.sendRedirect(redirectUrl);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E10: " + e + "\n");
			lt.start();
		} finally {
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			td1.setTxnID(acpTxnID);
			td1.start();
		}
	}

	@RequestMapping(value = "/verify-mob")
	public @ResponseBody void dispmdnpag(@RequestParam(value = "mTxnID", required = true) String aTransID,
			HttpServletRequest request, HttpServletResponse response) {
		StringBuffer sb = new StringBuffer();
		sb.append(" [" + aTransID + "] " + "verify-mob : ");
//		LoggingThread lt42 = new LoggingThread(" [" + aTransID + "] " + "verify-mob : ");
//		lt42.start();
		// Logging.getLogger().info("verify-mob : ");
		TimeDiffLogThread td1 = new TimeDiffLogThread("verify-mob");
		td1.setCurrentTimeMillis(System.currentTimeMillis());
		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String redirectUrl = "";

			if (authReqDetail != null) {
				String log = displayMdnpage(aTransID, request, response);
				sb.append(log + "\n");
			} else {
				redirectUrl = lRedirectUrl + "msisdn=0" + "&txnid=" + aTransID + "&status=" + SERVER_ERROR
						+ "&eshare=null";
				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", redirectUrl);
				response.sendRedirect(redirectUrl);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E11: " + e + "\n");
			lt.start();
		} finally {
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			td1.setTxnID(aTransID);
			td1.start();
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();
		}

	}

	private String displayMdnpage(String txnID, HttpServletRequest request, HttpServletResponse response) {

		SecureImageResponse authRespdetail = new SecureImageResponse();
		StringBuffer sb = new StringBuffer();

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "rdu");
		String redirectUrl = "";

		try {
//			authRespdetail = sendImageReq(txnID, "null", authReqDetail.getCpID(), request, response,
//					authReqDetail.getSeckey(), false, null);
			Object[] list = sendImageReq(txnID, "null", authReqDetail.getCpID(), request, response,
					authReqDetail.getSeckey(), false, null);
			authRespdetail = (SecureImageResponse) list[0];
			sb.append(list[1] + "\n");

			if (authRespdetail != null && authRespdetail.getStatusCode() != null
					&& authRespdetail.getStatusCode().contains("201")) {

				WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

				RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/verify.jsp");

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
					sb.append("Exception--" + e.getMessage());
//					Logging.getLogger().info("Exception--" + e.getMessage());
				}
				sb.append(" [" + txnID + "] " + "displayImage over : ");
//				LoggingThread lt43 = new LoggingThread(" [" + txnID + "] " + "displayImage over : ");
//				lt43.start();
				// Logging.getLogger().info("displayImage over : ");
			} else {
				sb.append(" [" + txnID + "] " + "displayImage fail : ");
//				LoggingThread lt44 = new LoggingThread(" [" + txnID + "] " + "displayImage fail : ");
//				lt44.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt2 = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
				clt2.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
				redirectUrl = lRedirectUrl + "msisdn=0" + "&txnid=" + txnID + "&status=" + SERVER_ERROR
						+ "&eshare=null";
				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", redirectUrl);
				response.sendRedirect(redirectUrl);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E12: " + e + "\n");
			lt.start();
		}
		return sb.toString();
	}

	private Object[] validatedevfin(String acpTxnID, String aDeviceFin, String aDevShare, boolean isIphone,
			boolean multidev, String aShareUrl, HttpServletRequest request, HttpServletResponse response,
			boolean loadtest) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		list[1] = sb;
		AuthReqValidObj respObj = new AuthReqValidObj();
		TimeDiffLogThread td1 = new TimeDiffLogThread("AuthShareEntity", "read");
		td1.setCurrentTimeMillis(System.currentTimeMillis());
		AuthShareEntity authEntity = mAuthDbService.getByNewtxnID(acpTxnID);
		td1.setCurrentTimeMillis2(System.currentTimeMillis());
		String authEntityread = td1.start();
		sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + authEntityread + "\n");
		if (authEntity != null) {

			String share3 = ""; // getShareVal(acpTxnID, aShareUrl, request, response);

			long startTime_url = System.currentTimeMillis();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Share from url: " + share3
					+ ", " + "Share URL fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_url) + "\n");
//			LoggingThread lt45 = new LoggingThread(" [" + acpTxnID + "] " + "Share from url: " + share3 + ", "
//					+ "Share URL fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_url));
//			lt45.start();
//			Logging.getLogger().info("Share from url: " + share3);
//			Logging.getLogger().info("Share URL fetch ElapsedTime: " + (System.currentTimeMillis() - startTime_url));

//			String share1 = authEntity.getShare1();
			String share1 = aDevShare;
			String share2 = authEntity.getShare2();
			String msisdn = authEntity.getMsisdn();
			String opn = authEntity.getOpn();
			String mID = authEntity.getMid();
			boolean authed = authEntity.isAuthed();
			long timestamp = authEntity.getTimestamp();
			String passkey = authEntity.getPasskey();
			String[] passval = passkey.split("-");
			String lDevicefinP = aDeviceFin + passval[0];
			String mlen = msisdn.length() + passval[2];
			String aTransIDP = acpTxnID + passval[3];
			String tlen = "";
			tlen = acpTxnID.length() + passval[4];
			int plen = passkey.length();
			String lval = timestamp + lDevicefinP + mlen + passkey + aTransIDP + tlen + plen + msisdn + passval[1];
			String str = lval;
			if (!WebAuthSign.debug) {
				try {
					str = mEncDecObj.encrypt(str);
				} catch (Exception e) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception: : " + e
							+ "\n");
				}
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "lval: " + str + "\n");
			String encval = "";
			try {
				encval = mEncDecObj.encrypt(lval, isIphone);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			if (TextUtils.isEmpty(share3)) {
				share3 = authEntity.getShare3();
			}

			respObj.setStatus(authed);

			if (opn != null) {
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", opn);
			} else {
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(acpTxnID + "opn", "null");
			}

			if (!authed) {
				authEntity.setAuthed(true);
				TimeDiffLogThread td = new TimeDiffLogThread("AuthShareEntity", "write");
				td.setCurrentTimeMillis(System.currentTimeMillis());
				mAuthDbService.saveShare(authEntity);
				td.setCurrentTimeMillis2(System.currentTimeMillis());
				String authEntitywrite = td.start();
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "setting auth variable to true in DB, " + authEntitywrite + "\n");
			}

			String decShare1 = "";
			String decShare2 = "";
			String decShare3 = "";
			String condecshare = "";

			try {

				String decMsisdn = mEncDecObj.decrypt(msisdn, isIphone);

				if ((TextUtils.isEmpty(decMsisdn) || TextUtils.isEmpty(share1) || TextUtils.isEmpty(share2)
						|| TextUtils.isEmpty(share3)) && loadtest) {
					respObj.setMsisdn("9900990099");
					list[0] = respObj;
					list[1] = sb.toString();
					return list;
//					return respObj;
				}

				TimeDiffLogThread td2 = new TimeDiffLogThread("AuthMobDFEntity", "read");
				td2.setCurrentTimeMillis(System.currentTimeMillis());
				AuthMobDFEntity mModData = null;
				if (WebAuthSign.debug) {
					mModData = mAuthDbService.getByMsisdn(decMsisdn + mID);
				} else {
					mModData = mAuthDbService.getByMsisdn(mEncDecObj.encrypt(decMsisdn + mID));
					if (mModData != null) {
						mModData.setDevicefin(mEncDecObj.decrypt(mModData.getDevicefin()));
						mModData.setMsisdn(mEncDecObj.decrypt(mModData.getMsisdn()));
					}
				}
				td2.setCurrentTimeMillis2(System.currentTimeMillis());
				String mModDataread = td2.start();
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + mModDataread + "\n");

				if (mModData != null) {
					String devicefin1 = mModData.getDevicefin();
					if (!WebAuthSign.debug) {
						devicefin1 = mEncDecObj.encrypt(devicefin1);
					}
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "msisdn def :"
							+ devicefin1 + "\n");
//					LoggingThread lt46 = new LoggingThread(
//							" [" + acpTxnID + "] " + "msisdn def :" + mModData.getDevicefin());
//					lt46.start();
					// Logging.getLogger().info("msisdn def :" + mModData.getDevicefin());
				}

				decShare1 = mEncDecObj.decrypt(share1, isIphone /* , mEncDecObj.decrypt(mEncKey1) */);
				decShare2 = mEncDecObj.decrypt(share2, isIphone /* , mEncDecObj.decrypt(mEncKey2) */);
				decShare3 = mEncDecObj.decrypt(share3, isIphone /* , mEncDecObj.decrypt(mEncKey3) */);
				String decr = decShare1 + decShare2 + decShare3;
//				condecshare = mEncDecObj.decrypt(decr, isIphone);
//				String[] split = condecshare.split(txnIDSuffix);
//				CharSequence subSequence = split[1].subSequence(20, split[1].length() - 4);
//				String encmsisdn = mEncDecObj.encrypt(subSequence.toString(), isIphone);
//				encval = condecshare.replaceAll(subSequence.toString(), encmsisdn);
				if (WebAuthSign.debug) {
					encval = mEncDecObj.decrypt(encval, isIphone);
					decr = mEncDecObj.decrypt(decr, isIphone);
				}
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
						+ "validatedevfin() lgenerated: " + encval + ", from DB: " + decr + "\n");
//				try {
//					String decrypt = mEncDecObj.decrypt(msisdn, isIphone);
//				} catch (Exception e) {
//					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "decrypting error:" + e
//							+ "\n");
//					Logging.getLogger().info("decrypting error:" + e);
//				}
//				condecshare = mEncDecObj.decrypt(decr, isIphone /* , mEncDecObj.decrypt(mEncKey4) */);
//
//				String txnidLen = condecshare.substring(condecshare.length() - 2, condecshare.length());
//
//				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(txnidLen) - 2);
//
//				String msisdnlen = condecshare.substring(condecshare.length() - 2, condecshare.length());
//
//				String msisdnshre = condecshare.substring(condecshare.length() - Integer.valueOf(msisdnlen),
//						condecshare.length() - 2);
//
//				condecshare = condecshare.substring(0, condecshare.length() - Integer.valueOf(msisdnlen) - 2);

				// Logging.getLogger().info("msisdnshre :" + msisdnshre);

				if ((multidev || (mModData != null && mModData.getDevicefin().contentEquals(aDeviceFin)))
						/* && aDevShare.contentEquals(share1) */
						&& encval.contentEquals(decr) /* condecshare.contentEquals(aDeviceFin) */) {
					respObj.setMsisdn(mEncDecObj.decrypt(msisdn, isIphone));
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "validatedevfin :"
							+ mEncDecObj.encrypt(respObj.getMsisdn(), isIphone) + "\n");
//					LoggingThread lt47 = new LoggingThread(" [" + acpTxnID + "] " + "validatedevfin :"
//							+ mEncDecObj.encrypt(respObj.getMsisdn(), isIphone));
//					lt47.start();
					// Logging.getLogger().info("validatedevfin :" +
					// mEncDecObj.encrypt(respObj.getMsisdn(), isIphone));
				} else {
					respObj.setMsisdn("");
				}
			} catch (Exception e) {
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "e.printStackTrace():"
						+ e + "\n");
			}

		} else {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] "
					+ "authEntity : null for txnID :" + acpTxnID + "\n");
//			LoggingThread lt48 = new LoggingThread(" [" + acpTxnID + "] " + "authEntity : null for txnID :" + acpTxnID);
//			lt48.start();
			// Logging.getLogger().info("authEntity : null for txnID :" + acpTxnID);

			if (loadtest) {
				respObj.setMsisdn("9900990099");
			}

		}
		list[0] = respObj;
		list[1] = sb.toString();
		return list;
//		return respObj;
	}

	private String getLogErrorMsg(SecureImageResponse authRespdetail, Gson gson, AuthReqDetail authDetail,
			String statusCode) {
		String str = "";
		authRespdetail.setStatusCode(statusCode);
		if (!statusCode.equalsIgnoreCase(DISC_FAIL)) {
			CDRLoggingThread clt3 = new CDRLoggingThread(authDetail, "null", statusCode, "NA");
			clt3.start();
			// CDRLogging.getCDRWriter().logCDR(authDetail, "null", statusCode, "NA");
		}
		str = " [" + authDetail.getCpTxnID() + "] " + "authResp"
				+ gson.toJson(authRespdetail, SecureImageResponse.class);
//		LoggingThread lt49 = new LoggingThread(" [" + authDetail.getCpTxnID() + "] " + "authResp"
//				+ gson.toJson(authRespdetail, SecureImageResponse.class));
//		lt49.start();
		// Logging.getLogger().info("authResp" + gson.toJson(authRespdetail,
		// SecureImageResponse.class));
		return str;
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
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " ["
					+ lDiscRep.getCpTxnID() + "] " + "Exception E13: " + e + "\n");
			lt.start();
		}
		return finurl;
	}

	private Object[] processInfoTokenReq(String aSourceIP, String acpTxnID) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String lDiscoveryResp = "";
		String aBaseAuthstr = "";

		String lRedirectUrl = mInbRedirectUrl + "?txnid=" + acpTxnID;

		try {

			aBaseAuthstr = mEncDecObj.decrypt(mInbClientID) + "-" + mEncDecObj.decrypt(mInbClientSec);

			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "mDiscoverUrl : "
					+ mInfoDiscoverUrl + ", aSourceIP : " + aSourceIP + ", aBaseAuthstr : " + aBaseAuthstr + "\n");
//			LoggingThread lt50 = new LoggingThread(" [" + acpTxnID + "] " + "mDiscoverUrl : " + mInfoDiscoverUrl
//					+ ", aSourceIP : " + aSourceIP + ", aBaseAuthstr : " + aBaseAuthstr);
//			lt50.start();
//			Logging.getLogger().info("mDiscoverUrl : " + mInfoDiscoverUrl);
//			Logging.getLogger().info("aSourceIP : " + aSourceIP);
//			Logging.getLogger().info("aBaseAuthstr : " + aBaseAuthstr);

			HttpPost httpPost = new HttpPost(mInfoDiscoverUrl);

			JSONObject tokenreqObj = new JSONObject();
			tokenreqObj.put("returnUrl", lRedirectUrl);
			tokenreqObj.put("callbackUrl", mInbCallbackUrl);
			tokenreqObj.put("devicePort", "");
			tokenreqObj.put("deviceIp", aSourceIP);
			tokenreqObj.put("consentGranted", "true");

			StringEntity entity = new StringEntity(tokenreqObj.toString());
			httpPost.setEntity(entity);

			httpPost.setHeader("Authorization", "App " + aBaseAuthstr);
			httpPost.setHeader("Accept", "application/json");
			httpPost.setHeader("Cache-Control", "no-cache");
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("clientId", mInbClientIDdes);

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
				System.out.println(imgresponse);
			}
			lDiscoveryResp = lDiscoveryRespStr.toString();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "lDiscoveryResp : "
					+ lDiscoveryResp + ", lDiscoveryResp Resp length " + lDiscoveryResp.length() + "\n");
//			LoggingThread lt51 = new LoggingThread(" [" + acpTxnID + "] " + "lDiscoveryResp : " + lDiscoveryResp
//					+ ", lDiscoveryResp Resp length " + lDiscoveryResp.length());
//			lt51.start();
//			Logging.getLogger().info("lDiscoveryResp : " + lDiscoveryResp);
//			Logging.getLogger().info("lDiscoveryResp Resp length " + lDiscoveryResp.length());

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E14: " + e + "\n");
			lt.start();
		}
		list[0] = lDiscoveryResp.toString();
		list[1] = sb.toString();
		return list;
	}

	private Object[] createSession(String lTxnID) {
		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String lCreateSessionResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "mCreSesUrl : " + mCreSesUrl
					+ "\n");
//			LoggingThread lt52 = new LoggingThread(" [" + lTxnID + "] " + "mCreSesUrl : " + mCreSesUrl);
//			lt52.start();
			// Logging.getLogger().info("mCreSesUrl : " + mCreSesUrl);

			String lAuthStr = mEncDecObj.decrypt(mZomClientID) + "" + mEncDecObj.decrypt(mZomClientSec);

			// String lAuthStr =mZomClientID + mZomClientSec;

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
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "lCreateSessionResp : "
					+ lCreateSessionResp + "lCreateSessionResp Resp length " + lCreateSessionResp.length() + "\n");
//			LoggingThread lt53 = new LoggingThread(" [" + lTxnID + "] " + "lCreateSessionResp : " + lCreateSessionResp
//					+ "lCreateSessionResp Resp length " + lCreateSessionResp.length());
//			lt53.start();
			// Logging.getLogger().info("lCreateSessionResp : " + lCreateSessionResp);
			// Logging.getLogger().info("lCreateSessionResp Resp length " +
			// lCreateSessionResp.length());

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "Exception E15: " + e + "\n");
			lt.start();
		}
		list[0] = lCreateSessionResp;
		list[1] = sb;
		return list;

	}

	private Object[] processIdeNet(String aSourceIP, String acpTxnID) {
		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String lNetIdenResp = "";
		TimeDiffLogThread td = new TimeDiffLogThread("processIdeNet()");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "mNetIdeUrl : " + mNetIdeUrl
					+ ", aSourceIP : " + aSourceIP + "\n");
//			LoggingThread lt54 = new LoggingThread(
//					" [" + acpTxnID + "] " + "mNetIdeUrl : " + mNetIdeUrl + ", aSourceIP : " + aSourceIP);
//			lt54.start();
//			Logging.getLogger().info("mNetIdeUrl : " + mNetIdeUrl);
//			Logging.getLogger().info("aSourceIP : " + aSourceIP);

			// String lAuthStr =mZomClientID + mZomClientSec;

			String lAuthStr = mEncDecObj.decrypt(mZomClientID) + "" + mEncDecObj.decrypt(mZomClientSec);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "lAuthStr : " + lAuthStr
					+ "\n");
//			LoggingThread lt55 = new LoggingThread(" [" + acpTxnID + "] " + "lAuthStr : " + lAuthStr);
//			lt55.start();
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
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "lNetIdenResp : "
					+ lNetIdenResp + ", lNetIdenResp Resp length " + lNetIdenResp.length() + "\n");
//			LoggingThread lt56 = new LoggingThread(" [" + acpTxnID + "] " + "lNetIdenResp : " + lNetIdenResp
//					+ ", lNetIdenResp Resp length " + lNetIdenResp.length());
//			lt56.start();
//			Logging.getLogger().info("lNetIdenResp : " + lNetIdenResp);
//			Logging.getLogger().info("lNetIdenResp Resp length " + lNetIdenResp.length());

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + "Exception E16: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(acpTxnID);
			String tdlog = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + acpTxnID + "] " + tdlog + "\n");
		}
		list[0] = lNetIdenResp;
		list[1] = sb.toString();
		return list;
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
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + "Exception E17: " + e + "\n");
			lt.start();
			return null;
		}
		return lDiscResp;
	}

	Object[] validateSignature(String operatorSecretKey, String hash, String dataHashed, String aTransId)
			throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		boolean result = true;
		try {
//			String seckey = operatorSecretKey; 
			operatorSecretKey = mEncDecObj.decrypt(operatorSecretKey);
			String hashres = CommonHelper.generateSign(operatorSecretKey, dataHashed);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransId + "] " + "datatohashmc : "
					+ dataHashed + ", hashres : " + hashres);
//			LoggingThread lt57 = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransId + "] "
//					+ "datatohashmc : " + dataHashed + ", hashres : " + hashres);
//			lt57.start();
//			Logging.getLogger().info("datatohashmc : " + dataHashed);
//			Logging.getLogger().info("hashres : " + hashres);
			if (!hashres.contentEquals(hash)) {
				result = false;
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransId + "] " + "Exception E18: " + e + "\n");
			lt.start();
		}
		list[0] = result;
		list[1] = sb.toString();
		return list;
	}

	@RequestMapping(value = "/tokenReqInfo")
	public @ResponseBody void tokenReqInfo(@RequestParam(value = "txnID") String txnID, HttpServletResponse response,
			HttpServletRequest request) {

		MDC.put(LOG4J_MDC_TOKEN, txnID);
		StringBuilder sb = new StringBuilder();
		sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "txnID :" + txnID + "\n");
//		LoggingThread lt58 = new LoggingThread(" [" + txnID + "] " + "txnID :" + txnID);
//		lt58.start();
		// Logging.getLogger().info("txnID :" + txnID);

		String msisdn;
		String redirectUrl = "";
		SecureImageResponse mImageResp = new SecureImageResponse();

		TimeDiffLogThread td = new TimeDiffLogThread("tokenReqInfo");
		td.setCurrentTimeMillis(System.currentTimeMillis());

		try {

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "chan").equals("wap");

			String sesID = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "token");

			msisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(sesID + "token");

			if (authReqDetail != null && msisdn != null) {

				String veriftyp = authReqDetail.getVerType();

				if (!TextUtils.isEmpty(veriftyp) && veriftyp.contentEquals("VERIFY")) {
					// infobip verify flow
					authReqDetail.setTelco("INFOBIP-VERIFY");
				} else {

					authReqDetail.setTelco("INFOBIP-HE");

					String niTime = CommonHelper.getFormattedDateString();
					authReqDetail.setNitime(niTime);

					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "mn", msisdn);

					if (!authReqDetail.isMulitdevice()) {
						TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "read");
						td1.setCurrentTimeMillis(System.currentTimeMillis());
						AuthMobDFEntity lMobData = null;
						if (WebAuthSign.debug) {
							lMobData = mAuthDbService.getByMsisdn(msisdn + authReqDetail.getCpID());
						} else {
							lMobData = mAuthDbService.getByMsisdn(mEncDecObj.encrypt(msisdn + authReqDetail.getCpID()));
							if (lMobData != null) {
								lMobData.setDevicefin(mEncDecObj.decrypt(lMobData.getDevicefin()));
								lMobData.setMsisdn(mEncDecObj.decrypt(lMobData.getMsisdn()));
							}
						}
						td1.setCurrentTimeMillis2(System.currentTimeMillis());
						td1.setTxnID(txnID);
						String log = td1.start();
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + log + "\n");
						if (lMobData != null
								&& !lMobData.getDevicefin().contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
									+ "DF not match : " + lMobData.getDevicefin() + "DF not match : "
									+ authReqDetail.getDf() + "\n");
//							LoggingThread lt59 = new LoggingThread(" [" + txnID + "] " + "DF not match : "
//									+ lMobData.getDevicefin() + "DF not match : " + authReqDetail.getDf());
//							lt59.start();
//							Logging.getLogger().info("DF not match : " + lMobData.getDevicefin());
//							Logging.getLogger().info("DF not match : " + authReqDetail.getDf());
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "action", "rereg");
						} else if (lMobData != null) {
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "DF match : "
									+ lMobData.getDevicefin() + "\n");
//							LoggingThread lt60 = new LoggingThread(
//									" [" + txnID + "] " + "DF match : " + lMobData.getDevicefin());
//							lt60.start();
							// Logging.getLogger().info("DF match : " + lMobData.getDevicefin());
						} else {
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "NO DF Data : "
									+ "\n");
//							LoggingThread lt61 = new LoggingThread(" [" + txnID + "] " + "NO DF Data : ");
//							lt61.start();
							// Logging.getLogger().info("NO DF Data : ");
						}
					}

					if (authReqDetail.isNoconsent()) {

						AuthWebResp resp = new AuthWebResp();
						String newTxnID = getTransID();
						String lRedirectUrl = authReqDetail.getCpRdu();

						resp.setStatus(SUCCESS);
						resp.setToken(newTxnID);
						resp.setTxnID(authReqDetail.getMerTxnID());
						resp.setMsisdn(mEncDecObj.encrypt(msisdn));

						String reqTime = CommonHelper.getFormattedDateString();

						String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
						redisMessagePublisher.publish(message);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", txnID);

						mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

						redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS + "&mertxnid="
								+ authReqDetail.getMerTxnID();

						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", redirectUrl);
						response.sendRedirect(redirectUrl);

					} else if (authReqDetail.isTakeprime()) {
						redirectUrl = mMultiFlowUrl + "?transID=" + txnID;

						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", redirectUrl);
						response.sendRedirect(redirectUrl);
					} else {

//						mImageResp = sendImageReq(txnID, msisdn, authReqDetail.getCpID(), request, response,
//								authReqDetail.getSeckey(), false, null);
						Object[] list = sendImageReq(txnID, msisdn, authReqDetail.getCpID(), request, response,
								authReqDetail.getSeckey(), false, null);
						mImageResp = (SecureImageResponse) list[0];
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + list[1].toString()
								+ "\n");
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "mImageResp : "
								+ mImageResp.getStatusCode() + "\n");
//						LoggingThread lt62 = new LoggingThread(
//								" [" + txnID + "] " + "mImageResp : " + mImageResp.getStatusCode());
//						lt62.start();
						// Logging.getLogger().info("mImageResp : " + mImageResp.getStatusCode());

						if (mImageResp != null && mImageResp.getStatusCode() != null
								&& mImageResp.getStatusCode().contains("201")) {
							String log = displayImage(mImageResp, request, response);
							sb.append(new Timestamp(System.currentTimeMillis()) + log + "\n");
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
									+ "displayImage over : ");
//							LoggingThread lt63 = new LoggingThread(" [" + txnID + "] " + "displayImage over : ");
//							lt63.start();
							// Logging.getLogger().info("displayImage over : ");
						} else {
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
									+ "displayImage fail : " + "\n");
//							LoggingThread lt64 = new LoggingThread(" [" + txnID + "] " + "displayImage fail : ");
//							lt64.start();
							// Logging.getLogger().info("displayImage fail : ");

							CDRLoggingThread clt4 = new CDRLoggingThread(authReqDetail,
									mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
							clt4.start();
//							CDRLogging.getCDRWriter().logCDR(authReqDetail,
//									mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
							String sendClientResp = sendClientResp(authReqDetail.getCpTxnID(),
									authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + sendClientResp
									+ "\n");

							if (wap) {
								redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status="
										+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
							} else {
								redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status="
										+ SERVER_ERROR + "&eshare=null";
							}

							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", redirectUrl);
							response.sendRedirect(redirectUrl);
						}
					}

				}
			} else {
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", HE_FAIL, "NA");
				authReqDetail.setTempStatus(HE_FAIL);
				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);

				if (wap) {
					String sendClientResp = sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
							HE_FAIL, INVALID_ZERO, INVALID_ZERO);
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + sendClientResp + "\n");
					redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status=" + HE_FAIL
							+ "&mertxnid=" + authReqDetail.getMerTxnID();
				} else {
					redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status=" + HE_FAIL
							+ "&eshare=null";
					deleteredis(txnID);
				}
				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", redirectUrl);
				response.sendRedirect(redirectUrl);
				return;
			}

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E19: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(txnID);
			td.start();
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();
		}

	}

	// https://poc.ashieldhub.com/Ashield/tokenReqZom?
	// sesID=64330E9C-65DA-4F53-9F04-D402E7039034&
	// txnID=1704169843920b841f357a71de333ccb1be92be61vpn&
	// status=SUCCESS&
	// detmsg=MDNHINT_VERIFIED
	@RequestMapping(value = "/tokenReqZom")
	public @ResponseBody void tokenReqZom(@RequestParam(value = "sesID", required = false) String sesID,
			@RequestParam(value = "txnID") String txnID,
			@RequestParam(value = "status", required = false) String status,
			@RequestParam(value = "detmsg", required = false) String detmsg, HttpServletResponse response,
			HttpServletRequest request) {

//		MDC.put(LOG4J_MDC_TOKEN, txnID);

		TimeDiffLogThread td = new TimeDiffLogThread("tokenReqZom");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		StringBuilder sb = new StringBuilder();
		sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "sesID : " + sesID + ", txnID :"
				+ txnID + ", status : " + status + ", detmsg :" + detmsg + "\n");
//		LoggingThread lt1 = new LoggingThread(" [" + txnID + "] " + "sesID : " + sesID + ", txnID :" + txnID
//				+ ", status : " + status + ", detmsg :" + detmsg);
//		lt1.start();
//		Logging.getLogger()
//				.info("sesID : " + sesID + ", txnID :" + txnID + ", status : " + status + ", detmsg :" + detmsg);
		// New DB flow

		try {
			// server to server code should move here
			Optional<AuthRegistryDoc> opArd = mAuthDbService.findByTxnId(txnID);
			AuthRegistryDoc ard = null;
			int newState = AuthRegistryDoc.AUTH_FAILURE;
			if (!opArd.isPresent()) {
				// TODO : Need to think how to handle this
				// Because we dont have any reference for this request
				return;
			}

			ard = opArd.get();
			Object[] verifyTokenReqZom = verifyTokenReqZom(sesID, txnID, ard);
			boolean verifyTokenReqZomResp = (boolean) verifyTokenReqZom[0] != false ? (boolean) verifyTokenReqZom[0]
					: false;
//			to print the logs sequentially I have used sb variable, we can fix or alter this logging later
			sb.append(verifyTokenReqZom[1]);

			ard.setApi(AuthRegistryDoc.API_TOKENREQZOM);
			boolean verified = (null != status && "SUCCESS".equalsIgnoreCase(status) && null != detmsg
					&& "MDNHINT_VERIFIED".equalsIgnoreCase(detmsg));

			if (!verified || !verifyTokenReqZomResp) {
				ard.setState(AuthRegistryDoc.TELCO_FAILED);
				String redirectUrl = ard.getRdu() + "msisdn=0" + "&txnid=" + txnID + "&status=" + HE_FAIL
						+ "&eshare=null";
				// Send error response but must update the registration status in case txnID
				// found
				ard.setUpdatedAt(new Date());
				mAuthDbService.saveAuthRegDoc(ard);
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", redirectUrl);
				response.setHeader("Connection", "close");
				response.sendRedirect(redirectUrl);
				return;
			}
			// ard.setRegnum(regnum);
			RegTxnRec regTxnRec = ard.getRegTxn();
			int authFlow = ard.getAuthFlow();
			if (AuthRegistryDoc.TELCO_INITIATED == ard.getState()) {
				// This is reg completion flow. Shares wont be available
				long createShareTime = System.currentTimeMillis();
				AuthTxnRec old = ard.getAuthTxn();
				ard.setMsisdn(ard.getRegnum());
				AuthTxnRec atr = createAuthTxn(ard, txnID, ard.getRdu());
				if (null != old) {
					atr.setSuccess(old.getSuccess());
				} else {
					atr.setSuccess(1);
				}
				sb.append(atr.getResp() + "\n");
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "sendShare ElapsedTime : "
						+ (System.currentTimeMillis() - createShareTime) + "\n");
				// authRespdetail.setUrl(atr.getResp());
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
						+ "Reg successful. Response to TokenReqZom-API: " + atr.getResp() + "\n");
				ard.setState(AuthRegistryDoc.REG_SUCCESS);
				ard.setAuthTxn(atr);
				regTxnRec.setSuccess(1 + regTxnRec.getSuccess());
				ard.setUpdatedAt(new Date());
				mAuthDbService.saveAuthRegDoc(ard);
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", atr.getResp());
				response.setHeader("Connection", "close");
				response.sendRedirect(atr.getResp());
				return;
			}

			String msisdn = "";
			String redirectUrl = "";
			SecureImageResponse mImageResp = new SecureImageResponse();

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "chan").equals("wap");

			if (authReqDetail != null && status != null && status.contentEquals("SUCCESS")) {

				String veriftyp = authReqDetail.getVerType();

				if (!TextUtils.isEmpty(veriftyp) && veriftyp.contentEquals("VERIFY")) {
					if (!TextUtils.isEmpty(detmsg) && detmsg.contentEquals("MDNHINT_VERIFIED")) {

						String lDevicefin = "";
						String lMsisdn = "0";
						String newTxnID = getTransID();
						String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "rdu");
						String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "opn");

						lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "df");
						lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "mn");
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "tokenReqZom:"
								+ "lDevicefin: " + mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()) + "\n");
//						LoggingThread lt65 = new LoggingThread(" [" + txnID + "] " + "tokenReqZom:" + "lDevicefin: "
//								+ mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()));
//						lt65.start();
//						Logging.getLogger().info("tokenReqZom:" + "lDevicefin: "
//								+ mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()));

						boolean isReReg = false;

						if (!authReqDetail.isMulitdevice()) {
							TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "read");
							td1.setCurrentTimeMillis(System.currentTimeMillis());
							AuthMobDFEntity lMobData = null;
							if (WebAuthSign.debug) {
								lMobData = mAuthDbService.getByMsisdn(msisdn + authReqDetail.getCpID());
							} else {
								lMobData = mAuthDbService
										.getByMsisdn(mEncDecObj.encrypt(msisdn + authReqDetail.getCpID()));
								if (lMobData != null) {
									lMobData.setDevicefin(mEncDecObj.decrypt(lMobData.getDevicefin()));
									lMobData.setMsisdn(mEncDecObj.decrypt(lMobData.getMsisdn()));
								}
							}
							td1.setCurrentTimeMillis2(System.currentTimeMillis());
							td1.setTxnID(txnID);
							String log = td1.start();
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + log + "\n");
//							LoggingThread lt = new LoggingThread(" [" + txnID + "] " + log + "\n");
//							lt.start();
							if (lMobData != null && !lMobData.getDevicefin()
									.contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "DF not match : " + lMobData.getDevicefin() + "DF not match : "
										+ authReqDetail.getDf() + "\n");
//								LoggingThread lt66 = new LoggingThread(" [" + txnID + "] " + "DF not match : "
//										+ lMobData.getDevicefin() + "DF not match : " + authReqDetail.getDf());
//								lt66.start();
//								Logging.getLogger().info("DF not match : " + lMobData.getDevicefin());
//								Logging.getLogger().info("DF not match : " + authReqDetail.getDf());
								isReReg = true;
							} else if (lMobData != null) {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "DF match : " + lMobData.getDevicefin() + "\n");
//								LoggingThread lt67 = new LoggingThread(
//										" [" + txnID + "] " + "DF match : " + lMobData.getDevicefin());
//								lt67.start();
								// Logging.getLogger().info("DF match : " + lMobData.getDevicefin());
							} else {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "NO DF Data : " + "\n");
//								LoggingThread lt68 = new LoggingThread(" [" + txnID + "] " + "NO DF Data : ");
//								lt68.start();
								// Logging.getLogger().info("NO DF Data : ");
							}
						}

						if (authReqDetail.isTakeprime()) {
							redirectUrl = mMultiFlowUrl + "?transID=" + txnID;

							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", redirectUrl);
							response.sendRedirect(redirectUrl);
						} else if (authReqDetail.isNoconsent()) {

							AuthWebResp resp = new AuthWebResp();
							lRedirectUrl = authReqDetail.getCpRdu();

							resp.setStatus(SUCCESS);
							resp.setToken(newTxnID);
							resp.setTxnID(authReqDetail.getMerTxnID());
							resp.setMsisdn(mEncDecObj.encrypt(msisdn));

							String reqTime = CommonHelper.getFormattedDateString();

							String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
							redisMessagePublisher.publish(message);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", txnID);

							mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

							redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS + "&mertxnid="
									+ authReqDetail.getMerTxnID();

							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", redirectUrl);
							response.sendRedirect(redirectUrl);

						} else if (isReReg) {

							mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(txnID + "action");

//							mImageResp = sendImageReq(txnID, lMsisdn, authReqDetail.getCpID(), request, response,
//									authReqDetail.getSeckey(), false, null);
							Object[] list = sendImageReq(txnID, lMsisdn, authReqDetail.getCpID(), request, response,
									authReqDetail.getSeckey(), false, null);
							mImageResp = (SecureImageResponse) list[0];
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
									+ list[1].toString() + "\n");
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "mImageResp : "
									+ mImageResp.getStatusCode() + "\n");
//							LoggingThread lt68 = new LoggingThread(
//									" [" + txnID + "] " + "mImageResp : " + mImageResp.getStatusCode());
//							lt68.start();
							// Logging.getLogger().info("mImageResp : " + mImageResp.getStatusCode());

							if (mImageResp != null && mImageResp.getStatusCode() != null
									&& mImageResp.getStatusCode().contains("201")) {
								String log = displayImage(mImageResp, request, response);
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + log + "\n");
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "displayImage over : " + "\n");
//								LoggingThread lt69 = new LoggingThread(" [" + txnID + "] " + "displayImage over : ");
//								lt69.start();
								// Logging.getLogger().info("displayImage over : ");
							} else {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "displayImage fail : " + "\n");
//								LoggingThread lt70 = new LoggingThread(" [" + txnID + "] " + "displayImage fail : ");
//								lt70.start();
								// Logging.getLogger().info("displayImage fail : ");
								CDRLoggingThread clt5 = new CDRLoggingThread(authReqDetail,
										mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
								clt5.start();
//								CDRLogging.getCDRWriter().logCDR(authReqDetail,
//										mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
								String sendClientResp = sendClientResp(authReqDetail.getCpTxnID(),
										authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
								sb.append(new Timestamp(System.currentTimeMillis()) + sendClientResp);
								if (wap) {
									redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status="
											+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
								} else {
									redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status="
											+ SERVER_ERROR + "&eshare=null";
								}

								response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
								response.setHeader("Location", redirectUrl);
								response.sendRedirect(redirectUrl);
							}
						} else {
							String niTime = CommonHelper.getFormattedDateString();
							authReqDetail.setNitime(niTime);
							authReqDetail.setTelco("ZUMIGO-VERIFY");
							authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMsisdn));

							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);
							String generateshareLog = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn,
									response, txnID, "YES", authReqDetail.getCpID(), request, true);
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + generateshareLog
									+ "\n");
						}

					} else {
						if (authReqDetail.isOtpflow()) {

							String lMobileNumber = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "mn");
							SecureImageResponse authRespdetail = new SecureImageResponse();

//							authRespdetail = sendImageReq(txnID, lMobileNumber, authReqDetail.getCpID(), request,
//									response, authReqDetail.getSeckey(), true, null);
							Object[] list = sendImageReq(txnID, lMobileNumber, authReqDetail.getCpID(), request,
									response, authReqDetail.getSeckey(), true, null);
							authRespdetail = (SecureImageResponse) list[0];
							sb.append(list[1] + "\n");

							if (authRespdetail != null && authRespdetail.getStatusCode() != null
									&& authRespdetail.getStatusCode().contains("201")) {
								String log = displayOtpImage(authRespdetail, lMobileNumber, request, response, 4, true);
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + log + "\n");
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "displayImage over : " + "\n");
//								LoggingThread lt71 = new LoggingThread(" [" + txnID + "] " + "displayImage over : ");
//								lt71.start();
								// Logging.getLogger().info("displayImage over : ");
							} else {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "displayImage fail : " + "\n");
//								LoggingThread lt72 = new LoggingThread(" [" + txnID + "] " + "displayImage fail : ");
//								lt72.start();
								// Logging.getLogger().info("displayImage fail : ");
								CDRLoggingThread clt5 = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
								clt5.start();
								// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
								if (wap) {
									redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status="
											+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
								} else {
									redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status="
											+ SERVER_ERROR + "&eshare=null";
								}
								response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
								response.setHeader("Location", redirectUrl);
								response.sendRedirect(redirectUrl);
								return;
							}
						} else {
							if (wap) {
								redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status="
										+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
							} else {
								redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status="
										+ SERVER_ERROR + "&eshare=null";
							}
							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", redirectUrl);
							response.sendRedirect(redirectUrl);
							return;
						}
					}
				} else {

//					msisdn = processTokenReqZom(sesID, txnID);
					Object[] processTokenReqZom = processTokenReqZom(sesID, txnID, ard);
					msisdn = (String) processTokenReqZom[0];
					sb.append(processTokenReqZom[1]);

					if (TextUtils.isEmpty(msisdn)) {
						CDRLoggingThread clt6 = new CDRLoggingThread(authReqDetail, "0", SERVER_ERROR, "NA");
						clt6.start();
						// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", SERVER_ERROR, "NA");
						String sendClientResp = sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
								SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
						sb.append(new Timestamp(System.currentTimeMillis()) + sendClientResp);
						if (wap) {
							redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status="
									+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
						} else {
							redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status="
									+ SERVER_ERROR + "&eshare=null";
						}
						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", redirectUrl);
						response.sendRedirect(redirectUrl);
						return;
					} else {

						authReqDetail.setTelco("ZUMIGO-HE");

						String niTime = CommonHelper.getFormattedDateString();
						authReqDetail.setNitime(niTime);

						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "mn", msisdn);

						if (!authReqDetail.isMulitdevice()) {
							TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "read");
							td1.setCurrentTimeMillis(System.currentTimeMillis());
							AuthMobDFEntity lMobData = null;
							if (WebAuthSign.debug) {
								lMobData = mAuthDbService.getByMsisdn(msisdn + authReqDetail.getCpID());
							} else {
								lMobData = mAuthDbService
										.getByMsisdn(mEncDecObj.encrypt(msisdn + authReqDetail.getCpID()));
								if (lMobData != null) {
									lMobData.setDevicefin(mEncDecObj.decrypt(lMobData.getDevicefin()));
									lMobData.setMsisdn(mEncDecObj.decrypt(lMobData.getMsisdn()));
								}
							}
							td1.setCurrentTimeMillis2(System.currentTimeMillis());
							td1.setTxnID(txnID);
							String log = td1.start();
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + log + "\n");
//							LoggingThread lt = new LoggingThread(" [" + txnID + "] " + log + "\n");
//							lt.start();
							if (lMobData != null && !lMobData.getDevicefin()
									.contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "DF not match : " + lMobData.getDevicefin() + "DF not match : "
										+ authReqDetail.getDf() + "\n");
//								LoggingThread lt73 = new LoggingThread(" [" + txnID + "] " + "DF not match : "
//										+ lMobData.getDevicefin() + "DF not match : " + authReqDetail.getDf());
//								lt73.start();
								// Logging.getLogger().info("DF not match : " + lMobData.getDevicefin());
								// Logging.getLogger().info("DF not match : " + authReqDetail.getDf());
								mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "action", "rereg");
							} else if (lMobData != null) {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "DF match : " + lMobData.getDevicefin() + "\n");
//								LoggingThread lt74 = new LoggingThread(
//										" [" + txnID + "] " + "DF match : " + lMobData.getDevicefin());
//								lt74.start();
								// Logging.getLogger().info("DF match : " + lMobData.getDevicefin());
							} else {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "NO DF Data : " + "\n");
//								LoggingThread lt75 = new LoggingThread(" [" + txnID + "] " + "NO DF Data : ");
//								lt75.start();
								// Logging.getLogger().info("NO DF Data : ");
							}
						}

						if (authReqDetail.isNoconsent()) {

							AuthWebResp resp = new AuthWebResp();
							String newTxnID = getTransID();
							String lRedirectUrl = authReqDetail.getCpRdu();

							resp.setStatus(SUCCESS);
							resp.setToken(newTxnID);
							resp.setTxnID(authReqDetail.getMerTxnID());
							resp.setMsisdn(mEncDecObj.encrypt(msisdn));

							String reqTime = CommonHelper.getFormattedDateString();

							String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
							redisMessagePublisher.publish(message);

							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", txnID);

							mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

							/*
							 * redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS +
							 * "&mertxnid=" + authReqDetail.getMerTxnID();
							 */

							/*
							 * response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							 * response.setHeader("Location", redirectUrl);
							 * response.sendRedirect(redirectUrl);
							 */

							String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "opn");

							String lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "df");

							// Generate shares using new mechanism
							// Get the record using txnID
							// This is registration completion through telco redirection

							String generateshareLog = generateshare(lDevicefin, msisdn, newTxnID, lRedirectUrl, lOpn,
									response, txnID, "YES", authReqDetail.getCpID(), request, true);
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + generateshareLog
									+ "\n");

						} else if (authReqDetail.isTakeprime()) {
							redirectUrl = mMultiFlowUrl + "?transID=" + txnID;

							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", redirectUrl);
							response.sendRedirect(redirectUrl);
						} else {

//							mImageResp = sendImageReq(txnID, msisdn, authReqDetail.getCpID(), request, response,
//									authReqDetail.getSeckey(), false, null);
							Object[] list = sendImageReq(txnID, msisdn, authReqDetail.getCpID(), request, response,
									authReqDetail.getSeckey(), false, null);
							mImageResp = (SecureImageResponse) list[0];
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + list[1] + "\n");
							sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "mImageResp : "
									+ mImageResp.getStatusCode() + "\n");
//							LoggingThread lt76 = new LoggingThread(
//									" [" + txnID + "] " + "mImageResp : " + mImageResp.getStatusCode());
//							lt76.start();
							// Logging.getLogger().info("mImageResp : " + mImageResp.getStatusCode());

							if (mImageResp != null && mImageResp.getStatusCode() != null
									&& mImageResp.getStatusCode().contains("201")) {
								String log = displayImage(mImageResp, request, response);
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + log + "\n");
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "displayImage over : " + "\n");
//								LoggingThread lt77 = new LoggingThread(" [" + txnID + "] " + "displayImage over : ");
//								lt77.start();
								// Logging.getLogger().info("displayImage over : ");
							} else {
								sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
										+ "displayImage fail : " + "\n");
//								LoggingThread lt78 = new LoggingThread(" [" + txnID + "] " + "displayImage fail : ");
//								lt78.start();
								// Logging.getLogger().info("displayImage fail : ");
								CDRLoggingThread clt7 = new CDRLoggingThread(authReqDetail,
										mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
								clt7.start();
//								CDRLogging.getCDRWriter().logCDR(authReqDetail,
//										mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
								String sendClientResp = sendClientResp(authReqDetail.getCpTxnID(),
										authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
								sb.append(new Timestamp(System.currentTimeMillis()) + sendClientResp);
								if (wap) {
									redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status="
											+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
								} else {
									redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status="
											+ SERVER_ERROR + "&eshare=null";
								}
								response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
								response.setHeader("Location", redirectUrl);
								response.sendRedirect(redirectUrl);
							}
						}
					}
				}
			} else {
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", HE_FAIL, "NA");
				/*
				 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
				 * SERVER_ERROR , INVALID_ZERO , INVALID_ZERO);
				 */
				authReqDetail.setTempStatus(HE_FAIL);
				mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnID + "req", authReqDetail);
				if (wap) {
					String sendClientResp = sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
							HE_FAIL, INVALID_ZERO, INVALID_ZERO);
					sb.append(new Timestamp(System.currentTimeMillis()) + sendClientResp + "\n");
					redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status=" + HE_FAIL
							+ "&mertxnid=" + authReqDetail.getMerTxnID();
				} else {
					redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status=" + HE_FAIL
							+ "&eshare=null";
					deleteredis(txnID);
				}
				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", redirectUrl);
				response.sendRedirect(redirectUrl);
				return;
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E20: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(txnID);
			String tdlog = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + tdlog + "\n");
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();
		}
	}

	private Object[] verifyTokenReqZom(String sesID, String txnID, AuthRegistryDoc ard) {
		Object[] resp = new Object[2];
		Object[] processTokenReqZom = processTokenReqZom(sesID, txnID, ard);
		StringBuilder sb = new StringBuilder();
		sb.append(processTokenReqZom[1]);
		if (!sb.toString().contains("SUCCESS")) {
			resp[0] = false;
			resp[1] = sb;
			return resp;
		}
		resp[0] = true;
		resp[1] = sb;
		return resp;
	}

	private String displayOtpImage(SecureImageResponse mImageResp, String mobilenum, HttpServletRequest request,
			HttpServletResponse response, int clkcount, boolean sendMsg) {
		StringBuilder sb = new StringBuilder();
		String img1 = mImageResp.getImage1();
		String img2 = mImageResp.getImage2();
		String txt = mImageResp.getPtext();
		String txnID = mImageResp.getOptxn();
		String pshare = mImageResp.getPimage();
		boolean showotp = false;

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");
		WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

		if (authReqDetail != null && webparam != null) {
			try {
				if (sendMsg) {
//					showotp = sendotpmsg(txt, mobilenum, authReqDetail.getSmsurl());
					Object[] sendotpmsg = sendotpmsg(txt, mobilenum, authReqDetail.getSmsurl());
					showotp = (boolean) sendotpmsg[0];
					sb.append(sendotpmsg[1] + "\n");
				} else {
					showotp = true;
				}
			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(
						new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E21: " + e + "\n");
				lt.start();
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
			LoggingThread lt79 = new LoggingThread(" [" + txnID + "] " + "displayImage fail : ");
			lt79.start();
			// Logging.getLogger().info("displayImage fail : ");
			CDRLoggingThread clt8 = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
			clt8.start();
			// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "chan").equals("wap");
			String redirectUrl = "";

			if (wap) {
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
						INVALID_ZERO);
				redirectUrl = authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status=" + HE_FAIL + "&mertxnid="
						+ authReqDetail.getMerTxnID();
			} else {
				redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + txnID + "&status=" + HE_FAIL
						+ "&eshare=null";
				deleteredis(txnID);
			}
			response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
			response.setHeader("Location", redirectUrl);
			try {
				response.sendRedirect(redirectUrl);
			} catch (IOException e) {
				LoggingThread lt = new LoggingThread(
						new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E22: " + e + "\n");
				lt.start();
			}
			return sb.toString();
		}
		return sb.toString();
	}

	private Object[] sendotpmsg(String txt, String mobilenum, String url) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];

		String message = "Your OTP is " + txt + " This OTP is valid only for 10 minutes";
		StringBuilder imageStr = new StringBuilder();
		HttpPost httpPost = null;

		if (mobilenum.length() > 12) {
			mobilenum = mobilenum.substring(2, mobilenum.length());
		}

		try {

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
				LoggingThread lt80 = new LoggingThread("send sms resp : " + imageStr.toString());
				lt80.start();
				// Logging.getLogger().info("send sms resp : " + imageStr.toString());
				list[0] = true;
				list[1] = sb.toString();
//				return true;
				return list;
			} else {
				LoggingErrorThread let = new LoggingErrorThread(imgresponse.toString());
				let.start();
				// Logging.getLogger().error(imgresponse.toString());
				System.out.println(imgresponse);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + "sendotpmsg" + "] "
					+ "Exception E23: " + e + "\n");
			lt.start();
		}
		list[0] = false;
		list[1] = sb.toString();
		return list;
	}

	@RequestMapping(value = "/tokenReq")
	public @ResponseBody void tokenReq(@RequestParam(value = "code", required = true) String tokenCode,
			@RequestParam(value = "state", required = true) String stateID, HttpServletRequest request,
			HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("tokenReq");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		StringBuilder sb = new StringBuilder();

		SecureImageResponse mImageResp = new SecureImageResponse();
		DiscoveryResponse mRedisDiscResp;
		String lTokenRequrl = "";
		String lClientID = "";
		String lClientSecID = "";
		String lUserInfoUrl = "";
		String msisdn = "";

		MDC.put(LOG4J_MDC_TOKEN, stateID);

		LoggingThread lt81 = new LoggingThread(" [" + stateID + "] " + "code : " + tokenCode + " ,state=" + stateID);
		lt81.start();
		// Logging.getLogger().info("code : " + tokenCode + " ,state=" + stateID);

		try {
			mRedisDiscResp = mMCDiscoverRespRespoImpl.getValueFromAshiledMCRedisRepo(stateID + "_MC");

			if (mRedisDiscResp != null) {

				lTokenRequrl = mRedisDiscResp.getTokenURL();
				lClientID = mRedisDiscResp.getClient_id();
				lClientSecID = mRedisDiscResp.getClient_secret();
				lUserInfoUrl = mRedisDiscResp.getUserinfoURL();

				AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(stateID + "req");
				boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(stateID + "chan").equals("wap");

				LoggingThread lt82 = new LoggingThread(
						" [" + stateID + "] " + "lTokenRequrl : " + lTokenRequrl + "-lClientID=" + lClientID
								+ "-lClientSecID : " + lClientSecID + "-lUserInfoUrl=" + lUserInfoUrl);
				lt82.start();
//				Logging.getLogger().info("lTokenRequrl : " + lTokenRequrl + "-lClientID=" + lClientID
//						+ "-lClientSecID : " + lClientSecID + "-lUserInfoUrl=" + lUserInfoUrl);

				String lAuthStr = lClientID + ":" + lClientSecID;
				String lBaseAuthstr = Base64.getEncoder().encodeToString(lAuthStr.getBytes());

//				String lTokenResp = processTokenReq(lTokenRequrl, lBaseAuthstr, tokenCode, stateID);
				Object[] processTokenReq = processTokenReq(lTokenRequrl, lBaseAuthstr, tokenCode, stateID);
				String lTokenResp = (String) processTokenReq[0];
				sb.append(processTokenReq[1]);
				LoggingThread lt83 = new LoggingThread(
						" [" + stateID + "] " + "lTokenResp length: " + lTokenResp.length());
				lt83.start();
				// Logging.getLogger().info("lTokenResp length: " + lTokenResp.length());
				String redirectUrl = "";

				if (!TextUtils.isEmpty(lTokenResp)) {
//					msisdn = processTokenResp(lTokenResp, lUserInfoUrl, stateID);
					Object[] processTokenResp = processTokenResp(lTokenResp, lUserInfoUrl, stateID);
					msisdn = (String) processTokenResp[0];
					sb.append(processTokenResp[1]);
				} else {
					CDRLoggingThread clt9 = new CDRLoggingThread(authReqDetail, "0", SERVER_ERROR, "NA");
					clt9.start();
					// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", SERVER_ERROR, "NA");
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
							INVALID_ZERO);
					if (wap) {
						redirectUrl = mRedisDiscResp.getCprdu() + "token=" + INVALID_TOKEN + "&status=" + SERVER_ERROR
								+ "&mertxnid=" + authReqDetail.getMerTxnID();
					} else {
						redirectUrl = mRedisDiscResp.getCprdu() + "msisdn=0" + "&txnid=" + stateID + "&status="
								+ SERVER_ERROR + "&eshare=null";
					}
					response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
					response.setHeader("Location", redirectUrl);
					response.sendRedirect(redirectUrl);
					return;
				}

				if (TextUtils.isEmpty(msisdn)) {
					CDRLoggingThread clt10 = new CDRLoggingThread(authReqDetail, "0", SERVER_ERROR, "NA");
					clt10.start();
					// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", SERVER_ERROR, "NA");
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
							INVALID_ZERO);
					if (wap) {
						redirectUrl = mRedisDiscResp.getCprdu() + "token=" + INVALID_TOKEN + "&status=" + SERVER_ERROR
								+ "&mertxnid=" + authReqDetail.getMerTxnID();
					} else {
						redirectUrl = mRedisDiscResp.getCprdu() + "msisdn=0" + "&txnid=" + stateID + "&status="
								+ SERVER_ERROR + "&eshare=null";
					}
					response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
					response.setHeader("Location", redirectUrl);
					response.sendRedirect(redirectUrl);
					return;
				} else {

					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(stateID + "mn", msisdn);

					if (!authReqDetail.isMulitdevice()) {
						TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "read");
						td1.setCurrentTimeMillis(System.currentTimeMillis());
						AuthMobDFEntity lMobData = null;
						if (WebAuthSign.debug) {
							lMobData = mAuthDbService.getByMsisdn(msisdn + authReqDetail.getCpID());
						} else {
							lMobData = mAuthDbService.getByMsisdn(mEncDecObj.encrypt(msisdn + authReqDetail.getCpID()));
							if (lMobData != null) {
								lMobData.setDevicefin(mEncDecObj.decrypt(lMobData.getDevicefin()));
								lMobData.setMsisdn(mEncDecObj.decrypt(lMobData.getMsisdn()));
							}
						}
						td1.setCurrentTimeMillis2(System.currentTimeMillis());
						td1.setTxnID(stateID);
						String log = td1.start();
						LoggingThread lt = new LoggingThread(" [" + stateID + "] " + log + "\n");
						lt.start();
						if (lMobData != null
								&& !lMobData.getDevicefin().contentEquals(mEncDecObj.decrypt(authReqDetail.getDf()))) {
							LoggingThread lt84 = new LoggingThread(" [" + stateID + "] " + "DF not match : "
									+ lMobData.getDevicefin() + "DF not match : " + authReqDetail.getDf());
							lt84.start();
							// Logging.getLogger().info("DF not match : " + lMobData.getDevicefin());
							// Logging.getLogger().info("DF not match : " + authReqDetail.getDf());
							mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(stateID + "action", "rereg");
						} else if (lMobData != null) {
							LoggingThread lt85 = new LoggingThread(
									" [" + stateID + "] " + "DF match : " + lMobData.getDevicefin());
							lt85.start();
							// Logging.getLogger().info("DF match : " + lMobData.getDevicefin());
						} else {
							LoggingThread lt86 = new LoggingThread(" [" + stateID + "] " + "NO DF Data : ");
							lt86.start();
							// Logging.getLogger().info("NO DF Data : ");
						}
					}

					if (authReqDetail.isNoconsent()) {

						AuthWebResp resp = new AuthWebResp();
						String newTxnID = getTransID();
						String lRedirectUrl = authReqDetail.getCpRdu();

						resp.setStatus(SUCCESS);
						resp.setToken(newTxnID);
						resp.setTxnID(authReqDetail.getMerTxnID());
						resp.setMsisdn(mEncDecObj.encrypt(msisdn));

						String reqTime = CommonHelper.getFormattedDateString();

						String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
						redisMessagePublisher.publish(message);

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", stateID);

						mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

						redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS + "&mertxnid="
								+ authReqDetail.getMerTxnID();

						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", redirectUrl);
						response.sendRedirect(redirectUrl);

					} else if (authReqDetail.isTakeprime()) {
						redirectUrl = mMultiFlowUrl + "?transID=" + stateID;

						response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
						response.setHeader("Location", redirectUrl);
						response.sendRedirect(redirectUrl);
					} else {

//						mImageResp = sendImageReq(stateID, msisdn, mRedisDiscResp.getCpID(), request, response,
//								authReqDetail.getSeckey(), false, null);
						Object[] list = sendImageReq(stateID, msisdn, mRedisDiscResp.getCpID(), request, response,
								authReqDetail.getSeckey(), false, null);
						mImageResp = (SecureImageResponse) list[0];
						sb.append(list[1] + "\n");
						LoggingThread lt87 = new LoggingThread(
								" [" + stateID + "] " + "mImageResp : " + mImageResp.getStatusCode());
						lt87.start();
						// Logging.getLogger().info("mImageResp : " + mImageResp.getStatusCode());

						if (mImageResp != null && mImageResp.getStatusCode() != null
								&& mImageResp.getStatusCode().contains("201")) {
							String log = displayImage(mImageResp, request, response);
							sb.append(log + "\n");
							sb.append(" [" + stateID + "] " + "displayImage over : " + "\n");
//							LoggingThread lt88 = new LoggingThread(" [" + stateID + "] " + "displayImage over : ");
//							lt88.start();
							// Logging.getLogger().info("displayImage over : ");
						} else {
							LoggingThread lt89 = new LoggingThread(" [" + stateID + "] " + "displayImage fail : ");
							lt89.start();
							// Logging.getLogger().info("displayImage fail : ");
							CDRLoggingThread clt11 = new CDRLoggingThread(authReqDetail,
									mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
							clt11.start();
//							CDRLogging.getCDRWriter().logCDR(authReqDetail,
//									mEncDecObj.encrypt(msisdn, authReqDetail.isIPhone()), SERVER_ERROR, "NA");
							sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR,
									INVALID_ZERO, INVALID_ZERO);
							if (wap) {
								redirectUrl = mRedisDiscResp.getCprdu() + "token=" + INVALID_TOKEN + "&status="
										+ SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID();
							} else {
								redirectUrl = mRedisDiscResp.getCprdu() + "msisdn=0" + "&txnid=" + stateID + "&status="
										+ SERVER_ERROR + "&eshare=null";
							}

							response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							response.setHeader("Location", redirectUrl);
							response.sendRedirect(redirectUrl);
						}
					}
				}
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + stateID + "] " + "Exception E24: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(stateID);
			String dflog = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + stateID + "] " + dflog + "\n");
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();
		}
	}

	private String displayImage(SecureImageResponse mImageResp, HttpServletRequest request,
			HttpServletResponse response) {
		StringBuffer sb = new StringBuffer();
		String txnID = mImageResp.getOptxn();
		try {
			String img1 = mImageResp.getImage1();
			String img2 = mImageResp.getImage2();
			String txt = mImageResp.getPimage();
			String pshare = "YES";

			boolean isSubscription = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "action") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "action").equals("sub");

			boolean isReReg = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "action") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "action").equals("rereg");

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

			WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

			RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/aoc.jsp");

			request.setAttribute("img1", img1);
			request.setAttribute("img2", img2);
			request.setAttribute("optxn", txnID);
			request.setAttribute("pshare", pshare);
			request.setAttribute("pimg", txt);

			if (isReReg) {
				request.setAttribute("multi", 1);
				request.setAttribute("simcnt", 1);
				request.setAttribute("desc1", "You already registered this sim in other device");
				request.setAttribute("desc2", "Please click Yes to Confirm to register in this device");
			} else if (authReqDetail.isMulitdevice() && !authReqDetail.isAuthorize()) {
				request.setAttribute("multi", 2);
				request.setAttribute("simcnt", 1);
				request.setAttribute("desc1", webparam.getDesdata1());
				request.setAttribute("desc2", webparam.getDesdata2());
			} else if (authReqDetail.isMulitdevice() && authReqDetail.isAuthorize()) {
				request.setAttribute("multi", 1);
				request.setAttribute("simcnt", 1);
				request.setAttribute("desc1", "The number below is requesting access to your account. "
						+ "To provide access confirm by clicking on YES");
				request.setAttribute("desc2", webparam.getDesdata2());
			} else {
				request.setAttribute("multi", 1);
				request.setAttribute("simcnt", authReqDetail.getSimcount());
				request.setAttribute("desc1", webparam.getDesdata1());
				request.setAttribute("desc2", webparam.getDesdata2());
			}

			sb.append(" [" + txnID + "] " + "logo image " + webparam.getLogoimg() + "\n");
//			LoggingThread lt90 = new LoggingThread(" [" + txnID + "] " + "logo image " + webparam.getLogoimg());
//			lt90.start();
			// Logging.getLogger().info("logo image " + webparam.getLogoimg());

			request.setAttribute("meroptxn", authReqDetail.getMerTxnID());
			request.setAttribute("header", webparam.getHtext());
			request.setAttribute("hcolor", webparam.getHcolor());

			request.setAttribute("footer", webparam.getFtext());
			request.setAttribute("imgurl", webparam.getLogoimg());
			request.setAttribute("imgstr", webparam.getImgstr());
			request.setAttribute("t", mSessionTimeout);
			request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

			rd.forward(request, response);
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E25: " + e + "\n");
			lt.start();
			ErrorLoggingThread elt = new ErrorLoggingThread(" [" + txnID + "] " + "Exception--" + e.getMessage());
			elt.start();
			// ErrorLogging.getLogger().info("Exception--" + e.getMessage());
		}
		return sb.toString();
	}

	private Object[] processTokenResp(String lTokenResp, String lUserInfoUrl, String txnid) {
		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		list[1] = "";
		Gson gson = new Gson();
		String lUserInfoResp = "";
		try {
			if (!CommonHelper.isJSONValid(lTokenResp)) {
				list[0] = "";
				return list;
			}
			TokenResponse lResponse = gson.fromJson(lTokenResp, TokenResponse.class);
//			lUserInfoResp = processUserInfo(lResponse.getAccess_token(), lUserInfoUrl, txnid);
			Object[] processUserInfo = processUserInfo(lResponse.getAccess_token(), lUserInfoUrl, txnid);
			lUserInfoResp = (String) processUserInfo[0];
			sb.append(processUserInfo[1]);
			if (!TextUtils.isEmpty(lUserInfoResp) && CommonHelper.isJSONValid(lUserInfoResp)) {
				lUserInfoResp = processUserinfoResp(lUserInfoResp);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnid + "] " + "Exception E26: " + e + "\n");
			lt.start();
		}
		list[0] = lUserInfoResp;
		list[1] = sb.toString();
		return list;
	}

	private String processUserinfoResp(String lUserInfoResp) {
		String msisdn = "";
		Gson gson = new Gson();
		UserInfoResponse lUserResponse = gson.fromJson(lUserInfoResp, UserInfoResponse.class);

		msisdn = lUserResponse.getDevice_msisdn();

		return msisdn;
	}

	private Object[] processUserInfo(String access_token, String lUserInfoUrl, String txnid) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String lUserInfoResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder luserInfoRespStr = new StringBuilder();

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();

			HttpGet httpget = new HttpGet(lUserInfoUrl + "?schema=openid");
			httpget.setHeader("Authorization", "Bearer " + access_token);
			httpget.setConfig(conf);

			CloseableHttpResponse imgresponse = client.execute(httpget);
			if (imgresponse.getStatusLine().getStatusCode() == 200
					|| imgresponse.getStatusLine().getStatusCode() == 202) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					luserInfoRespStr.append(readLine);
				}
			} else {
				System.out.println(imgresponse);
			}
			lUserInfoResp = luserInfoRespStr.toString();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnid + "] " + "lUserInfoResp Resp length "
					+ lUserInfoResp.length() + "\n");
//			LoggingThread lt91 = new LoggingThread(
//					" [" + txnid + "] " + "lUserInfoResp Resp length " + lUserInfoResp.length());
//			lt91.start();
			// Logging.getLogger().info("lUserInfoResp Resp length " +
			// lUserInfoResp.length());

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnid + "] " + "Exception E27: " + e + "\n");
			lt.start();
		}
		list[0] = lUserInfoResp;
		list[1] = sb.toString();
		return list;
	}

	private Object[] processTokenReqZom(String sesID, String txnID, AuthRegistryDoc ard) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String mdnResp = "";

//		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		try {

			String lAuthStr = mEncDecObj.decrypt(mZomClientID, ard.isIphone()) + ""
					+ mEncDecObj.decrypt(mZomClientSec, ard.isIphone());

			String lTokenResp = "";
			// String lAuthStr =mZomClientID + mZomClientSec;

			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lDiscoveryRespStr = new StringBuilder();

			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "mLinIdeUrl : " + mLinIdeUrl
					+ " lAuthStr : " + lAuthStr + "\n");
//				LoggingThread lt92 = new LoggingThread(
//						" [" + txnID + "] " + "mLinIdeUrl : " + mLinIdeUrl + " lAuthStr : " + lAuthStr);
//				lt92.start();
			// Logging.getLogger().info("mLinIdeUrl : " + mLinIdeUrl + " lAuthStr : " +
			// lAuthStr);

			ArrayList<String> mylist = new ArrayList<>();

			// mylist.add("hashedMDN");
			String lVertype = ard.getTelcoVeriType(); // HE or VERIFY

			if (!TextUtils.isEmpty(lVertype) && lVertype.contains("VERIFY")) {
				mylist.add("rawMDN");
			} else {
				mylist.add("mdnVerify");
			}

			String reqTime = CommonHelper.getFormattedDateStringZOM();

			JSONObject reqObj = new JSONObject();
			JSONObject consentObj = new JSONObject();

			consentObj.put("optinType", "whitelist");
			consentObj.put("optinVersionId", "Consent V1.0.1234");
			consentObj.put("optinMethod", "TCO");
			consentObj.put("optinDuration", "ONE");
			consentObj.put("optinId", txnID);
			consentObj.put("optinTimestamp", reqTime);

			reqObj.put("consent", consentObj);

			reqObj.put("deviceSessionId", sesID);
			reqObj.put("optionList", mylist);

			HttpPost httpPost = new HttpPost(mLinIdeUrl);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "LineIdentity : "
					+ reqObj.toString() + "\n");
//				LoggingThread lt93 = new LoggingThread(" [" + txnID + "] " + "LineIdentity : " + reqObj.toString());
//				lt93.start();
			// Logging.getLogger().info("LineIdentity : " + reqObj.toString());

			StringEntity entity = new StringEntity(reqObj.toString());
			httpPost.setEntity(entity);
			httpPost.setHeader("Authorization", "Basic " + lAuthStr);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Accept", "application/json");
			httpPost.setHeader("clientId", mZomClientIDen);
			httpPost.setHeader("Cache-Control", "no-cache");

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
				System.out.println(imgresponse);
			}
			lTokenResp = lDiscoveryRespStr.toString();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Token : " + lTokenResp
					+ ", Token Resp length " + lTokenResp.length() + "\n");
//				LoggingThread lt94 = new LoggingThread(
//						" [" + txnID + "] " + "Token : " + lTokenResp + ", Token Resp length " + lTokenResp.length());
//				lt94.start();
//				Logging.getLogger().info("Token : " + lTokenResp);
//				Logging.getLogger().info("Token Resp length " + lTokenResp.length());

			if (lTokenResp.length() > 0) {
				JSONObject lTokrespJson = new JSONObject(lTokenResp);

				String status = lTokrespJson.getString("status");

				if (status.contentEquals("SUCCESS")) {
					if (!TextUtils.isEmpty(lVertype) && lVertype.contains("VERIFY")) {
						String msisdn = lTokrespJson.getString("rawMDN");
						mdnResp = msisdn;
					} else {
						mdnResp = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "mn");
					}
				}
			}

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E28: " + e + "\n");
			lt.start();
		}
		list[0] = mdnResp;
		list[1] = sb.toString();
		return list;
	}

	private Object[] processTokenReq(String lTokenRequrl, String lBaseAuthstr, String tokenCode, String txnid) {
		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String lTokenResp = "";

		try {
			CloseableHttpClient client = HttpClients.createDefault();
			StringBuilder lTokenRespStr = new StringBuilder();

			HttpPost httpPost = new HttpPost(lTokenRequrl);
			List<NameValuePair> params = new ArrayList<>();
			params.add(new BasicNameValuePair("redirect_uri", mRedirectUrl));
			params.add(new BasicNameValuePair("grant_type", "authorization_code"));
			params.add(new BasicNameValuePair("code", tokenCode));

			httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));
			httpPost.setHeader("Authorization", "Basic " + lBaseAuthstr);

			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);

			CloseableHttpResponse imgresponse = client.execute(httpPost);
			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					lTokenRespStr.append(readLine);
				}
			} else {
				System.out.println(imgresponse);
			}
			lTokenResp = lTokenRespStr.toString();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnid + "] " + "lTokenResp Resp length "
					+ lTokenResp.length() + "\n");
//			LoggingThread lt95 = new LoggingThread(
//					" [" + txnid + "] " + "lTokenResp Resp length " + lTokenResp.length());
//			lt95.start();
			// Logging.getLogger().info("lTokenResp Resp length " + lTokenResp.length());

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnid + "] " + "Exception E29: " + e + "\n");
			lt.start();
		}
		list[0] = lTokenResp;
		list[1] = sb.toString();
		return list;
	}

	@RequestMapping(value = "/validate-img")
	public @ResponseBody void checkImg(@RequestParam(value = "transID", required = true) String aTransID,
			@RequestParam("param5") String param5, @RequestParam(value = "en", required = false) String aesplatform,
			@RequestParam(value = "mertxnid", required = true) String aMerTxnID, HttpServletRequest request,
			HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("validate-img");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		try {

			ImageValidationResponse mImgResp = null;
			StringBuilder imageStr = new StringBuilder();
			String headerName = null;
			String headerValue = null;

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			if (authReqDetail != null) {

				boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true"))
						? true
						: false;

				String dataHashed = aTransID + param5;
				String hash = "";
				try {
					hash = CommonHelper.generateSign(authReqDetail.getSeckey(), dataHashed);
				} catch (Exception e1) {
					e1.printStackTrace();
				}

				MDC.put(LOG4J_MDC_TOKEN, aTransID);

				try {

					String decrypted_aesdata = null;
					// AES encryption Alogorithm from here
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

//					Logging.getLogger().info("*********************AES encrypted value of aesplatform --> salt : "
//							+ salt + ", iv : " + iv + ", ciphertext : " + ciphertext);
						decrypted_aesdata = aesEncryptDecrypt.decrypt(salt, iv, aTransID, ciphertext);
//					Logging.getLogger()
//							.info("*********************AES Decrypted platform from JS - " + decrypted_aesdata);

						LoggingThread lt96 = new LoggingThread(" [" + aTransID + "] "
								+ "*********************AES Encrypted_platform from JS - " + aesplatform
								+ ", *********************AES encrypted value of aesplatform --> salt : " + salt
								+ ", iv : " + iv + ", ciphertext : " + ciphertext
								+ ", *********************AES Decrypted platform from JS - " + decrypted_aesdata);
						lt96.start();

					}

					String platform = decrypted_aesdata != null
							? URLDecoder.decode(decrypted_aesdata.split("\\*")[0], "UTF-8")
							: "null";
					String scn_Size = decrypted_aesdata != null ? decrypted_aesdata.split("\\*")[1] : "null";
					String nav_bua = decrypted_aesdata != null
							? URLDecoder.decode(decrypted_aesdata.split("\\*")[2], "UTF-8")
							: "null";

					String otp = "null";

					if (decrypted_aesdata != null && decrypted_aesdata.split("\\*").length > 3) {
						otp = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[3], "UTF-8")
								: "null";
					}

					LoggingThread lt1 = new LoggingThread(
							" [" + aTransID + "] " + "*********************AES encrypted data --> Navigator_Platform : "
									+ platform + ", Navigator_userAgent : " + nav_bua + ", ScreenWidthHeight : "
									+ scn_Size + ", OTP : " + otp);
					lt1.start();
//				Logging.getLogger()
//						.info("*********************AES encrypted data --> Navigator_Platform : " + platform
//								+ ", Navigator_userAgent : " + nav_bua + ", ScreenWidthHeight : " + scn_Size
//								+ ", OTP : " + otp);

					String remoteIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
					String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null
							? request.getHeader("X-FORWARDED-FOR")
							: "null";
					String clientIP = request.getHeader("CLIENT_IP") != null ? request.getHeader("CLIENT_IP") : "null";
					String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
					String acpt = request.getHeader("accept");
					String userAgent = request.getHeader("user-agent");
					String mip = Stream.of(xforwardedIP, remoteIp, clientIP)
							.filter(s -> s != null && !s.isEmpty() && !s.equalsIgnoreCase("null"))
							.collect(Collectors.joining("-"));

					LoggingThread lt2 = new LoggingThread(" [" + aTransID + "] "
							+ "*** ChkImg Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
							+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
							+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);
					lt2.start();
//				Logging.getLogger()
//						.info("*** ChkImg Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
//								+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
//								+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);
					authReqDetail.setBua(userAgent);
					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

					Enumeration<String> headerNames = request.getHeaderNames();
					String headersInfo = "";
					while (headerNames.hasMoreElements()) {
						headerName = headerNames.nextElement();
						Enumeration<String> headers = request.getHeaders(headerName);
						while (headers.hasMoreElements()) {
							headerValue = headers.nextElement();
						}
						headersInfo = headersInfo + " [" + aTransID + "] " + "**HEADER --> " + headerName + " : "
								+ headerValue + "\n";
						// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
					}
					LoggingThread lt97 = new LoggingThread(headersInfo);
					lt97.start();

					HttpPost httpPost = new HttpPost(mChkImgReqUrl);
					List<NameValuePair> params = new ArrayList<>();
					params.add(new BasicNameValuePair("optxn", aTransID));
					params.add(new BasicNameValuePair("param5", param5));
					params.add(new BasicNameValuePair("sig", hash));
					params.add(new BasicNameValuePair("bua", nav_bua));
					// params.add(new BasicNameValuePair("ip", mip));
					params.add(new BasicNameValuePair("ip", xforwardedIP));
					params.add(new BasicNameValuePair("plf", platform));
					params.add(new BasicNameValuePair("srnsize", scn_Size));
					params.add(new BasicNameValuePair("qaDev", "true"));

					httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8.name()));
					httpPost.setHeader("origin", "https://junosecure");
					RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
							.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
					httpPost.setConfig(conf);
					CloseableHttpClient client = HttpClients.createDefault();
					CloseableHttpResponse imgresponse = client.execute(httpPost);
					if (imgresponse.getStatusLine().getStatusCode() == 200) {
						BufferedReader br = new BufferedReader(
								new InputStreamReader(imgresponse.getEntity().getContent()));
						String readLine;
						while (((readLine = br.readLine()) != null)) {
							imageStr.append(readLine);
						}
					}

					String lDevicefin = "";
					String lMsisdn = "0";
					String newTxnID = getTransID();
					String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
					String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");

					LoggingThread lt98 = new LoggingThread(" [" + aTransID + "] " + " Opn value :" + lOpn);
					lt98.start();
					// Logging.getLogger().info(" Opn value :" + lOpn);

					String redirectUrl = "";

					boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

					boolean isSubscription = mMCTrackTransRespoImpl
							.getValueFromAshiledAuthTranRepo(aTransID + "action") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action")
									.equals("sub");

					boolean isReReg = mMCTrackTransRespoImpl
							.getValueFromAshiledAuthTranRepo(aTransID + "action") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action")
									.equals("rereg");

					mImgResp = new Gson().fromJson(imageStr.toString(), ImageValidationResponse.class);
					if (mImgResp == null) {
						CDRLoggingThread clt12 = new CDRLoggingThread(authReqDetail, "0", SERVER_ERROR, "");
						clt12.start();
						// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", SERVER_ERROR, "");
						sendClientResp(aTransID, aMerTxnID, SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
						if (wap) {
							redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + SESSION_TIME_OUT
									+ "&mertxnid=" + aMerTxnID;
						} else {
							redirectUrl = "0" + "msisdn=" + mEncDecObj.encrypt("0", authReqDetail.isIPhone())
									+ "&txnid=" + aTransID + "&status=" + SESSION_TIME_OUT + "&eshare=" + ""
									+ "&result=" + "" + "&mtxnid=" + aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
						}
						MDC.clear();
						// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
						deleteredis(aTransID);
						response.sendRedirect(redirectUrl);
					}

					if (mImgResp.getStatusCode().contentEquals("JS201")
							&& (mImgResp.getResult().contentEquals("YES") || loadtest)) {
						lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "df");
						lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "mn");

						LoggingThread lt99 = new LoggingThread(" [" + aTransID + "] " + "validate-img:" + "lDevicefin: "
								+ mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()));
						lt99.start();
//					Logging.getLogger().info("validate-img:" + "lDevicefin: "
//							+ mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()));

						if (!otp.contains("null")) {

							LoggingThread lt100 = new LoggingThread(" [" + aTransID + "] " + "validate-otp:" + "otp: "
									+ otp + ", validate-otp:" + "sentOtp: " + authReqDetail.getSenotp());
							lt100.start();
							// Logging.getLogger().info("validate-otp:" + "otp: " + otp);
							// Logging.getLogger().info("validate-otp:" + "sentOtp: "
							// +authReqDetail.getSenotp());

							if (otp.equals("0")) {
								displayinOtppage(aTransID, request, response, aMerTxnID);
							} else {

								if (!authReqDetail.getSenotp().contentEquals(otp)) {
									CDRLoggingThread clt13 = new CDRLoggingThread(authReqDetail, "0", INVALID_OTP, "");
									clt13.start();
									// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", INVALID_OTP, "");
									sendClientResp(aTransID, aMerTxnID, INVALID_OTP, INVALID_ZERO, INVALID_ZERO);
									if (wap) {
										redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + INVALID_OTP
												+ "&mertxnid=" + aMerTxnID;
									} else {
										redirectUrl = "0" + "msisdn="
												+ mEncDecObj.encrypt("0", authReqDetail.isIPhone()) + "&txnid="
												+ aTransID + "&status=" + INVALID_OTP + "&eshare=" + "" + "&result="
												+ "" + "&mtxnid=" + aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
									}
									MDC.clear();
									deleteredis(aTransID);
									response.sendRedirect(redirectUrl);
									return;
								}
							}
						}

						if (isReReg) {

							mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "action");

							authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMsisdn));

							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

							generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response, aTransID,
									mImgResp.getResult(), authReqDetail.getCpID(), request, true);

							/*
							 * SecureImageResponse mImageResp = sendImageReq(aTransID, lMsisdn,
							 * authReqDetail.getCpID(), request, response, authReqDetail.getSeckey(), false,
							 * null); Logging.getLogger().info("mImageResp : " + mImageResp.getStatusCode()
							 * );
							 * 
							 * if(mImageResp != null && mImageResp.getStatusCode() != null &&
							 * mImageResp.getStatusCode().contains("201")) { displayImage(mImageResp,
							 * request, response); Logging.getLogger().info("displayImage over : "); } else
							 * { Logging.getLogger().info("displayImage fail : ");
							 * CDRLogging.getCDRWriter().logCDR(authReqDetail, mEncDecObj.encrypt(lMsisdn,
							 * authReqDetail.isIPhone()), SERVER_ERROR, "NA");
							 * sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(),
							 * SERVER_ERROR , INVALID_ZERO , INVALID_ZERO); if(wap) { redirectUrl =
							 * authReqDetail.getCpRdu() + "token=" + INVALID_TOKEN + "&status=" +
							 * SERVER_ERROR + "&mertxnid=" + authReqDetail.getMerTxnID(); } else {
							 * redirectUrl = authReqDetail.getCpRdu() + "msisdn=0" + "&txnid=" + aTransID +
							 * "&status=" + SERVER_ERROR + "&eshare=null"; }
							 * 
							 * response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
							 * response.setHeader("Location", redirectUrl);
							 * response.sendRedirect(redirectUrl); }
							 */
						} else if (isSubscription) {
							// Do Subscription
							generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response, aTransID,
									mImgResp.getResult(), authReqDetail.getCpID(), request, true);
						} else {

							authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMsisdn));

							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

							generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response, aTransID,
									mImgResp.getResult(), authReqDetail.getCpID(), request, true);
						}

					} else {
						CDRLoggingThread clt14 = new CDRLoggingThread(authReqDetail,
								mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), USER_CANCLED,
								mImgResp.getResult());
						clt14.start();
//					CDRLogging.getCDRWriter().logCDR(authReqDetail,
//							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), USER_CANCLED, mImgResp.getResult());
						sendClientResp(aTransID, aMerTxnID, USER_CANCLED, INVALID_ZERO, INVALID_ZERO);

						if (authReqDetail.isAuthorize()) {
							lDevicefin = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "df");
							lMsisdn = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "mn");

							generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response, aTransID,
									mImgResp.getResult(), authReqDetail.getCpID(), request, false);
						} else {

							if (wap) {
								Cookie cookie = new Cookie("authshare", "");
								cookie.setDomain(System.getenv("DOMAIN_NAME"));
								cookie.setPath(request.getContextPath());
								cookie.setMaxAge(0);
								response.addCookie(cookie);
								redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + USER_CANCLED
										+ "&mertxnid=" + aMerTxnID;
							} else {
								redirectUrl = lRedirectUrl + "msisdn="
										+ mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()) + "&txnid=" + "0"
										+ "&status=" + USER_CANCLED + "&eshare=" + "" + "&result="
										+ mImgResp.getResult() + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid="
										+ aTransID + "&opn=" + lOpn;
								// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
								deleteredis(aTransID);
							}
							MDC.clear();
							response.setHeader("Location", redirectUrl);
							response.setHeader("Connection", "close");
							response.sendRedirect(redirectUrl);
						}
					}

				} catch (Exception e) {
					MDC.clear();
					LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID
							+ "] " + "Exception E30: " + e + "\n");
					lt.start();
				}
			} else {

				try {
					boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

					String redirectUrl;

					String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");

					if (wap) {
						Cookie cookie = new Cookie("authshare", "");
						cookie.setDomain(System.getenv("DOMAIN_NAME"));
						cookie.setPath(request.getContextPath());
						cookie.setMaxAge(0);
						response.addCookie(cookie);
						redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + SESSION_TIME_OUT
								+ "&mertxnid=" + aMerTxnID;
					} else {
						redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt("0", false) + "&txnid=" + "0"
								+ "&status=" + USER_CANCLED + "&eshare=" + "" + "&result=" + "No" + "&mtxnid="
								+ aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
						deleteredis(aTransID);
					}
					MDC.clear();
					response.setHeader("Location", redirectUrl);
					response.setHeader("Connection", "close");
					response.sendRedirect(redirectUrl);
				} catch (Exception e) {
					LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID
							+ "] " + "Exception E31: " + e + "\n");
					lt.start();
				}
			}
		} catch (Exception e) {
			System.out.println(e);
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(aTransID);
			td.start();
		}
	}

	@RequestMapping(value = "/validate-img-load")
	public @ResponseBody String checkImgload(@RequestParam(value = "transID", required = true) String aTransID,
			@RequestParam("param5") String param5, @RequestParam(value = "en", required = false) String aesplatform,
			@RequestParam(value = "mertxnid", required = true) String aMerTxnID, HttpServletRequest request,
			HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("validate-img-load");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		StringBuilder sb = new StringBuilder();
		ImageValidationResponse mImgResp = null;
		StringBuilder imageStr = new StringBuilder();
		String headerName = null;
		String headerValue = null;
		String shareresp = "";
		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			if (authReqDetail != null) {

				boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true"))
						? true
						: false;

				String dataHashed = aTransID + param5;
				String hash = "";
				try {
					hash = CommonHelper.generateSign(authReqDetail.getSeckey(), dataHashed);
				} catch (Exception e1) {
					e1.printStackTrace();
				}

				MDC.put(LOG4J_MDC_TOKEN, aTransID);

				try {

					String decrypted_aesdata = null;
					// AES encryption Alogorithm from here
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

//					Logging.getLogger().info("*********************AES encrypted value of aesplatform --> salt : "
//							+ salt + ", iv : " + iv + ", ciphertext : " + ciphertext);
						decrypted_aesdata = aesEncryptDecrypt.decrypt(salt, iv, aTransID, ciphertext);
//					Logging.getLogger()
//							.info("*********************AES Decrypted platform from JS - " + decrypted_aesdata);

						LoggingThread lt101 = new LoggingThread(" [" + aTransID + "] "
								+ "*********************AES Encrypted_platform from JS - " + aesplatform
								+ ", *********************AES encrypted value of aesplatform --> salt : " + salt
								+ ", iv : " + iv + ", ciphertext : " + ciphertext
								+ ", *********************AES Decrypted platform from JS - " + decrypted_aesdata);
						lt101.start();

					}

					String platform = decrypted_aesdata != null
							? URLDecoder.decode(decrypted_aesdata.split("\\*")[0], "UTF-8")
							: "null";
					String scn_Size = decrypted_aesdata != null ? decrypted_aesdata.split("\\*")[1] : "null";
					String nav_bua = decrypted_aesdata != null
							? URLDecoder.decode(decrypted_aesdata.split("\\*")[2], "UTF-8")
							: "null";

					String otp = "null";

					if (decrypted_aesdata != null && decrypted_aesdata.split("\\*").length > 3) {
						otp = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[3], "UTF-8")
								: "null";
					}

					LoggingThread lt3 = new LoggingThread(
							" [" + aTransID + "] " + "*********************AES encrypted data --> Navigator_Platform : "
									+ platform + ", Navigator_userAgent : " + nav_bua + ", ScreenWidthHeight : "
									+ scn_Size + ", OTP : " + otp);
					lt3.start();
//				Logging.getLogger()
//						.info("*********************AES encrypted data --> Navigator_Platform : " + platform
//								+ ", Navigator_userAgent : " + nav_bua + ", ScreenWidthHeight : " + scn_Size
//								+ ", OTP : " + otp);

					String remoteIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
					String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null
							? request.getHeader("X-FORWARDED-FOR")
							: "null";
					String clientIP = request.getHeader("CLIENT_IP") != null ? request.getHeader("CLIENT_IP") : "null";
					String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
					String acpt = request.getHeader("accept");
					String userAgent = request.getHeader("user-agent");
					String mip = Stream.of(xforwardedIP, remoteIp, clientIP)
							.filter(s -> s != null && !s.isEmpty() && !s.equalsIgnoreCase("null"))
							.collect(Collectors.joining("-"));

					LoggingThread lt4 = new LoggingThread(" [" + aTransID + "] "
							+ "*** ChkImg Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
							+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
							+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);
					lt4.start();

//				Logging.getLogger()
//						.info("*** ChkImg Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
//								+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
//								+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);
					authReqDetail.setBua(userAgent);
					mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

					Enumeration<String> headerNames = request.getHeaderNames();
					String headersInfo = "";
					while (headerNames.hasMoreElements()) {
						headerName = headerNames.nextElement();
						Enumeration<String> headers = request.getHeaders(headerName);
						while (headers.hasMoreElements()) {
							headerValue = headers.nextElement();
						}
						headersInfo = headersInfo + " [" + aTransID + "] " + "**HEADER --> " + headerName + " : "
								+ headerValue + "\n";
						// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
					}
					LoggingThread lt102 = new LoggingThread(headersInfo);
					lt102.start();

					HttpPost httpPost = new HttpPost(mChkImgReqUrl);
					List<NameValuePair> params = new ArrayList<>();
					params.add(new BasicNameValuePair("optxn", aTransID));
					params.add(new BasicNameValuePair("param5", param5));
					params.add(new BasicNameValuePair("sig", hash));
					params.add(new BasicNameValuePair("bua", nav_bua));
					// params.add(new BasicNameValuePair("ip", mip));
					params.add(new BasicNameValuePair("ip", xforwardedIP));
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
						BufferedReader br = new BufferedReader(
								new InputStreamReader(imgresponse.getEntity().getContent()));
						String readLine;
						while (((readLine = br.readLine()) != null)) {
							imageStr.append(readLine);
						}
					}

					String lDevicefin = "";
					String lMsisdn = "0";
					String newTxnID = getTransID();
					String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
					String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");

					LoggingThread lt103 = new LoggingThread(" [" + aTransID + "] " + " Opn value :" + lOpn);
					lt103.start();
					// Logging.getLogger().info(" Opn value :" + lOpn);

					String redirectUrl = "";

					boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

					boolean isSubscription = mMCTrackTransRespoImpl
							.getValueFromAshiledAuthTranRepo(aTransID + "action") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action")
									.equals("sub");

					boolean isReReg = mMCTrackTransRespoImpl
							.getValueFromAshiledAuthTranRepo(aTransID + "action") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action")
									.equals("rereg");

					mImgResp = new Gson().fromJson(imageStr.toString(), ImageValidationResponse.class);
					if (mImgResp == null) {
						CDRLoggingThread clt15 = new CDRLoggingThread(authReqDetail, "0", SERVER_ERROR, "");
						clt15.start();
						// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", SERVER_ERROR, "");
						sendClientResp(aTransID, aMerTxnID, SERVER_ERROR, INVALID_ZERO, INVALID_ZERO);
						if (wap) {
							redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + SESSION_TIME_OUT
									+ "&mertxnid=" + aMerTxnID;
						} else {
							redirectUrl = "0" + "msisdn=" + mEncDecObj.encrypt("0", authReqDetail.isIPhone())
									+ "&txnid=" + aTransID + "&status=" + SESSION_TIME_OUT + "&eshare=" + ""
									+ "&result=" + "" + "&mtxnid=" + aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
						}
						MDC.clear();
						// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
						deleteredis(aTransID);
						// response.sendRedirect(redirectUrl);
					}

					if ((mImgResp.getStatusCode().contentEquals("JS201") && (mImgResp.getResult().contentEquals("YES"))
							|| loadtest)) {
						lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "df");
						lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "mn");

						LoggingThread lt104 = new LoggingThread(" [" + aTransID + "] " + "validate-img:"
								+ "lDevicefin: " + mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()));
						lt104.start();
//					Logging.getLogger().info("validate-img:" + "lDevicefin: "
//							+ mEncDecObj.encrypt(lDevicefin, authReqDetail.isIPhone()));

						if (!otp.contains("null")) {

							LoggingThread lt105 = new LoggingThread(" [" + aTransID + "] " + "validate-otp:" + "otp: "
									+ otp + "validate-otp:" + "sentOtp: " + authReqDetail.getSenotp());
							lt105.start();
							// Logging.getLogger().info("validate-otp:" + "otp: " + otp);
							// Logging.getLogger().info("validate-otp:" + "sentOtp: " +
							// authReqDetail.getSenotp());

							if (otp.equals("0")) {
								displayinOtppage(aTransID, request, response, aMerTxnID);
							} else {

								if (!authReqDetail.getSenotp().contentEquals(otp)) {
									CDRLoggingThread clt16 = new CDRLoggingThread(authReqDetail, "0", INVALID_OTP, "");
									clt16.start();
									// CDRLogging.getCDRWriter().logCDR(authReqDetail, "0", INVALID_OTP, "");
									sendClientResp(aTransID, aMerTxnID, INVALID_OTP, INVALID_ZERO, INVALID_ZERO);
									if (wap) {
										redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + INVALID_OTP
												+ "&mertxnid=" + aMerTxnID;
									} else {
										redirectUrl = "0" + "msisdn="
												+ mEncDecObj.encrypt("0", authReqDetail.isIPhone()) + "&txnid="
												+ aTransID + "&status=" + INVALID_OTP + "&eshare=" + "" + "&result="
												+ "" + "&mtxnid=" + aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
									}
									MDC.clear();
									deleteredis(aTransID);
									// response.sendRedirect(redirectUrl);
									return null;
								}
							}
						}

						if (isReReg) {

							mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "action");

							authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMsisdn));

							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

//							shareresp = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response,
//									aTransID, mImgResp.getResult(), authReqDetail.getCpID(), request, true, true);
							Object[] generateshare = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn,
									response, aTransID, mImgResp.getResult(), authReqDetail.getCpID(), request, true,
									true);
							shareresp = (String) generateshare[0];
							sb.append(generateshare[1] + "\n");
						} else if (isSubscription) {
							// Do Subscription
//							shareresp = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response,
//									aTransID, mImgResp.getResult(), authReqDetail.getCpID(), request, true, true);
							Object[] generateshare = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn,
									response, aTransID, mImgResp.getResult(), authReqDetail.getCpID(), request, true,
									true);
							shareresp = (String) generateshare[0];
							sb.append(generateshare[1]);
						} else {

							authReqDetail.setPrimMsisdn(mEncDecObj.encrypt(lMsisdn));

							mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

							if (TextUtils.isEmpty(lMsisdn)) {
								lMsisdn = "9900990099";
							}
//							shareresp = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response,
//									aTransID, mImgResp.getResult(), authReqDetail.getCpID(), request, true, true);
							Object[] generateshare = generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn,
									response, aTransID, mImgResp.getResult(), authReqDetail.getCpID(), request, true,
									true);
							shareresp = (String) generateshare[0];
							sb.append(generateshare[1]);
						}

					} else {
						CDRLoggingThread clt17 = new CDRLoggingThread(authReqDetail,
								mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), USER_CANCLED,
								mImgResp.getResult());
						clt17.start();
//					CDRLogging.getCDRWriter().logCDR(authReqDetail,
//							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), USER_CANCLED, mImgResp.getResult());
						sendClientResp(aTransID, aMerTxnID, USER_CANCLED, INVALID_ZERO, INVALID_ZERO);

						if (authReqDetail.isAuthorize()) {
							lDevicefin = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "df");
							lMsisdn = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(mImgResp.getOptxn() + "mn");

							generateshare(lDevicefin, lMsisdn, newTxnID, lRedirectUrl, lOpn, response, aTransID,
									mImgResp.getResult(), authReqDetail.getCpID(), request, false, true);
						} else {

							if (wap) {
								Cookie cookie = new Cookie("authshare", "");
								cookie.setDomain(System.getenv("DOMAIN_NAME"));
								cookie.setPath(request.getContextPath());
								cookie.setMaxAge(0);
								response.addCookie(cookie);
								redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + USER_CANCLED
										+ "&mertxnid=" + aMerTxnID;
							} else {
								redirectUrl = lRedirectUrl + "msisdn="
										+ mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()) + "&txnid=" + "0"
										+ "&status=" + USER_CANCLED + "&eshare=" + "" + "&result="
										+ mImgResp.getResult() + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid="
										+ aTransID + "&opn=" + lOpn;
								// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
								deleteredis(aTransID);
							}
							MDC.clear();
							// response.setHeader("Location", redirectUrl);
							// response.setHeader("Connection", "close");
							// response.sendRedirect(redirectUrl);
						}
					}

				} catch (Exception e) {
					MDC.clear();
					LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID
							+ "] " + "Exception E32: " + e + "\n");
					lt.start();
				}
			} else {

				try {
					boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
							&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

					String redirectUrl;

					String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");

					if (wap) {
						Cookie cookie = new Cookie("authshare", "");
						cookie.setDomain(System.getenv("DOMAIN_NAME"));
						cookie.setPath(request.getContextPath());
						cookie.setMaxAge(0);
						response.addCookie(cookie);
						redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + SESSION_TIME_OUT
								+ "&mertxnid=" + aMerTxnID;
					} else {
						redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt("0", false) + "&txnid=" + "0"
								+ "&status=" + USER_CANCLED + "&eshare=" + "" + "&result=" + "No" + "&mtxnid="
								+ aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
						deleteredis(aTransID);
					}
					MDC.clear();
					// response.setHeader("Location", redirectUrl);
					// response.setHeader("Connection", "close");
					// response.sendRedirect(redirectUrl);
				} catch (Exception e) {
					LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID
							+ "] " + "Exception E33: " + e + "\n");
					lt.start();
				}
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "return resp:" + shareresp
					+ "\n");
//			LoggingThread lt106 = new LoggingThread(" [" + aTransID + "] " + "return resp:" + shareresp);
//			lt106.start();
			// Logging.getLogger().info("return resp:" + shareresp);

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E34: " + e + "\n");
			lt.start();
		} finally {

		}
		return shareresp;
	}

	private Object[] generateshare(String lDevicefin, String lMsisdn, String newTxnID, String lRedirectUrl, String lOpn,
			HttpServletResponse response, String aTransID, String imgRespRes, String aMID, HttpServletRequest request,
			boolean yesclick, boolean loadtest) {
		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];
		String redirectUrl = "";
		SetMerConfig.setMerConfig(aMID);
		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String tlen = "";
			String mlen = "";

			if (aTransID.length() < 10) {
				tlen = "0" + aTransID.length();
			} else {
				tlen = "" + aTransID.length();
			}

//			if (lMsisdn.length() < 10) {
//				mlen = "0" + lMsisdn.length();
//			} else {
//				mlen = "" + lMsisdn.length();
//			}
			String lMsisdnP = mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone());
			mlen = lMsisdnP.length() + "";
			String passkey = genKey();
			String[] passval = passkey.split("-");
			String lDevicefinP = lDevicefin + passval[0];
			mlen = mlen + passval[2];
			String aTransIDP = newTxnID + passval[3];
			tlen = tlen + passval[4];
			int plen = passkey.length();
			long timestamp = System.currentTimeMillis();

//			String encval = lDevicefin + lMsisdn + mlen + aTransID + tlen;
			String encval = timestamp + lDevicefinP + mlen + passkey + aTransIDP + tlen + plen + lMsisdnP + passval[1];

			String mEncDf = mEncDecObj.encrypt(encval, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey4) */);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "generateshare:" + "mEncDf: "
					+ mEncDf + "\n");
//			LoggingThread lt107 = new LoggingThread(" [" + aTransID + "] " + "generateshare:" + "mEncDf: " + mEncDf);
//			lt107.start();
			// Logging.getLogger().info("generateshare:" + "mEncDf: " + mEncDf);

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
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E35: " + e + "\n");
				lt.start();
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Crypto Share 1 : "
					+ EncString1 + ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3 + "\n");
//			LoggingThread lt108 = new LoggingThread(" [" + aTransID + "] " + "Crypto Share 1 : " + EncString1
//					+ ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3);
//			lt108.start();
			// Logging.getLogger().info("Crypto Share 1 : " + EncString1);
			// Logging.getLogger().info("Crypto Share 2 : " + EncString2);
			// Logging.getLogger().info("Crypto Share 3 : " + EncString3);

			AuthShareEntity mEntity = new AuthShareEntity();

			mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()));
			if (WebAuthSign.debug) {
				mEntity.setDevicefin(lDevicefin);
			} else {
				mEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));
			}
			mEntity.setId(aTransID);
			mEntity.setNewtxnid(newTxnID);
//			mEntity.setShare1(EncString1);
			mEntity.setShare2(EncString2);
			mEntity.setShare3(EncString3);
			mEntity.setTxnid(aTransID);
			mEntity.setMertxnid(authReqDetail.getMerTxnID());
			mEntity.setOpn(lOpn);
			mEntity.setMid(aMID);
			mEntity.setAuthed(false);
			mEntity.setRegnum(authReqDetail.getRegnum());
			mEntity.setRegnumMatchFlag(WebAuthSign.regnumMatchFlag);
			mEntity.setPasskey(passkey);
			mEntity.setTimestamp(timestamp);
			mEntity.setStatus(SUCCESS);
			mEntity.setUpdatedAt(new Date());
			mEntity.setOpn(lOpn);
			AuthMobDFEntity mMobEntity = new AuthMobDFEntity();
			if (WebAuthSign.debug) {
				mMobEntity.setMsisdn(lMsisdn + aMID);
				mMobEntity.setDevicefin(lDevicefin);
			} else {
				mMobEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn + aMID));
				mMobEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));
			}
			mMobEntity.setMid(aMID);
			mMobEntity.setChannel(authReqDetail.getChannel());

			TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "write");
			td1.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveDf(mMobEntity);
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String log1 = td1.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Mobile DF writing into DB, "
					+ log1 + "\n");

			// mAuthsharedbrepoImpl.saveauthsharetodb(mEntity);
			TimeDiffLogThread td2 = new TimeDiffLogThread("AuthShareEntity", "write");
			td2.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveShare(mEntity);
			td2.setCurrentTimeMillis2(System.currentTimeMillis());
			String log2 = td2.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Shares writing into DB, "
					+ log2 + "\n");
			authReqDetail.setNewTxnID(newTxnID);

			mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

			AuthWebResp resp = new AuthWebResp();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
					+ "authReqDetail.getSecTxnID() : " + authReqDetail.getSecTxnID() + "\n");
//			LoggingThread lt109 = new LoggingThread(
//					" [" + aTransID + "] " + "authReqDetail.getSecTxnID() : " + authReqDetail.getSecTxnID());
//			lt109.start();
			// Logging.getLogger().info("authReqDetail.getSecTxnID() : " +
			// authReqDetail.getSecTxnID());

			String lMob = lMsisdn;
			if (!TextUtils.isEmpty(authReqDetail.getSecTxnID())) {
				String txnIDD = authReqDetail.getSecTxnID();
				if (mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnIDD + "req") != null) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
							+ "sendShare msisdnObj.getMsisdn(): " + lMsisdn
							+ ", sendShare authReqDetail.getPrimMsisdn(): "
							+ mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()) + "\n");
//					LoggingThread lt110 = new LoggingThread(" [" + aTransID + "] " + "sendShare msisdnObj.getMsisdn(): "
//							+ lMsisdn + ", sendShare authReqDetail.getPrimMsisdn(): "
//							+ mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()));
//					lt110.start();
//					Logging.getLogger().info("sendShare msisdnObj.getMsisdn(): " + lMsisdn);
//					Logging.getLogger().info("sendShare authReqDetail.getPrimMsisdn(): "
//							+ mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()));

					if (lMsisdn.length() != 10) {
						lMob = lMob.substring(2, lMob.length());
					}

					if (lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {
						AuthReqDetail authReqDetailresp = mReqTrackTransRespoImpl
								.getValueFromAshiledReqRedisRepo(txnIDD + "req");

						authReqDetailresp.setYesclick(yesclick);

						PriSecDFEntity mPriEntity = new PriSecDFEntity();

						String primdn = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

						if (primdn.length() != 10) {
							primdn = primdn.substring(2, primdn.length());
						}

						mPriEntity.setPmdn(mEncDecObj.encrypt(primdn));
						mPriEntity.setSmdn(mEncDecObj.decrypt(authReqDetail.getSecMsisdn()));
						mPriEntity.setMid(aMID);
						mPriEntity.setDevicefin(mEncDecObj.encrypt(authReqDetail.getDf()));
						TimeDiffLogThread td3 = new TimeDiffLogThread("PriSecDFEntity", "write");
						td3.setCurrentTimeMillis(System.currentTimeMillis());
						mAuthDbService.savePriSecDF(mPriEntity);
						td3.setCurrentTimeMillis2(System.currentTimeMillis());
						String log = td3.start();
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + log + "\n");
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
								+ "authReqDetail.getSecTxnID() dave resp : " + txnIDD + "\n");
//						LoggingThread lt111 = new LoggingThread(
//								" [" + aTransID + "] " + "authReqDetail.getSecTxnID() dave resp : " + txnIDD);
//						lt111.start();
						// Logging.getLogger().info("authReqDetail.getSecTxnID() dave resp : " +
						// txnIDD);
						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnIDD + "aurires", authReqDetailresp);
					}
					// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(txnIDD + "req");
				}
			} else if (authReqDetail.isMulitdevice()) {
				PriSecDFEntity mPriEntity = new PriSecDFEntity();

				String primdn = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

				if (primdn.length() != 10) {
					primdn = primdn.substring(2, primdn.length());
				}

				mPriEntity.setPmdn(mEncDecObj.encrypt(primdn));
				mPriEntity.setSmdn(mEncDecObj.decrypt(authReqDetail.getSecMsisdn()));
				mPriEntity.setMid(aMID);
				mPriEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));

				TimeDiffLogThread td4 = new TimeDiffLogThread("PriSecDFEntity", "write");
				td4.setCurrentTimeMillis(System.currentTimeMillis());
				mAuthDbService.savePriSecDF(mPriEntity);
				td4.setCurrentTimeMillis2(System.currentTimeMillis());
				String log = td4.start();
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + log + "\n");
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "wap : " + wap + "\n");
//			LoggingThread lt112 = new LoggingThread(" [" + aTransID + "] " + "wap : " + wap);
//			lt112.start();
			// Logging.getLogger().info("wap : " + wap);

			if (wap) {
				String shareval = newTxnID.length() + newTxnID + EncString1;
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "**shareval--> "
						+ shareval + "\n");
//				LoggingThread lt113 = new LoggingThread(" [" + aTransID + "] " + "**shareval--> " + shareval);
//				lt113.start();
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

				String reqTime = CommonHelper.getFormattedDateString();

				String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
				redisMessagePublisher.publish(message);

				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", aTransID);

				mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

				if (!TextUtils.isEmpty(authReqDetail.getSecTxnID())
						&& !lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {
					redirectUrl = mMobmismatUrl;
				} else {
					redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS + "&mertxnid="
							+ authReqDetail.getMerTxnID();
					String clientResp = sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn,
							authReqDetail.getSecMsisdn());
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + clientResp + "\n");
				}

			} else {

				if (!TextUtils.isEmpty(authReqDetail.getSecTxnID())
						&& !lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {

					String displayImgUrl = mMobmismatUrl + "?mTxnID=" + newTxnID + "&mID=" + authReqDetail.getCpID();
					CDRLoggingThread clt18 = new CDRLoggingThread(authReqDetail,
							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);
					clt18.start();
//					CDRLogging.getCDRWriter().logCDR(authReqDetail,
//							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);

					redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone())
							+ "&txnid=" + newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result="
							+ imgRespRes + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn="
							+ lOpn + "&secmsisdn="
							+ mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone()) + "&dispimg="
							+ displayImgUrl;

				} else {
					CDRLoggingThread clt19 = new CDRLoggingThread(authReqDetail,
							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);
					clt19.start();
//					CDRLogging.getCDRWriter().logCDR(authReqDetail,
//							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);

					redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone())
							+ "&txnid=" + newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result="
							+ imgRespRes + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn="
							+ lOpn + "&secmsisdn="
							+ mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone());
					// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
					String clientResp = sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn,
							authReqDetail.getSecMsisdn());
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + clientResp + "\n");
				}
			}

			// saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "respurl", redirectUrl);

			if (authReqDetail.isDemography() /* && !wap */ && TextUtils.isEmpty(authReqDetail.getSecTxnID())
					&& (lOpn != null && (lOpn.contains("voda") || lOpn.contains("idea") || lOpn.contains("VODA")
							|| lOpn.contains("IDEA")))) {
				String log = processDemography(aTransID, request, response);
				sb.append(log);
			} else if (authReqDetail.isDemography() /* && !wap */ && TextUtils.isEmpty(authReqDetail.getSecTxnID())) {

				String locresp = processAirLocation(aTransID, request, response);

				if (locresp.contentEquals("CONSENT_PENDING")) {
					String reqTime = CommonHelper.getFormattedDateString();
					String message = "ZOMASHIELD" + aTransID + "#" + reqTime;
					redisMessagePublisher.publish(message);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "locret", String.valueOf(1));
				} else {
					if (locresp.contains("SUCCESS")) {
						DemoGraphyResp demresp = new DemoGraphyResp();
						demresp.setLocation(locresp);

						String strresp = gson.toJson(demresp);
						sendDiResp(aTransID, authReqDetail.getMerTxnID(), strresp);

					} else {
						ErrorLoggingThread elt = new ErrorLoggingThread(
								" [" + aTransID + "] " + "Location Request failed :" + aTransID);
						elt.start();
						// ErrorLogging.getLogger().info("Location Request failed :" + aTransID);
					}

				}

				// response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				// response.setHeader("Location", redirectUrl);
				// response.setHeader("Connection", "close");
				// response.sendRedirect(redirectUrl);
			} else {
				if (!wap) {
					deleteredis(aTransID);
				}
				MDC.clear();
				// response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				// response.setHeader("Location", redirectUrl);
				// response.setHeader("Connection", "close");
				// response.sendRedirect(redirectUrl);
			}

		} catch (Exception e) {
			MDC.clear();
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E36: " + e + "\n");
			lt.start();
		}
		sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "return resp:" + redirectUrl
				+ "\n");
//		LoggingThread lt114 = new LoggingThread(" [" + aTransID + "] " + "return resp:" + redirectUrl);
//		lt114.start();
		// Logging.getLogger().info("return resp:" + redirectUrl);
		list[0] = redirectUrl;
		list[1] = sb.toString();
		return list;
	}

	private String generateshare(String lDevicefin, String lMsisdn, String newTxnID, String lRedirectUrl, String lOpn,
			HttpServletResponse response, String aTransID, String imgRespRes, String aMID, HttpServletRequest request,
			boolean yesclick) {

		StringBuilder sb = new StringBuilder();
		SetMerConfig.setMerConfig(aMID);

		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String tlen = "";
			String mlen = "";

			if (aTransID.length() < 10) {
				tlen = "0" + aTransID.length();
			} else {
				tlen = "" + aTransID.length();
			}

//			if (lMsisdn.length() < 10) {
//				mlen = "0" + lMsisdn.length();
//			} else {
//				mlen = "" + lMsisdn.length();
//			}
			String lMsisdnP = mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone());
			mlen = lMsisdnP.length() + "";
			String passkey = genKey();
			String[] passval = passkey.split("-");
			String lDevicefinP = lDevicefin + passval[0];
			mlen = mlen + passval[2];
			String aTransIDP = newTxnID + passval[3];
			tlen = tlen + passval[4];
			int plen = passkey.length();
			long timestamp = System.currentTimeMillis();

//			String encval = lDevicefin + lMsisdn + mlen + aTransID + tlen;
			String encval = timestamp + lDevicefinP + mlen + passkey + aTransIDP + tlen + plen + lMsisdnP + passval[1];

			String mEncDf = mEncDecObj.encrypt(encval, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey4) */);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "generateshare:" + "mEncDf: "
					+ mEncDf + "\n");
//			LoggingThread lt115 = new LoggingThread(" [" + aTransID + "] " + "generateshare:" + "mEncDf: " + mEncDf);
//			lt115.start();
			// Logging.getLogger().info("generateshare:" + "mEncDf: " + mEncDf);

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
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E36: " + e + "\n");
				lt.start();
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Crypto Share 1 : "
					+ EncString1 + ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3 + "\n");
//			LoggingThread lt116 = new LoggingThread(" [" + aTransID + "] " + "Crypto Share 1 : " + EncString1
//					+ ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3);
//			lt116.start();
			// Logging.getLogger().info("Crypto Share 1 : " + EncString1);
			// Logging.getLogger().info("Crypto Share 2 : " + EncString2);
			// Logging.getLogger().info("Crypto Share 3 : " + EncString3);

			AuthShareEntity mEntity = new AuthShareEntity();

			mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()));
			if (WebAuthSign.debug) {
				mEntity.setDevicefin(lDevicefin);
			} else {
				mEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));
			}
			mEntity.setId(aTransID);
			mEntity.setNewtxnid(newTxnID);
//			mEntity.setShare1(EncString1);
			mEntity.setShare2(EncString2);
			mEntity.setShare3(EncString3);
			mEntity.setTxnid(aTransID);
			mEntity.setMertxnid(authReqDetail.getMerTxnID());
			mEntity.setOpn(lOpn);
			mEntity.setMid(aMID);
			mEntity.setAuthed(false);
			mEntity.setRegnum(authReqDetail.getRegnum());
			mEntity.setRegnumMatchFlag(WebAuthSign.regnumMatchFlag);
			mEntity.setPasskey(passkey);
			mEntity.setTimestamp(timestamp);
			mEntity.setOpn(lOpn);
			AuthMobDFEntity mMobEntity = new AuthMobDFEntity();
			if (WebAuthSign.debug) {
				mMobEntity.setMsisdn(lMsisdn + aMID);
				mMobEntity.setDevicefin(lDevicefin);
			} else {
				mMobEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn + aMID));
				mMobEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));
			}
			mMobEntity.setMid(aMID);
			mMobEntity.setChannel(authReqDetail.getChannel());
			TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "write");
			td1.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveDf(mMobEntity);
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String log = td1.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Mobile DF writing into DB, "
					+ log + "\n");
			// mAuthsharedbrepoImpl.saveauthsharetodb(mEntity);
			TimeDiffLogThread td2 = new TimeDiffLogThread("AuthShareEntity", "write");
			td2.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveShare(mEntity);
			td2.setCurrentTimeMillis2(System.currentTimeMillis());
			String log2 = td2.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Shares writing into DB, "
					+ log2 + "\n");
			authReqDetail.setNewTxnID(newTxnID);

			mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(aTransID + "req", authReqDetail);

			String redirectUrl = "";

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

			AuthWebResp resp = new AuthWebResp();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
					+ "authReqDetail.getSecTxnID() : " + authReqDetail.getSecTxnID() + "\n");
//			LoggingThread lt117 = new LoggingThread(
//					" [" + aTransID + "] " + "authReqDetail.getSecTxnID() : " + authReqDetail.getSecTxnID());
//			lt117.start();
			// Logging.getLogger().info("authReqDetail.getSecTxnID() : " +
			// authReqDetail.getSecTxnID());

			String lMob = lMsisdn;
			if (!TextUtils.isEmpty(authReqDetail.getSecTxnID())) {
				String txnIDD = authReqDetail.getSecTxnID();
				if (mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnIDD + "req") != null) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
							+ "sendShare msisdnObj.getMsisdn(): " + lMsisdn
							+ ", sendShare authReqDetail.getPrimMsisdn(): "
							+ mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()) + "\n");
//					LoggingThread lt118 = new LoggingThread(" [" + aTransID + "] " + "sendShare msisdnObj.getMsisdn(): "
//							+ lMsisdn + ", sendShare authReqDetail.getPrimMsisdn(): "
//							+ mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()));
//					lt118.start();
//					Logging.getLogger().info("sendShare msisdnObj.getMsisdn(): " + lMsisdn);
//					Logging.getLogger().info("sendShare authReqDetail.getPrimMsisdn(): "
//							+ mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()));

					if (lMsisdn.length() != 10) {
						lMob = lMob.substring(2, lMob.length());
					}

					if (lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {
						AuthReqDetail authReqDetailresp = mReqTrackTransRespoImpl
								.getValueFromAshiledReqRedisRepo(txnIDD + "req");

						authReqDetailresp.setYesclick(yesclick);

						PriSecDFEntity mPriEntity = new PriSecDFEntity();

						String primdn = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

						if (primdn.length() != 10) {
							primdn = primdn.substring(2, primdn.length());
						}

						mPriEntity.setPmdn(mEncDecObj.encrypt(primdn));
						mPriEntity.setSmdn(mEncDecObj.decrypt(authReqDetail.getSecMsisdn()));
						mPriEntity.setMid(aMID);
						mPriEntity.setDevicefin(mEncDecObj.encrypt(authReqDetail.getDf()));

						TimeDiffLogThread td3 = new TimeDiffLogThread("PriSecDFEntity", "write");
						td3.setCurrentTimeMillis(System.currentTimeMillis());
						mAuthDbService.savePriSecDF(mPriEntity);
						td3.setCurrentTimeMillis2(System.currentTimeMillis());
						String log3 = td3.start();
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + log3 + "\n");
						sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
								+ "authReqDetail.getSecTxnID() dave resp : " + txnIDD + "\n");
//						LoggingThread lt119 = new LoggingThread(
//								" [" + aTransID + "] " + "authReqDetail.getSecTxnID() dave resp : " + txnIDD);
//						lt119.start();
						// Logging.getLogger().info("authReqDetail.getSecTxnID() dave resp : " +
						// txnIDD);
						mReqTrackTransRespoImpl.saveToAshiledReqRedisRepo(txnIDD + "aurires", authReqDetailresp);
					}
					// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(txnIDD + "req");
				}
			} else if (authReqDetail.isMulitdevice()) {
				PriSecDFEntity mPriEntity = new PriSecDFEntity();

				String primdn = mEncDecObj.decrypt(authReqDetail.getPrimMsisdn());

				if (primdn.length() != 10) {
					primdn = primdn.substring(2, primdn.length());
				}

				mPriEntity.setPmdn(mEncDecObj.encrypt(primdn));
				mPriEntity.setSmdn(mEncDecObj.decrypt(authReqDetail.getSecMsisdn()));
				mPriEntity.setMid(aMID);
				mPriEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));

				TimeDiffLogThread td3 = new TimeDiffLogThread("PriSecDFEntity", "write");
				td3.setCurrentTimeMillis(System.currentTimeMillis());
				mAuthDbService.savePriSecDF(mPriEntity);
				td3.setCurrentTimeMillis2(System.currentTimeMillis());
				td3.setTxnID(aTransID);
				String log4 = td3.start();
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + log4 + "\n");
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "wap : " + wap + "\n");
//			LoggingThread lt120 = new LoggingThread(" [" + aTransID + "] " + "wap : " + wap);
//			lt120.start();
			// Logging.getLogger().info("wap : " + wap);

			if (wap) {
				String shareval = newTxnID.length() + newTxnID + EncString1;
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "**shareval--> "
						+ shareval + "\n");
//				LoggingThread lt121 = new LoggingThread(" [" + aTransID + "] " + "**shareval--> " + shareval);
//				lt121.start();
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

				String reqTime = CommonHelper.getFormattedDateString();

				String message = "WEBASHIELD" + newTxnID + "#" + reqTime;
				redisMessagePublisher.publish(message);

				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(newTxnID + "new", aTransID);

				mTokenRespRepoImpl.saveToAshiledReqRedisRepo(newTxnID + "resp", resp);

				if (!TextUtils.isEmpty(authReqDetail.getSecTxnID())
						&& !lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {
					redirectUrl = mMobmismatUrl;
				} else {
					redirectUrl = lRedirectUrl + "token=" + newTxnID + "&status=" + SUCCESS + "&mertxnid="
							+ authReqDetail.getMerTxnID();
					String clientResp = sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn,
							authReqDetail.getSecMsisdn());
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + clientResp + "\n");
				}

			} else {

				if (!TextUtils.isEmpty(authReqDetail.getSecTxnID())
						&& !lMob.contentEquals(mEncDecObj.decrypt(authReqDetail.getPrimMsisdn()))) {

					String displayImgUrl = mMobmismatUrl + "?mTxnID=" + newTxnID + "&mID=" + authReqDetail.getCpID();
					CDRLoggingThread clt20 = new CDRLoggingThread(authReqDetail,
							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);
					clt20.start();
//					CDRLogging.getCDRWriter().logCDR(authReqDetail,
//							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);

					redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone())
							+ "&txnid=" + newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result="
							+ imgRespRes + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn="
							+ lOpn + "&secmsisdn="
							+ mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone()) + "&dispimg="
							+ displayImgUrl;

				} else {
					CDRLoggingThread clt21 = new CDRLoggingThread(authReqDetail,
							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);
					clt21.start();
//					CDRLogging.getCDRWriter().logCDR(authReqDetail,
//							mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, imgRespRes);

					redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone())
							+ "&txnid=" + newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result="
							+ imgRespRes + "&mtxnid=" + authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn="
							+ lOpn + "&secmsisdn="
							+ mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone());
					// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
					String clientResp = sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn,
							authReqDetail.getSecMsisdn());
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + clientResp + "\n");
				}
			}

			// saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

			mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "respurl", redirectUrl);

			if (authReqDetail.isDemography() /* && !wap */ && TextUtils.isEmpty(authReqDetail.getSecTxnID())
					&& (lOpn != null && (lOpn.contains("voda") || lOpn.contains("idea") || lOpn.contains("VODA")
							|| lOpn.contains("IDEA")))) {
				String log3 = processDemography(aTransID, request, response);
				sb.append(log3);
			} else if (authReqDetail.isDemography() /* && !wap */ && TextUtils.isEmpty(authReqDetail.getSecTxnID())) {

				String locresp = processAirLocation(aTransID, request, response);

				if (locresp.contentEquals("CONSENT_PENDING")) {
					String reqTime = CommonHelper.getFormattedDateString();
					String message = "ZOMASHIELD" + aTransID + "#" + reqTime;
					redisMessagePublisher.publish(message);
					mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "locret", String.valueOf(1));
				} else {
					if (locresp.contains("SUCCESS")) {
						DemoGraphyResp demresp = new DemoGraphyResp();
						demresp.setLocation(locresp);

						String strresp = gson.toJson(demresp);
						sendDiResp(aTransID, authReqDetail.getMerTxnID(), strresp);

					} else {
						ErrorLoggingThread elt = new ErrorLoggingThread(
								" [" + aTransID + "] " + "Location Request failed :" + aTransID);
						elt.start();
						// ErrorLogging.getLogger().info("Location Request failed :" + aTransID);
					}

				}

				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", redirectUrl);
				response.setHeader("Connection", "close");
				response.sendRedirect(redirectUrl);
			} else {
				if (!wap) {
					deleteredis(aTransID);
				}
				MDC.clear();
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", redirectUrl);
				response.setHeader("Connection", "close");
				response.sendRedirect(redirectUrl);
			}

		} catch (Exception e) {
			MDC.clear();
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E38: " + e + "\n");
			lt.start();
		}
		return sb.toString();
	}

	private String displayinOtppage(String aTransID, HttpServletRequest request, HttpServletResponse response,
			String aMerTxnID) {
		SecureImageResponse authRespdetail = new SecureImageResponse();
		StringBuilder sb = new StringBuilder();
		try {
			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");

			String redirectUrl = "";

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

			if (authReqDetail != null) {

//				authRespdetail = sendImageReq(aTransID, "null", authReqDetail.getCpID(), request, response,
//						authReqDetail.getSeckey(), false, null);
				Object[] list = sendImageReq(aTransID, "null", authReqDetail.getCpID(), request, response,
						authReqDetail.getSeckey(), false, null);
				authRespdetail = (SecureImageResponse) list[0];
				sb.append(list[1] + "\n");
				if (authRespdetail != null && authRespdetail.getStatusCode() != null
						&& authRespdetail.getStatusCode().contains("201")) {

					String img1 = authRespdetail.getImage1();
					String img2 = authRespdetail.getImage2();
					String txt = authRespdetail.getPtext();
					String txnID = authRespdetail.getOptxn();
					String pshare = authRespdetail.getPimage();

					WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(aTransID + "web");

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
					request.setAttribute("clickcnt", 4);
					request.setAttribute("imgstr", webparam.getImgstr());
					request.setAttribute("t", mSessionTimeout);
					request.setAttribute("domain", System.getenv("DOMAIN_NAME"));

					try {
						rd.forward(request, response);
					} catch (ServletException | IOException e) {
						Logging.getLogger().info("Exception--" + e.getMessage());
					}

					LoggingThread lt122 = new LoggingThread(" [" + aTransID + "] " + "displayImage over : ");
					lt122.start();
					// Logging.getLogger().info("displayImage over : ");
				} else {
					LoggingThread lt123 = new LoggingThread(" [" + aTransID + "] " + "displayImage fail : ");
					lt123.start();
					// Logging.getLogger().info("displayImage fail : ");
					CDRLoggingThread clt22 = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
					clt22.start();
					// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
					sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
							INVALID_ZERO);
					if (wap) {
						redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + SERVER_ERROR + "&mertxnid="
								+ aMerTxnID;
					} else {
						redirectUrl = "0" + "msisdn=" + mEncDecObj.encrypt("0", authReqDetail.isIPhone()) + "&txnid="
								+ aTransID + "&status=" + SERVER_ERROR + "&eshare=" + "" + "&result=" + "" + "&mtxnid="
								+ aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
					}
					MDC.clear();
					deleteredis(aTransID);
					response.sendRedirect(redirectUrl);
					return sb.toString();
				}
			} else {
				LoggingThread lt124 = new LoggingThread(" [" + aTransID + "] " + "displayImage fail : ");
				lt124.start();
				// Logging.getLogger().info("displayImage fail : ");
				CDRLoggingThread clt23 = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
				clt23.start();
				// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
				sendClientResp(authReqDetail.getCpTxnID(), authReqDetail.getMerTxnID(), SERVER_ERROR, INVALID_ZERO,
						INVALID_ZERO);
				if (wap) {
					redirectUrl = lRedirectUrl + "token=" + INVALID_TOKEN + "&status=" + SERVER_ERROR + "&mertxnid="
							+ aMerTxnID;
				} else {
					redirectUrl = "0" + "msisdn=" + mEncDecObj.encrypt("0", authReqDetail.isIPhone()) + "&txnid="
							+ aTransID + "&status=" + SERVER_ERROR + "&eshare=" + "" + "&result=" + "" + "&mtxnid="
							+ aMerTxnID + "&atxnid=" + aTransID + "&opn=" + "0";
				}
				MDC.clear();
				deleteredis(aTransID);
				response.sendRedirect(redirectUrl);
				return sb.toString();
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E39: " + e + "\n");
			lt.start();
		}
		return sb.toString();

	}

	private String processDemography(String txnID, HttpServletRequest request, HttpServletResponse response) {

		StringBuilder sb = new StringBuilder();

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		String resp = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "respurl");

		if (authReqDetail != null) {

			try {

				String lAuthStr = mEncDecObj.decrypt(mZomClientDGID, authReqDetail.isIPhone()) + ""
						+ mEncDecObj.decrypt(mZomClientDGSec, authReqDetail.isIPhone());

				String lInitOtpResp = "";
				// String lAuthStr = mZomClientID + mZomClientSec;

				String lMsisdn = mMCTrackTransRespoImpl
						.getValueFromAshiledAuthTranRepo(authReqDetail.getCpTxnID() + "mn");
				CloseableHttpClient client = HttpClients.createDefault();
				StringBuilder lDiscoveryRespStr = new StringBuilder();

				LoggingThread lt125 = new LoggingThread(
						" [" + txnID + "] " + "mDGiOtpUrl : " + mDGiOtpUrl + " lAuthStr : " + lAuthStr);
				lt125.start();
				// Logging.getLogger().info("mDGiOtpUrl : " + mDGiOtpUrl + " lAuthStr : " +
				// lAuthStr);

				JSONObject initotp = new JSONObject();
				JSONObject mobotp = new JSONObject();
				mobotp.put("mdn", lMsisdn);
				mobotp.put("clientName", mZoClientName);
				mobotp.put("otpMethod", "sms");

				initotp.put("mobilePossession", mobotp);

				HttpPost httpPost = new HttpPost(mDGiOtpUrl);

				LoggingThread lt126 = new LoggingThread(
						" [" + txnID + "] " + "initotp otp req : " + initotp.toString());
				lt126.start();
				// Logging.getLogger().info("initotp otp req : " + initotp.toString());

				StringEntity entity = new StringEntity(initotp.toString());
				httpPost.setEntity(entity);
				httpPost.setHeader("Authorization", "Basic " + lAuthStr);
				httpPost.setHeader("Content-Type", "application/json");
				httpPost.setHeader("Accept", "application/json");
				httpPost.setHeader("clientId", mZomClientDGIDen);
				httpPost.setHeader("Cache-Control", "no-cache");

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
					System.out.println(imgresponse);
				}
				lInitOtpResp = lDiscoveryRespStr.toString();
				LoggingThread lt127 = new LoggingThread(" [" + txnID + "] " + "lInitOtpResp : " + lInitOtpResp
						+ ", lInitOtpResp Resp length " + lInitOtpResp.length());
				lt127.start();
				// Logging.getLogger().info("lInitOtpResp : " + lInitOtpResp);
				// Logging.getLogger().info("lInitOtpResp Resp length " +
				// lInitOtpResp.length());

				if (lInitOtpResp.length() > 0 && lInitOtpResp.contains("mobilePossession")) {
					JSONObject lOtprespJson = new JSONObject(lInitOtpResp);

					JSONObject mobJson = lOtprespJson.getJSONObject("mobilePossession");

					String status = mobJson.getString("status");
					String sessionKey = mobJson.getString("sessionKey");
					String dateTime = lOtprespJson.getString("dateTime");

					if (status.contentEquals("OTP_SENT")) {
						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(txnID + "seskey", sessionKey);
						String dispdemourl = mDispDemoUrl + "?transID=" + txnID;
						response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
						response.setHeader("Location", dispdemourl);
						response.setHeader("Connection", "close");
						response.sendRedirect(dispdemourl);
					} else {
						deleteredis(txnID);
						response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
						response.setHeader("Location", resp);
						response.setHeader("Connection", "close");
						response.sendRedirect(resp);
					}
				} else {
					deleteredis(txnID);
					response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
					response.setHeader("Location", resp);
					response.setHeader("Connection", "close");
					response.sendRedirect(resp);
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(
						new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E40: " + e + "\n");
				lt.start();
				deleteredis(txnID);
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", resp);
				response.setHeader("Connection", "close");
				try {
					response.sendRedirect(resp);
				} catch (IOException e1) {
					LoggingThread lt2 = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + txnID
							+ "] " + "Exception E41: " + e + "\n");
					lt2.start();
				}
			}
		}
		return sb.toString();
	}

	@RequestMapping(value = "/dispdemog")
	public @ResponseBody void displayDemography(@RequestParam(value = "transID", required = true) String txnID,
			HttpServletRequest request, HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("dispdemog");
		td.setCurrentTimeMillis(System.currentTimeMillis());

		SecureImageResponse authRespdetail = new SecureImageResponse();
		StringBuilder sb = new StringBuilder();

		try {
			String respUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(txnID + "respurl");

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

//			authRespdetail = sendImageReq(txnID, "null", authReqDetail.getCpID(), request, response,
//					authReqDetail.getSeckey(), false, null);
			Object[] list = sendImageReq(txnID, "null", authReqDetail.getCpID(), request, response,
					authReqDetail.getSeckey(), false, null);
			authRespdetail = (SecureImageResponse) list[0];
			sb.append(list[1] + "\n");
			if (authRespdetail != null && authRespdetail.getStatusCode() != null
					&& authRespdetail.getStatusCode().contains("201")) {

				WebDesignParam webparam = mWebDesignParamRepoImpl.getValueFromWebDesignparamRepo(txnID + "web");

				RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/demootp.jsp");

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
				request.setAttribute("desc1", "Enter OTP Number");
				request.setAttribute("desc2", " ");
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

				LoggingThread lt128 = new LoggingThread(" [" + txnID + "] " + "displayImage over : ");
				lt128.start();
				// Logging.getLogger().info("displayImage over : ");
			} else {
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", respUrl);
				response.setHeader("Connection", "close");
				response.sendRedirect(respUrl);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E42: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(txnID);
			td.start();
		}
	}

	private String getshares(String encval) {

		StringBuilder imageStr = new StringBuilder();

		try {

			JSONObject json = new JSONObject();
			json.put("appID", mShareAppID);
			json.putOnce("data", encval);

			JSONObject finaljson = new JSONObject();

			finaljson.putOnce("Split", json);

			HttpPost httpPost = new HttpPost(mShareUrl + "Split");
			StringEntity params = new StringEntity(finaljson.toString());

			httpPost.setEntity(params);
			RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
					.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
			httpPost.setConfig(conf);
			CloseableHttpClient client = HttpClients.createDefault();
			CloseableHttpResponse imgresponse = client.execute(httpPost);

			LoggingThread lt129 = new LoggingThread("Status : " + imgresponse.getStatusLine().getStatusCode());
			lt129.start();
			// Logging.getLogger().info("Status : " +
			// imgresponse.getStatusLine().getStatusCode());

			if (imgresponse.getStatusLine().getStatusCode() == 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(imgresponse.getEntity().getContent()));
				String readLine;
				while (((readLine = br.readLine()) != null)) {
					imageStr.append(readLine);
				}
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + "Exception E43: " + e + "\n");
			lt.start();
		}

		return imageStr.toString();
	}

	public Object[] sendImageReq(String aTransID, String aMsisdn, String aMid, HttpServletRequest aRequest,
			HttpServletResponse response, String operatorSecretKey, boolean otpimg, String otp) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];

		SecureImageResponse lImageRs = new SecureImageResponse();
		try {
			sb.append(" [" + aTransID + "] " + "getsecure-img:" + "txnID: " + aTransID + ",msisdn:"
					+ mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid + "\n");
//			LoggingThread lt130 = new LoggingThread(" [" + aTransID + "] " + "getsecure-img:" + "txnID: " + aTransID
//					+ ",msisdn:" + mEncDecObj.encrypt(aMsisdn) + "aMid" + aMid);
//			lt130.start();
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
				params.add(new BasicNameValuePair("qaDev", "true"));
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
					LoggingErrorThread let = new LoggingErrorThread(" [" + aTransID + "] " + imgresponse.toString());
					let.start();
					// Logging.getLogger().error(imgresponse.toString());
					System.out.println(imgresponse);
				}
				lImageRs = new Gson().fromJson(imageStr.toString(), SecureImageResponse.class);
				// lImageRs.setOptxn(aTransID);
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E44: " + e + "\n");
			lt.start();
			ErrorLoggingThread elt = new ErrorLoggingThread(" [" + aTransID + "] " + "Get Img error " + e.getMessage());
			elt.start();// ErrorLogging.getLogger().info("Get Img error " + e.getMessage());
		}
		list[0] = lImageRs;
		list[1] = sb;
		return list;
	}

	private Object[] sendShare(String aTransID, HttpServletRequest request, HttpServletResponse response) {

		StringBuilder sb = new StringBuilder();
		Object[] list = new Object[2];

		String lDevicefin = "";
		String lMsisdn = "0";
		String redirectUrl = "";

		try {
			String newTxnID = getTransID();

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String lOpn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn");

			lDevicefin = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "df");
			lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");

			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "sendShare:" + "lDevicefin: "
					+ mEncDecObj.encrypt(lDevicefin) + "\n");
//			LoggingThread lt131 = new LoggingThread(
//					" [" + aTransID + "] " + "sendShare:" + "lDevicefin: " + mEncDecObj.encrypt(lDevicefin));
//			lt131.start();
			// Logging.getLogger().info("sendShare:" + "lDevicefin: " +
			// mEncDecObj.encrypt(lDevicefin));

			String tlen = "";
			String mlen = "";

			if (newTxnID.length() < 10) {
				tlen = "0" + newTxnID.length();
			} else {
				tlen = "" + newTxnID.length();
			}

//			if (lMsisdn.length() < 10) {
//				mlen = "0" + lMsisdn.length();
//			} else {
//				mlen = "" + lMsisdn.length();
//			}
			String lMsisdnP = mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone());
			mlen = lMsisdnP.length() + "";
			String passkey = genKey();
			String[] passval = passkey.split("-");
			String lDevicefinP = lDevicefin + passval[0];
			mlen = mlen + passval[2];
			String aTransIDP = newTxnID + passval[3];
			tlen = tlen + passval[4];
			int plen = passkey.length();
			long timestamp = System.currentTimeMillis();

			// String encval = lDevicefin + lMsisdn + mlen + aTransID + tlen;
			String encval = timestamp + lDevicefinP + mlen + passkey + aTransIDP + tlen + plen + lMsisdnP + passval[1];

//			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "encval:" + encval + "\n");
//			LoggingThread lt132 = new LoggingThread(" [" + aTransID + "] " + "encval:" + encval);
//			lt132.start();
			// Logging.getLogger().info("encval:" + encval);
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "sendShare:" + "encval: "
					+ encval + "\n");
			String mEncDf = mEncDecObj.encrypt(encval, authReqDetail.isIPhone() /* , mEncDecObj.decrypt(mEncKey4) */);

//			LoggingThread lt133 = new LoggingThread(" [" + aTransID + "] " + "sendShare:" + "mEncDf: " + mEncDf);
//			lt133.start();
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
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E45: " + e + "\n");
				lt.start();
			}
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Crypto Share 1 : "
					+ EncString1 + ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3 + "\n");
//			LoggingThread lt134 = new LoggingThread(" [" + aTransID + "] " + "Crypto Share 1 : " + EncString1
//					+ ", Crypto Share 2 : " + EncString2 + ", Crypto Share 3 : " + EncString3);
//			lt134.start();
			// Logging.getLogger().info("Crypto Share 1 : " + EncString1);
			// Logging.getLogger().info("Crypto Share 2 : " + EncString2);
			// Logging.getLogger().info("Crypto Share 3 : " + EncString3);

//			long startTime_share = System.currentTimeMillis();

			AuthShareEntity mEntity = new AuthShareEntity();

			mEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()));
			if (WebAuthSign.debug) {
				mEntity.setDevicefin(lDevicefin);
			} else {
				mEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));
			}
			mEntity.setId(aTransID);
			mEntity.setNewtxnid(newTxnID);
//			mEntity.setShare1(EncString1);
			mEntity.setShare2(EncString2);
			mEntity.setShare3(EncString3);
			mEntity.setTxnid(aTransID);
			mEntity.setMertxnid(authReqDetail.getMerTxnID());
			mEntity.setOpn(lOpn);
			mEntity.setMid(authReqDetail.getCpID());
			mEntity.setAuthed(false);
			mEntity.setPasskey(passkey);
			mEntity.setTimestamp(timestamp);
			mEntity.setRegnum(authReqDetail.getRegnum());
			mEntity.setRegnumMatchFlag(WebAuthSign.regnumMatchFlag);
			mEntity.setStatus(SUCCESS);
			mEntity.setUpdatedAt(new Date());
			mEntity.setOpn(lOpn);
			// mAuthsharedbrepoImpl.saveauthsharetodb(mEntity);
			TimeDiffLogThread td = new TimeDiffLogThread("AuthShareEntity", "write");
			td.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveShare(mEntity);
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			String shareWrite = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "shares into DB, "
					+ shareWrite + "\n");
			AuthMobDFEntity mMobEntity = new AuthMobDFEntity();
			if (WebAuthSign.debug) {
				mMobEntity.setMsisdn(lMsisdn + authReqDetail.getCpID());
				mMobEntity.setDevicefin(lDevicefin);
			} else {
				mMobEntity.setMsisdn(mEncDecObj.encrypt(lMsisdn + authReqDetail.getCpID()));
				mMobEntity.setDevicefin(mEncDecObj.encrypt(lDevicefin));
			}
			mMobEntity.setMid(authReqDetail.getCpID());
			mMobEntity.setChannel(authReqDetail.getChannel());
			TimeDiffLogThread td1 = new TimeDiffLogThread("AuthMobDFEntity", "write");
			td1.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveDf(mMobEntity);
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			String dfwrite = td1.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "DF write into DB, "
					+ dfwrite + "\n");
			authReqDetail.setNewTxnID(newTxnID);
			boolean isVPNClient = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "vpn") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "vpn").equals("YES");
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "isVPNClient : "
					+ isVPNClient + ", authReqDetail.isVpnflag() :" + authReqDetail.isVpnflag() + "\n");
//			LoggingThread lt135 = new LoggingThread(" [" + aTransID + "] " + "isVPNClient : " + isVPNClient
//					+ ", authReqDetail.isVpnflag() :" + authReqDetail.isVpnflag());
//			lt135.start();
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
					sb.append(
							new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "NO_VPN_DATA" + "\n");
//					LoggingThread lt136 = new LoggingThread(" [" + aTransID + "] " + "NO_VPN_DATA");
//					lt136.start();
					// Logging.getLogger().info("NO_VPN_DATA");
					authReqDetail.setVpnServerReq(NO_VPN_DATA);
				}
			}

			mMCTrackTransRespoImpl.saveAuthTS(aTransID + "ts", "true");

			CDRLoggingThread clt24 = new CDRLoggingThread(authReqDetail,
					mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()), SUCCESS, "YES");
			clt24.start();
//			CDRLogging.getCDRWriter().logCDR(authReqDetail, mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()),
//					SUCCESS, "YES");

			boolean wap = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan") != null
					&& mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "chan").equals("wap");

			if (wap) {
				String shareval = newTxnID.length() + newTxnID + EncString1;
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "**shareval--> "
						+ shareval + "\n");
//				LoggingThread lt137 = new LoggingThread(" [" + aTransID + "] " + "**shareval--> " + shareval);
//				lt137.start();
				// Logging.getLogger().info("**shareval--> " + shareval);
				String encshare = mEncDecObj.encrypt(shareval);

				Cookie cookie = new Cookie("authshare", encshare);
				cookie.setDomain(System.getenv("DOMAIN_NAME"));
				cookie.setPath(request.getContextPath());
				cookie.setMaxAge(60 * 60 * 24 * 30);
				response.addCookie(cookie);
			}

			redirectUrl = lRedirectUrl + "msisdn=" + mEncDecObj.encrypt(lMsisdn, authReqDetail.isIPhone()) + "&txnid="
					+ newTxnID + "&status=" + SUCCESS + "&eshare=" + EncString1 + "&result=" + "YES" + "&mtxnid="
					+ authReqDetail.getMerTxnID() + "&atxnid=" + aTransID + "&opn=" + lOpn + "&secmsisdn="
					+ mEncDecObj.encrypt(authReqDetail.getSecMsisdn(), authReqDetail.isIPhone());

			// saveShareVal(authReqDetail, newTxnID, EncString3, request, response);

			AuthStatus authStatus = new AuthStatus();
			authStatus.setMertxnID(authReqDetail.getMerTxnID());
			authStatus.setStatus(SUCCESS);
			authStatus.setMsisdn(mEncDecObj.encrypt(lMsisdn));
			authStatus.setRegNumber(authReqDetail.getRegnum());
			authStatusRespRepoImpl.saveAuthStatus(authReqDetail.getMerTxnID() + "authStatus", authStatus);

			String userAuthStatus = sendClientResp(aTransID, authReqDetail.getMerTxnID(), SUCCESS, lMsisdn,
					authReqDetail.getSecMsisdn());
			sb.append(userAuthStatus + "\n");
			if (!wap) {
				deleteredis(aTransID);
			}
			MDC.clear();
			list[0] = redirectUrl;
			list[1] = sb.toString();
			return list;
//			return redirectUrl;
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E46: " + e + "\n");
			lt.start();
			list[0] = redirectUrl;
			list[1] = sb.toString();
			return list;
//			return null;
		}
	}

	private String sendClientResp(String txnID, String mertxnID, String resp, String pmdn, String smdn) {

		StringBuilder sb = new StringBuilder();

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		TxnResp mResp = new TxnResp();

		StringBuilder imageStr = new StringBuilder();
		mResp.setStatus(resp != null ? resp : "0");
		mResp.setMertxnid(mertxnID != null ? mertxnID : "null");
		if (!WebAuthSign.debug) {
			try {
				pmdn = mEncDecObj.encrypt(pmdn);
			} catch (Exception e) {
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
						+ "Exception in sendClientResp(): " + e);
			}
		}
		mResp.setPmdn(pmdn != null ? pmdn : "0");
		mResp.setSmdn(smdn != null ? smdn : "0");
		mResp.setAstxnid(txnID != null ? txnID : "0");

//		try {
//			TimeDiffLogThread td1 = new TimeDiffLogThread("PriSecDFEntity");
//			td1.setCurrentTimeMillis(System.currentTimeMillis());
//			List<PriSecDFEntity> mPmdnlist = mAuthDbService.getBypMdn(pmdn);
//			td1.setCurrentTimeMillis2(System.currentTimeMillis());
//			td1.setTxnID(txnID);
//			td1.start();
//
//			LoggingThread lt138 = new LoggingThread(" [" + txnID + "] " + "mPmdnlist count : " + mPmdnlist.size());
//			lt138.start();
//			// Logging.getLogger().info("mPmdnlist count : " + mPmdnlist.size());
//
//		} catch (Exception e) {
//			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] " + "Exception E: " e + "\n"); sb.append(new Timestamp(System.currentTimeMillis()) + " [" + lTxnID + "] "+ "" +e+ "\n")
//		}

		String resps = gson.toJson(mResp);
		try {
			if (authReqDetail != null) {

//				String clientUrl = authReqDetail.getClientURl();
				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
						+ "User Authentication status: " + resps);
//				LoggingThread lt139 = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] "
//						+ "User Authentication response: " + resps + "\n");
//				lt139.start();
//				// Logging.getLogger().info("ClientURl resp: " + resps);
//				boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true"))
//						? true
//						: false;
//
//				if (clientUrl != null && !loadtest) {
//
//					LoggingThread lt140 = new LoggingThread(
//							" [" + txnID + "] " + "ClientURl : " + clientUrl + ", ClientURl resp: " + resps);
//					lt140.start();
//					// Logging.getLogger().info("ClientURl : " + clientUrl);
//					// Logging.getLogger().info("ClientURl resp: " + resps);
//
//					CloseableHttpClient client = HttpClients.createDefault();
//					CloseableHttpResponse imgresponse = null;
//
//					RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
//							.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
//
//					if (authReqDetail.getCpID().contentEquals("024")) {
//
//						StringBuilder UrlBuilder = new StringBuilder();
//
//						UrlBuilder.append(clientUrl);
//						UrlBuilder.append("uniqueCode=");
//						UrlBuilder.append(mertxnID != null ? mertxnID : "null");
//						UrlBuilder.append("&mobileNumber=");
//						UrlBuilder.append(pmdn != null ? pmdn : "0");
//						UrlBuilder.append("&virtualMobileNo=");
//						UrlBuilder.append(txnID != null ? txnID : "0");
//
//						String httpURl = UrlBuilder.toString();
//
//						HttpGet httpget = new HttpGet(httpURl);
//
//						httpget.setConfig(conf);
//
//						imgresponse = client.execute(httpget);
//
//					} else {
//						HttpPost httpPost = new HttpPost(clientUrl);
//
//						StringEntity mEntity = new StringEntity(resps);
//						httpPost.setEntity(mEntity);
//						httpPost.setHeader("Content-Type", "application/json");
//						httpPost.setHeader("Accept", "application/json");
//
//						// List<NameValuePair> params = new ArrayList<>();
//						// params.add(new BasicNameValuePair("resp", resps));
//
//						// httpPost.setEntity(new
//						// UrlEncodedFormEntity(params,StandardCharsets.UTF_8.name()));
//
//						httpPost.setConfig(conf);
//
//						imgresponse = client.execute(httpPost);
//					}
//
//					if (imgresponse.getStatusLine().getStatusCode() == 200) {
//						BufferedReader br = new BufferedReader(
//								new InputStreamReader(imgresponse.getEntity().getContent()));
//						String readLine;
//						while (((readLine = br.readLine()) != null)) {
//							imageStr.append(readLine);
//						}
//					} else {
//						LoggingErrorThread let = new LoggingErrorThread(" [" + txnID + "] " + imgresponse.toString());
//						let.start();
//						// Logging.getLogger().error(imgresponse.toString());
//						System.out.println(imgresponse);
//					}
//					LoggingThread lt141 = new LoggingThread(" [" + txnID + "] " + "sendclientresp : " + resps
//							+ ", sendclientresp : " + imageStr.toString());
//					lt141.start();
//					// Logging.getLogger().info("sendclientresp : " + resps);
//					// Logging.getLogger().info("sendclientresp : " + imageStr.toString());
//				} else {
//					LoggingThread lt142 = new LoggingThread(
//							" [" + txnID + "] " + "sendclientresp : " + "Client Url not set");
//					lt142.start();
//					// Logging.getLogger().info("sendclientresp : " + "Client Url not set");
//				}
//			} else {
//				LoggingThread lt143 = new LoggingThread(
//						" [" + txnID + "] " + "sendclientresp : " + "Client Url not set");
//				lt143.start();
				// Logging.getLogger().info("sendclientresp : " + "Client Url not set");
			}
		} catch (Exception e) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + e + "\n");
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E47: " + e + "\n");
			lt.start();
		}
		return sb.toString();
	}

	private void sendDiResp(String txnID, String mertxnID, String resp) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(txnID + "req");

		StringBuilder imageStr = new StringBuilder();

		try {
			if (authReqDetail != null) {
				if (authReqDetail.getDiUrl() != null) {

					HttpPost httpPost = new HttpPost(authReqDetail.getDiUrl());

					StringEntity mEntity = new StringEntity(resp);
					httpPost.setEntity(mEntity);
					httpPost.setHeader("Content-Type", "application/json");
					httpPost.setHeader("Accept", "application/json");

					RequestConfig conf = RequestConfig.custom().setConnectTimeout(mcHttpTimeout)
							.setConnectionRequestTimeout(mcHttpTimeout).setSocketTimeout(mcHttpTimeout).build();
					httpPost.setConfig(conf);
					CloseableHttpClient client = HttpClients.createDefault();
					CloseableHttpResponse imgresponse = client.execute(httpPost);
					if (imgresponse.getStatusLine().getStatusCode() == 200) {
						BufferedReader br = new BufferedReader(
								new InputStreamReader(imgresponse.getEntity().getContent()));
						String readLine;
						while (((readLine = br.readLine()) != null)) {
							imageStr.append(readLine);
						}
					} else {
						LoggingErrorThread let = new LoggingErrorThread(" [" + txnID + "] " + imgresponse.toString());
						let.start();
						// Logging.getLogger().error(imgresponse.toString());
						System.out.println(imgresponse);
					}
					LoggingThread lt144 = new LoggingThread(
							" [" + txnID + "] " + "sendDIresp : " + imageStr.toString());
					lt144.start();
					// Logging.getLogger().info("sendDIresp : " + imageStr.toString());
				} else {
					LoggingThread lt145 = new LoggingThread(
							" [" + txnID + "] " + "sendDIresp : " + "Demography Url not set");
					lt145.start();
					// Logging.getLogger().info("sendDIresp : " + "Demography Url not set");
				}
			} else {
				LoggingThread lt146 = new LoggingThread(
						" [" + txnID + "] " + "sendDIresp : " + "Demography Url not set");
				lt146.start();
				// Logging.getLogger().info("sendDIresp : " + "Demography Url not set");
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + txnID + "] " + "Exception E48: " + e + "\n");
			lt.start();
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
				ErrorLoggingThread elt = new ErrorLoggingThread(" [" + authReqDetail.getCpTxnID() + "] "
						+ "saveShareVal error : " + imgresponse.getStatusLine().getStatusCode());
				elt.start();
				// ErrorLogging.getLogger().info("saveShareVal error : " +
				// imgresponse.getStatusLine().getStatusCode());
			}
			LoggingThread lt147 = new LoggingThread(
					" [" + authReqDetail.getCpTxnID() + "] " + "saveShareVal : " + imageStr.toString());
			lt147.start();
			// Logging.getLogger().info("saveShareVal : " + imageStr.toString());

		} catch (Exception e) {
			ErrorLoggingThread elt = new ErrorLoggingThread(
					" [" + authReqDetail.getCpTxnID() + "] " + "saveShareVal error : " + e.getMessage());
			elt.start();
			// ErrorLogging.getLogger().info("saveShareVal error : " + e.getMessage());
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
				ErrorLoggingThread elt = new ErrorLoggingThread(
						"getShareVal error : " + imgresponse.getStatusLine().getStatusCode());
				elt.start();
				// ErrorLogging.getLogger().info("getShareVal error : " +
				// imgresponse.getStatusLine().getStatusCode());
			}
			LoggingThread lt148 = new LoggingThread("getShareVal : " + imageStr.toString());
			lt148.start();
			// Logging.getLogger().info("getShareVal : " + imageStr.toString());

		} catch (Exception e) {
			ErrorLoggingThread elt = new ErrorLoggingThread("getShareVal error : " + e.getMessage());
			elt.start();
			// ErrorLogging.getLogger().info("getShareVal error : " + e.getMessage());
		}
		return imageStr.toString();
	}

	@RequestMapping(value = "/sendotp")
	public @ResponseBody void submitOTP(@RequestParam("mdnum") String aesplatform,
			@RequestParam("txnid") String aTransID, @RequestParam("param5") String param5,
			@RequestParam("mertxnid") String merTxnID, HttpServletRequest request, HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("sendotp");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		try {
			String OTP = "";

			ImageValidationResponse mImgResp = null;
			StringBuilder imageStr = new StringBuilder();
			String headerName = null;
			String headerValue = null;

			String respUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "respurl");

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String dataHashed = aTransID + param5;
			String hash = "";
			try {
				hash = CommonHelper.generateSign(authReqDetail.getSeckey(), dataHashed);
			} catch (Exception e1) {
				e1.printStackTrace();
			}

			MDC.put(LOG4J_MDC_TOKEN, merTxnID);

			LoggingThread lt149 = new LoggingThread(" [" + aTransID + "] " + "displayOTP txnID" + aTransID);
			lt149.start();
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
					// - " + OTP);

					LoggingThread lt150 = new LoggingThread(" [" + aTransID + "] "
							+ "*********************AES Encrypted_platform from JS - " + aesplatform
							+ ", *********************AES encrypted value of aesplatform --> salt :" + " " + salt
							+ ", iv : " + iv + ", ciphertext : " + ciphertext
							+ ", *********************AES Decrypted platform from JS - " + OTP);
					lt150.start();
				}

				OTP = decrypted_aesdata != null ? URLDecoder.decode(decrypted_aesdata.split("\\*")[0], "UTF-8")
						: "null";
				String platform = decrypted_aesdata != null
						? URLDecoder.decode(decrypted_aesdata.split("\\*")[1], "UTF-8")
						: "null";
				String scn_Size = decrypted_aesdata != null ? decrypted_aesdata.split("\\*")[2] : "null";
				String nav_bua = decrypted_aesdata != null
						? URLDecoder.decode(decrypted_aesdata.split("\\*")[3], "UTF-8")
						: "null";

				String remoteIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
				String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null
						? request.getHeader("X-FORWARDED-FOR")
						: "null";
				String clientIP = request.getHeader("CLIENT_IP") != null ? request.getHeader("CLIENT_IP") : "null";
				String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
				String acpt = request.getHeader("accept");
				String userAgent = request.getHeader("user-agent");
				String mip = Stream.of(xforwardedIP, remoteIp, clientIP)
						.filter(s -> s != null && !s.isEmpty() && !s.equalsIgnoreCase("null"))
						.collect(Collectors.joining("-"));

				LoggingThread lt151 = new LoggingThread(" [" + aTransID + "] "
						+ "*** sendmdn Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
						+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : " + clientIP
						+ ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);
				lt151.start();
//			Logging.getLogger()
//					.info("*** sendmdn Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
//							+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
//							+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);

				LoggingThread lt152 = new LoggingThread(" [" + aTransID + "] " + "sendmdn lMobileNumber" + OTP);
				lt152.start();
				// Logging.getLogger().info("sendmdn lMobileNumber" + OTP);

				Enumeration<String> headerNames = request.getHeaderNames();
				String headersInfo = "";
				while (headerNames.hasMoreElements()) {
					headerName = headerNames.nextElement();
					Enumeration<String> headers = request.getHeaders(headerName);
					while (headers.hasMoreElements()) {
						headerValue = headers.nextElement();
					}
					headersInfo = headersInfo + " [" + aTransID + "] " + "**HEADER --> " + headerName + " : "
							+ headerValue + "\n";
					// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
				}
				LoggingThread lt153 = new LoggingThread(headersInfo);
				lt153.start();

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

				if (mImgResp != null && mImgResp.getStatusCode().contentEquals("JS201")
						&& mImgResp.getResult().contentEquals("YES")) {
					sendOtpvalidation(OTP, aTransID, request, response);
				} else {
					response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
					response.setHeader("Location", respUrl);
					response.setHeader("Connection", "close");
					response.sendRedirect(respUrl);
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E49: " + e + "\n");
				lt.start();
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", respUrl);
				response.setHeader("Connection", "close");
				try {
					response.sendRedirect(respUrl);
				} catch (IOException e1) {
					LoggingThread lt2 = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID
							+ "] " + "Exception E50: " + e + "\n");
					lt2.start();
				}
			}
			MDC.clear();
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E51: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(aTransID);
			td.start();
		}
	}

	private void sendOtpvalidation(String oTP, String aTransID, HttpServletRequest request,
			HttpServletResponse response) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");
		String respUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "respurl");

		if (authReqDetail != null) {

			try {

				String lAuthStr = mEncDecObj.decrypt(mZomClientDGID, authReqDetail.isIPhone()) + ""
						+ mEncDecObj.decrypt(mZomClientDGSec, authReqDetail.isIPhone());

				String valOtpResp = "";
				// String lAuthStr =mZomClientID + mZomClientSec;

				String seskey = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "seskey");

				CloseableHttpClient client = HttpClients.createDefault();
				StringBuilder lDiscoveryRespStr = new StringBuilder();

				LoggingThread lt154 = new LoggingThread(" [" + aTransID + "] " + "mDGvOtpUrl : " + mDGvOtpUrl);
				lt154.start();
				// Logging.getLogger().info("mDGvOtpUrl : " + mDGvOtpUrl);

				JSONObject subotp = new JSONObject();
				JSONObject valotp = new JSONObject();
				valotp.put("passcode", oTP);
				valotp.put("sessionKey", seskey);

				subotp.put("mobilePossession", valotp);

				HttpPost httpPost = new HttpPost(mDGvOtpUrl);

				LoggingThread lt155 = new LoggingThread(
						" [" + aTransID + "] " + "subotp otp req : " + subotp.toString());
				lt155.start();
				// Logging.getLogger().info("subotp otp req : " + subotp.toString());

				StringEntity entity = new StringEntity(subotp.toString());
				httpPost.setEntity(entity);
				httpPost.setHeader("Authorization", "Basic " + lAuthStr);
				httpPost.setHeader("Content-Type", "application/json");
				httpPost.setHeader("Accept", "application/json");
				httpPost.setHeader("clientId", mZomClientDGIDen);
				httpPost.setHeader("Cache-Control", "no-cache");

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
				valOtpResp = lDiscoveryRespStr.toString();

				LoggingThread lt156 = new LoggingThread(" [" + aTransID + "] " + "lDiscoveryResp : " + valOtpResp
						+ "lDiscoveryResp Resp length " + valOtpResp.length());
				lt156.start();
				// Logging.getLogger().info("lDiscoveryResp : " + valOtpResp);
				// Logging.getLogger().info("lDiscoveryResp Resp length " +
				// valOtpResp.length());

				if (valOtpResp.length() > 0) {
					JSONObject lOtprespJson = new JSONObject(valOtpResp);

					JSONObject mobJson = lOtprespJson.getJSONObject("mobilePossession");

					String status = mobJson.getString("status");
					JSONObject conJson = mobJson.getJSONObject("consent");
					String dateTime = lOtprespJson.getString("dateTime");

					String refID = conJson.getString("refId");

					if (status.contentEquals("SUCCESS")) {
						String locresp = processLocation(aTransID, request, response);
						String ideResp = processIdentity(refID, aTransID, request, response);

						if (TextUtils.isEmpty(ideResp) && TextUtils.isEmpty(locresp)) {
							ErrorLoggingThread elt = new ErrorLoggingThread(
									" [" + aTransID + "] " + "Both Location and Identity failed :" + aTransID);
							elt.start();
							// ErrorLogging.getLogger().info("Both Location and Identity failed :" +
							// aTransID);
						} else {
							DemoGraphyResp demresp = new DemoGraphyResp();
							demresp.setLocation(locresp);
							demresp.setIdentity(ideResp);

							String strresp = gson.toJson(demresp);
							sendDiResp(aTransID, authReqDetail.getMerTxnID(), strresp);
						}

						deleteredis(aTransID);
						response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
						response.setHeader("Location", respUrl);
						response.setHeader("Connection", "close");
						response.sendRedirect(respUrl);
					} else {
						deleteredis(aTransID);
						response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
						response.setHeader("Location", respUrl);
						response.setHeader("Connection", "close");
						response.sendRedirect(respUrl);
					}
				} else {
					deleteredis(aTransID);
					response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
					response.setHeader("Location", respUrl);
					response.setHeader("Connection", "close");
					response.sendRedirect(respUrl);
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E52: " + e + "\n");
				lt.start();
				deleteredis(aTransID);
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
				response.setHeader("Location", respUrl);
				response.setHeader("Connection", "close");
				try {
					response.sendRedirect(respUrl);
				} catch (IOException e1) {
					LoggingThread lt2 = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID
							+ "] " + "Exception E53: " + e + "\n");
					lt2.start();
				}
			}
		}
	}

	private String processIdentity(String refID, String aTransID, HttpServletRequest request,
			HttpServletResponse response) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		String resp = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "respurl");

		String ideResp = "";

		if (authReqDetail != null) {
			try {

				String lAuthStr = mEncDecObj.decrypt(mZomClientDGID, authReqDetail.isIPhone()) + ""
						+ mEncDecObj.decrypt(mZomClientDGSec, authReqDetail.isIPhone());

				String lInitOtpResp = "";
				// String lAuthStr =mZomClientID + mZomClientSec;

				String lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");
				CloseableHttpClient client = HttpClients.createDefault();
				StringBuilder lDiscoveryRespStr = new StringBuilder();

				LoggingThread lt157 = new LoggingThread(" [" + aTransID + "] " + "mDGideUrl : " + mDGideUrl);
				lt157.start();
				// Logging.getLogger().info("mDGideUrl : " + mDGideUrl);

				JSONObject ideReq = new JSONObject();

				ideReq.put("mdn", lMsisdn);

				JSONObject conzoom = new JSONObject();
				JSONObject optZom = new JSONObject();

				conzoom.put("refId", refID);
				ideReq.put("consent", conzoom);

				optZom.put("acctStatusInfo", true);
				optZom.put("acctInfo", true);
				optZom.put("demographicInfo", true);
				optZom.put("revenueInfo", true);
				optZom.put("deviceInfo", true);

				ideReq.put("options", optZom);

				HttpPost httpPost = new HttpPost(mDGideUrl);

				LoggingThread lt158 = new LoggingThread(" [" + aTransID + "] " + "ideReq req : " + ideReq.toString());
				lt158.start();
				// Logging.getLogger().info("ideReq req : " + ideReq.toString());

				StringEntity mEntity = new StringEntity(ideReq.toString());
				httpPost.setEntity(mEntity);
				httpPost.setHeader("Authorization", "Basic " + lAuthStr);
				httpPost.setHeader("Content-Type", "application/json");
				httpPost.setHeader("Accept", "application/json");
				httpPost.setHeader("clientId", mZomClientDGIDen);
				httpPost.setHeader("Cache-Control", "no-cache");

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
				lInitOtpResp = lDiscoveryRespStr.toString();

				LoggingThread lt159 = new LoggingThread(" [" + aTransID + "] " + "Identity resp : " + lInitOtpResp
						+ ", Identity Resp length " + lInitOtpResp.length());
				lt159.start();
				// Logging.getLogger().info("Identity resp : " + lInitOtpResp);
				// Logging.getLogger().info("Identity Resp length " + lInitOtpResp.length());

				if (lInitOtpResp.length() > 0) {
					JSONObject lOtprespJson = new JSONObject(lInitOtpResp);

					String status = lOtprespJson.getString("mdn");

					if (!TextUtils.isEmpty(status)) {
						return lInitOtpResp;
					} else {
						ErrorLoggingThread elt = new ErrorLoggingThread(
								" [" + aTransID + "] " + "Identity Request failed :" + aTransID);
						elt.start();
						// ErrorLogging.getLogger().info("Identity Request failed :" + aTransID);
					}
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E54: " + e + "\n");
				lt.start();
			}
		}

		return ideResp;
	}

	private String processLocation(String aTransID, HttpServletRequest request, HttpServletResponse response) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		String locResp = "";

		if (authReqDetail != null) {
			try {

				String lAuthStr = mEncDecObj.decrypt(mZomClientDGID, authReqDetail.isIPhone()) + ""
						+ mEncDecObj.decrypt(mZomClientDGSec, authReqDetail.isIPhone());

				String lInitOtpResp = "";
				// String lAuthStr =mZomClientID + mZomClientSec;

				String lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");
				CloseableHttpClient client = HttpClients.createDefault();
				StringBuilder lDiscoveryRespStr = new StringBuilder();

				JSONObject locReq = new JSONObject();

				locReq.put("mdn", lMsisdn);
				locReq.put("requestedAccuracy", "CELL");

				String reqTime = CommonHelper.getFormattedDateStringZOM();

				JSONObject conzoom = new JSONObject();
				JSONObject optZom = new JSONObject();

				conzoom.put("optinId", aTransID);
				conzoom.put("optinUrl", "www.abcbank.com/privacy");
				conzoom.put("optinVersionId", "Consent V1.0.1234");
				conzoom.put("optinType", "Whitelist");
				conzoom.put("optinMethod", "Other");
				conzoom.put("optinDuration", "ONG");
				conzoom.put("optinTimestamp", reqTime);

				locReq.put("consent", conzoom);

				optZom.put("mobileCoordinates", true);
				optZom.put("mobilePhysicalAddress", true);
				locReq.put("options", optZom);

				LoggingThread lt160 = new LoggingThread(" [" + aTransID + "] " + "mDGlocUrl : " + mDGlocUrl);
				lt160.start();
				// Logging.getLogger().info("mDGlocUrl : " + mDGlocUrl);

				HttpPost httpPost = new HttpPost(mDGlocUrl);

				LoggingThread lt161 = new LoggingThread(" [" + aTransID + "] " + "locReq req : " + locReq.toString());
				lt161.start();
				// Logging.getLogger().info("locReq req : " + locReq.toString());

				StringEntity mEntity = new StringEntity(locReq.toString());
				httpPost.setEntity(mEntity);
				httpPost.setHeader("Authorization", "Basic " + lAuthStr);
				httpPost.setHeader("Content-Type", "application/json");
				httpPost.setHeader("Accept", "application/json");
				httpPost.setHeader("clientId", mZomClientDGIDen);
				httpPost.setHeader("Cache-Control", "no-cache");

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
				lInitOtpResp = lDiscoveryRespStr.toString();

				LoggingThread lt162 = new LoggingThread(" [" + aTransID + "] " + "Location : " + lInitOtpResp
						+ ", Location Resp length " + lInitOtpResp.length());
				lt162.start();
				// Logging.getLogger().info("Location : " + lInitOtpResp);
				// Logging.getLogger().info("Location Resp length " + lInitOtpResp.length());

				if (lInitOtpResp.length() > 0) {
					JSONObject lOtprespJson = new JSONObject(lInitOtpResp);

					String status = lOtprespJson.getString("status");

					if (status.contentEquals("SUCCESS")) {
						return lInitOtpResp;
					} else {
						ErrorLoggingThread elt = new ErrorLoggingThread(
								" [" + aTransID + "] " + "Location Request failed :" + aTransID);
						elt.start();
						// ErrorLogging.getLogger().info("Location Request failed :" + aTransID);
					}
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E55: " + e + "\n");
				lt.start();
			}
		}

		return locResp;
	}

	private String processAirLocation(String aTransID, HttpServletRequest request, HttpServletResponse response) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		String locResp = "";

		if (authReqDetail != null) {
			try {

				String lAuthStr = mEncDecObj.decrypt(mZomClientDGID, authReqDetail.isIPhone()) + ""
						+ mEncDecObj.decrypt(mZomClientDGSec, authReqDetail.isIPhone());

				String lInitOtpResp = "";
				// String lAuthStr =mZomClientID + mZomClientSec;

				String lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");
				CloseableHttpClient client = HttpClients.createDefault();
				StringBuilder lDiscoveryRespStr = new StringBuilder();

				JSONObject locReq = new JSONObject();

				locReq.put("mdn", lMsisdn);
				locReq.put("requestedAccuracy", "CELL");

				String reqTime = CommonHelper.getFormattedDateStringZOM();

				JSONObject conzoom = new JSONObject();
				JSONObject optZom = new JSONObject();

				conzoom.put("optinId", aTransID);
				conzoom.put("optinUrl", "www.abcbank.com/privacy");
				conzoom.put("optinVersionId", "Consent V1.0.1234");
				conzoom.put("optinType", "initiateOptin");
				conzoom.put("optinMethod", "SMS");
				conzoom.put("optinDuration", "ONE");
				conzoom.put("optinTimestamp", reqTime);

				locReq.put("consent", conzoom);

				optZom.put("mobileCoordinates", true);
				optZom.put("mobilePhysicalAddress", true);
				locReq.put("options", optZom);

				LoggingThread lt163 = new LoggingThread(" [" + aTransID + "] " + "mDGlocUrl : " + mDGlocUrl);
				lt163.start();
				// Logging.getLogger().info("mDGlocUrl : " + mDGlocUrl);

				HttpPost httpPost = new HttpPost(mDGlocUrl);

				LoggingThread lt164 = new LoggingThread(" [" + aTransID + "] " + "locReq req : " + locReq.toString());
				lt164.start();
				// Logging.getLogger().info("locReq req : " + locReq.toString());

				StringEntity mEntity = new StringEntity(locReq.toString());
				httpPost.setEntity(mEntity);
				httpPost.setHeader("Authorization", "Basic " + lAuthStr);
				httpPost.setHeader("Content-Type", "application/json");
				httpPost.setHeader("Accept", "application/json");
				httpPost.setHeader("clientId", mZomClientDGIDen);
				httpPost.setHeader("Cache-Control", "no-cache");

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
				lInitOtpResp = lDiscoveryRespStr.toString();

				LoggingThread lt165 = new LoggingThread(" [" + aTransID + "] " + "Location : " + lInitOtpResp
						+ ", Location Resp length " + lInitOtpResp.length());
				lt165.start();
				// Logging.getLogger().info("Location : " + lInitOtpResp);
				// Logging.getLogger().info("Location Resp length " + lInitOtpResp.length());

				if (lInitOtpResp.length() > 0) {
					JSONObject lOtprespJson = new JSONObject(lInitOtpResp);

					String status = lOtprespJson.getString("status");

					if (status.contentEquals("SUCCESS")) {
						return lInitOtpResp;
					} else if (status.contentEquals("CONSENT_PENDING")) {

						JSONObject consentJson = lOtprespJson.getJSONObject("consent");

						String refid = consentJson.getString("refId");

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "refid", refid);

						locResp = "CONSENT_PENDING";
					}
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E56: " + e + "\n");
				lt.start();
			}
		}

		return locResp;
	}

	@RequestMapping(value = "/sendverify")
	public @ResponseBody void verifyNum(@RequestParam("mdnum") String aesplatform,
			@RequestParam("txnid") String aTransID, @RequestParam("param5") String param5,
			@RequestParam("mertxnid") String merTxnID, HttpServletRequest request, HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("sendverify");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		StringBuffer sb = new StringBuffer();
		try {
			String lMobileNumber = "";

			ImageValidationResponse mImgResp = null;
			StringBuilder imageStr = new StringBuilder();
			String headerName = null;
			String headerValue = null;

			AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

			String lRedirectUrl = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "rdu");
			String redirectUrl = "";

			String dataHashed = aTransID + param5;
			String hash = "";
			try {
				hash = CommonHelper.generateSign(authReqDetail.getSeckey(), dataHashed);
			} catch (Exception e1) {
				e1.printStackTrace();
			}

			MDC.put(LOG4J_MDC_TOKEN, merTxnID);

			LoggingThread lt166 = new LoggingThread(" [" + aTransID + "] " + "displayOTP txnID" + aTransID);
			lt166.start();
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

					LoggingThread lt167 = new LoggingThread(" [" + aTransID + "] "
							+ "*********************AES Encrypted_platform from JS - " + aesplatform
							+ ", *********************AES encrypted value of aesplatform --> salt :" + " " + salt
							+ ", iv : " + iv + ", ciphertext : " + ciphertext
							+ ", *********************AES Decrypted platform from JS - " + lMobileNumber);
					lt167.start();
				}

				StringBuilder mobileBuilder = new StringBuilder();

				String MobileNumber = decrypted_aesdata != null
						? URLDecoder.decode(decrypted_aesdata.split("\\*")[0], "UTF-8")
						: "null";
				String platform = decrypted_aesdata != null
						? URLDecoder.decode(decrypted_aesdata.split("\\*")[1], "UTF-8")
						: "null";
				String scn_Size = decrypted_aesdata != null ? decrypted_aesdata.split("\\*")[2] : "null";
				String nav_bua = decrypted_aesdata != null
						? URLDecoder.decode(decrypted_aesdata.split("\\*")[3], "UTF-8")
						: "null";

				mobileBuilder.append("91").append(MobileNumber);

				lMobileNumber = mobileBuilder.toString();

				String remoteIp = request.getRemoteAddr() != null ? request.getRemoteAddr() : "null";
				String xforwardedIP = request.getHeader("X-FORWARDED-FOR") != null
						? request.getHeader("X-FORWARDED-FOR")
						: "null";
				String clientIP = request.getHeader("CLIENT_IP") != null ? request.getHeader("CLIENT_IP") : "null";
				String referer = request.getHeader("referer") != null ? request.getHeader("referer") : "null";
				String acpt = request.getHeader("accept");
				String userAgent = request.getHeader("user-agent");
				String mip = Stream.of(xforwardedIP, remoteIp, clientIP)
						.filter(s -> s != null && !s.isEmpty() && !s.equalsIgnoreCase("null"))
						.collect(Collectors.joining("-"));

				LoggingThread lt168 = new LoggingThread(
						" [" + aTransID + "] " + "*** sendmdn Parameters *** purchaseId : " + aTransID
								+ ", UserAgent : " + userAgent + ", remoteIp : " + remoteIp + ", X-forwardedIP : "
								+ xforwardedIP + ", clientIP : " + clientIP + ", Referer : " + referer + ", acpt : "
								+ acpt + ", param5 : " + param5 + "\n" + "sendmdn lMobileNumber" + lMobileNumber);
				lt168.start();
//			Logging.getLogger()
//					.info("*** sendmdn Parameters *** purchaseId : " + aTransID + ", UserAgent : " + userAgent
//							+ ", remoteIp : " + remoteIp + ", X-forwardedIP : " + xforwardedIP + ", clientIP : "
//							+ clientIP + ", Referer : " + referer + ", acpt : " + acpt + ", param5 : " + param5);

				// Logging.getLogger().info("sendmdn lMobileNumber" + lMobileNumber);

				Enumeration<String> headerNames = request.getHeaderNames();
				String headersInfo = "";
				while (headerNames.hasMoreElements()) {
					headerName = headerNames.nextElement();
					Enumeration<String> headers = request.getHeaders(headerName);
					while (headers.hasMoreElements()) {
						headerValue = headers.nextElement();
					}
					headersInfo = headersInfo + " [" + aTransID + "] " + "**HEADER --> " + headerName + " : "
							+ headerValue + "\n";
					// Logging.getLogger().info("**HEADER --> " + headerName + " : " + headerValue);
				}
				LoggingThread lt169 = new LoggingThread(headersInfo);
				lt169.start();

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
					LoggingThread lt170 = new LoggingThread(" [" + aTransID + "] " + "displayImage fail : ");
					lt170.start();
					// Logging.getLogger().info("displayImage fail : ");
					CDRLoggingThread clt25 = new CDRLoggingThread(authReqDetail, null, SERVER_ERROR, "NA");
					clt25.start();
					// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, SERVER_ERROR, "NA");
					redirectUrl = lRedirectUrl + "msisdn=0" + "&txnid=" + aTransID + "&status=" + SERVER_ERROR
							+ "&eshare=null";
					response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
					response.setHeader("Location", redirectUrl);
					response.sendRedirect(redirectUrl);
				}
				if (mImgResp != null && mImgResp.getStatusCode().contentEquals("JS201")
						&& mImgResp.getResult().contentEquals("YES")) {

					LoggingThread lt171 = new LoggingThread(
							" [" + aTransID + "] " + "displayOTP mobilenum" + lMobileNumber);
					lt171.start();
					// Logging.getLogger().info("displayOTP mobilenum" + lMobileNumber);

					if (lMobileNumber.equals("910")) {
						String log = displayMdnpage(aTransID, request, response);
						sb.append(log + "\n");
					} else {

						mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(aTransID + "mn", lMobileNumber);

//						String createsesResp = createSession(aTransID);
						Object[] createSession = createSession(aTransID);
						String createsesResp = (String) createSession[0];
						sb.append(createSession[1]);
						if (!TextUtils.isEmpty(createsesResp)) {
							JSONObject lCrerespJson = new JSONObject(createsesResp);

							String sesstatus = lCrerespJson.getString("status");

							if (sesstatus.contentEquals("SUCCESS")) {
								String sesID = lCrerespJson.getString("sessionId");

								String lAuthrizeurl = mIdeDevUrl + "?sessionId=" + sesID + "&correlationId=" + aTransID
										+ "&redirectUrl=" + mZomRedirectUrl + "&mdnHint=" + lMobileNumber;
								response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
								response.setHeader("Location", lAuthrizeurl);
								response.sendRedirect(lAuthrizeurl);

							} else {
								LoggingThread lt172 = new LoggingThread(" [" + aTransID + "] " + "Identity Fail : ");
								lt172.start();
								// Logging.getLogger().info("Identity Fail : ");
								redirectUrl = lRedirectUrl + "msisdn=0" + "&txnid=" + aTransID + "&status="
										+ SERVER_ERROR + "&eshare=null";
								response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
								response.setHeader("Location", redirectUrl);
								response.sendRedirect(redirectUrl);
							}
						}
					}

				} else {
					LoggingThread lt173 = new LoggingThread(" [" + aTransID + "] " + "displayImage fail : ");
					lt173.start();
					// Logging.getLogger().info("displayImage fail : ");
					CDRLoggingThread clt26 = new CDRLoggingThread(authReqDetail, null, USER_CANCLED, "NA");
					clt26.start();
					// CDRLogging.getCDRWriter().logCDR(authReqDetail, null, USER_CANCLED, "NA");
					redirectUrl = lRedirectUrl + "msisdn=0" + "&txnid=" + aTransID + "&status=" + USER_CANCLED
							+ "&eshare=null";
					response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
					response.setHeader("Location", redirectUrl);
					response.sendRedirect(redirectUrl);
				}

			} catch (Exception e) {
				LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] "
						+ "Exception E57: " + e + "\n");
				lt.start();
			}
			MDC.clear();
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E58: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(aTransID);
			td.start();
		}
	}

	@RequestMapping(value = "/inbipcallback")
	@ResponseBody
	void infobipcallback(@RequestBody String payload, HttpServletRequest request, HttpServletResponse response) {

		String msisdn;
		String token = "";
		TimeDiffLogThread td = new TimeDiffLogThread("inbipcallback");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		try {

			InfobipCallbackResponse infobipresp = gson.fromJson(payload, InfobipCallbackResponse.class);

			token = infobipresp.getToken();

			MDC.put(LOG4J_MDC_TOKEN, token);

			LoggingThread lt174 = new LoggingThread(" [" + token + "] " + "InfobipCallbackResponse : " + payload);
			lt174.start();
			// Logging.getLogger().info("InfobipCallbackResponse : " + payload);

			msisdn = infobipresp.getMsisdn();

			if (!TextUtils.isEmpty(msisdn)) {
				mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(token + "token", msisdn);
			}

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + token + "] " + "Exception E59: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(token);
			td.start();
		}

	}

	@RequestMapping(value = "/insertsign")
	@ResponseBody
	void SignKeyInsert(@RequestParam(value = "avtimgurl", required = true) String avtimgurl,
			@RequestParam(value = "cliotpflag", required = true) boolean cliotpflag,
			@RequestParam(value = "cliUrl", required = true) String cliUrl,
			@RequestParam(value = "demography", required = true) boolean demography,
			@RequestParam(value = "desdata1", required = true) String desdata1,
			@RequestParam(value = "desdata2", required = true) String desdata2,
			@RequestParam(value = "desotp1", required = true) String desotp1,
			@RequestParam(value = "desotp2", required = true) String desotp2,
			@RequestParam(value = "deswifi1", required = true) String deswifi1,
			@RequestParam(value = "deswifi2", required = true) String deswifi2,
			@RequestParam(value = "ftext", required = true) String ftext,
			@RequestParam(value = "hcolor", required = true) String hcolor,
			@RequestParam(value = "htext", required = true) String htext,
			@RequestParam(value = "imgstr", required = true) String imgstr,
			@RequestParam(value = "imgurl", required = true) String imgurl,
			@RequestParam(value = "ipnsignkey", required = true) String ipnsignkey,
			@RequestParam(value = "mclkflag", required = true) boolean mclkflag,
			@RequestParam(value = "mid", required = true) String mid,
			@RequestParam(value = "multiDevice", required = true) boolean multiDevice,
			@RequestParam(value = "noconsent", required = true) boolean noconsent,
			@RequestParam(value = "rUrl", required = true) String rUrl,
			@RequestParam(value = "signkey", required = true) String signkey,
			@RequestParam(value = "wififlag", required = true) boolean wififlag,
			@RequestParam(value = "diurl", required = false) String diurl,
			@RequestParam(value = "shareurl", required = false) String shareurl,
			@RequestParam(value = "cmpname", required = false) String cmpname,
			@RequestParam(value = "smsurl", required = true) String smsurl,
			@RequestParam(value = "emailsuport", required = true) boolean emailsup,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request, HttpServletResponse response) {

		try {

			LoggingThread lt175 = new LoggingThread("### Sign in  QUERY PARAMS ### " + allReqParams.entrySet());
			lt175.start();
			// Logging.getLogger().info("### Sign in QUERY PARAMS ### " +
			// allReqParams.entrySet());

			/*
			 * SignKeyEntity signEntity = new SignKeyEntity();
			 * 
			 * signEntity.setAvtimgurl(avtimgurl); signEntity.setCliotpflag(cliotpflag);
			 * signEntity.setCliUrl(cliUrl); signEntity.setDemography(demography);
			 * signEntity.setDesdata1(desdata1); signEntity.setDesdata2(desdata2);
			 * signEntity.setDesotp1(desotp1); signEntity.setDesotp2(desotp2);
			 * signEntity.setDeswifi1(deswifi1); signEntity.setDeswifi2(deswifi2);
			 * signEntity.setFtext(ftext); signEntity.setHcolor(hcolor);
			 * signEntity.setHtext(htext); signEntity.setImgstr(imgstr);
			 * signEntity.setImgurl(imgurl); signEntity.setIpnsignkey(ipnsignkey);
			 * signEntity.setMclkflag(mclkflag); signEntity.setMid(mid);
			 * signEntity.setMultiDevice(multiDevice); signEntity.setNoconsent(noconsent);
			 * signEntity.setRUrl(rUrl); signEntity.setSignkey(signkey);
			 * signEntity.setWififlag(wififlag); signEntity.setDiurl(diurl);
			 * signEntity.setShareurl(shareurl); signEntity.setCmpname(cmpname);
			 * signEntity.setSmsurl(smsurl); signEntity.setEmailsup(emailsup);
			 * 
			 * mAuthDbService.saveSignKey(signEntity);
			 */
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + "insertsign" + "] "
					+ "Exception E60: " + e + "\n");
			lt.start();
		}
	}

	@RequestMapping(value = "/insertimg")
	@ResponseBody
	void ImgKeyInsert(@RequestParam(value = "mid", required = true) String mid,
			@RequestParam(value = "imgstr", required = true) String imgstr,
			@RequestParam(value = "gifstr", required = false) String gifstr,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request, HttpServletResponse response) {

		LoggingThread lt176 = new LoggingThread("### Img in  QUERY PARAMS ### " + allReqParams.entrySet());
		lt176.start();
		// Logging.getLogger().info("### Img in QUERY PARAMS ### " +
		// allReqParams.entrySet());
		try {
			ImgKeyEntity imgent = new ImgKeyEntity();

			/*
			 * imgent.setCustomerId(mid); imgent.setImgstr(imgstr);
			 * if(TextUtils.isEmpty(gifstr)) { imgent.setGifstr(" "); } else {
			 * imgent.setGifstr(gifstr); }
			 */

			TimeDiffLogThread td1 = new TimeDiffLogThread("ImgKeyEntity");
			td1.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveImgKey(imgent);
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			td1.start();

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + "insertimg" + "] "
					+ "Exception E61: " + e + "\n");
			lt.start();
		}
	}

	@RequestMapping(value = "/insertvenopr")
	@ResponseBody
	void vendorOptInse(@RequestParam(value = "opt", required = true) String Operator,
			@RequestParam(value = "vendor", required = true) String vendor,
			@RequestParam(value = "vertype", required = true) String vertype,
			@RequestParam(value = "status", required = true) String status,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request, HttpServletResponse response) {

		TimeDiffLogThread td = new TimeDiffLogThread("insertvenopr");
		td.setCurrentTimeMillis(System.currentTimeMillis());

		LoggingThread lt177 = new LoggingThread("### Vendor in  QUERY PARAMS ### " + allReqParams.entrySet());
		lt177.start();
		// Logging.getLogger().info("### Vendor in QUERY PARAMS ### " +
		// allReqParams.entrySet());

		try {
			OptVebdorEntity optvenEnt = new OptVebdorEntity();

			optvenEnt.setOpt(Operator);
			optvenEnt.setStatus(status);
			optvenEnt.setVendor(vendor);
			optvenEnt.setVertype(vertype);

			TimeDiffLogThread td1 = new TimeDiffLogThread("OptVebdorEntity");
			td1.setCurrentTimeMillis(System.currentTimeMillis());
			mAuthDbService.saveOptVend(optvenEnt);
			td1.setCurrentTimeMillis2(System.currentTimeMillis());
			td1.start();

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + "insertvenopr"
					+ "] " + "Exception E62: " + e + "\n");
			lt.start();
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.start();
		}
	}

	private String deleteredis(String aTransID) {

		StringBuilder sb = new StringBuilder();
		sb.append(
				new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "TxnID deleted from redis" + "\n");
//		LoggingThread lt178 = new LoggingThread(" [" + aTransID + "] " + "TxnID deleted from redis");
//		lt178.start();
		// Logging.getLogger().info("deleteredis aTransID :" + aTransID);

		try {
			if (mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req") != null) {
				mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(aTransID + "req");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "dffin") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "dffin");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "opn") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "opn");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "df") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "df");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "respurl") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "respurl");
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

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "veri") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "veri");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "token") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "token");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "new") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "new");
			}

			if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "action") != null) {
				mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "action");
			}

			if (mMCDiscoverRespRespoImpl.getValueFromAshiledMCRedisRepo(aTransID + "_MC") != null) {
				mMCDiscoverRespRespoImpl.deleteValueFromAshiledMCRedisRepo(aTransID + "_MC");
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
		} catch (Exception e) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "delete redis :"
					+ e.getMessage());
			ErrorLoggingThread elt = new ErrorLoggingThread(" [" + aTransID + "] " + "delete redis :" + e.getMessage());
			elt.start();
			// ErrorLogging.getLogger().info("delete redis :" + e.getMessage());
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransID + "] " + "Exception E63: " + e + "\n");
			lt.start();
		}
		return sb.toString();
	}

	@RequestMapping(value = "/getNumber")
	public @ResponseBody AuthMobResp getMobileNumber(@RequestParam(value = "txnID", required = true) String reqMerTxnID,
			@RequestParam(value = "mid", required = true) String reqMid,
			@RequestParam(value = "sign", required = true) String reqSign,
			@RequestParam Map<String, String> allReqParams, HttpServletRequest request) {
		GetNumberPojo CdrInfo = new GetNumberPojo();
		CdrInfo.setApiName("getNumber");
		CdrInfo.setMerTxnId(reqMerTxnID);
		CdrInfo.setAShieldTxnId("");
		CdrInfo.setSdkVersion("");
		CdrInfo.setSdkType("");
		CdrInfo.setDeviceTimestamp("");
		CdrInfo.setSimCount("");
		CdrInfo.setSelectedSim("");
		CdrInfo.setDf("");
		CdrInfo.setIP("");
		CdrInfo.setBua("");
		CdrInfo.setNType("");
		CdrInfo.setPurpose("");
		CdrInfo.setFlowType("");
		CdrInfo.setLongCode("");
		CdrInfo.setOpn1("");
		CdrInfo.setOpn2("");
		CdrInfo.setCauseOfReRegTrigger("");
		CdrInfo.setMobileDataStatus("");
		CdrInfo.setTransactionType("");
		CdrInfo.setEnvironment("");
		CdrInfo.setCircle("");

		CdrInfo.setMid(reqMid);
		CdrInfo.setReqTS(new Timestamp(System.currentTimeMillis()));
		TimeDiffLogThread td = new TimeDiffLogThread("getNumber");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		StringBuilder sb = new StringBuilder();
		AuthMobResp lResponse = new AuthMobResp();
		lResponse.setMertxnID(reqMerTxnID);
		lResponse.setMsisdn(INVALID_ZERO);
		lResponse.setStatus(SERVER_ERROR);
		SetMerConfig.setMerConfig(reqMid);
		if (!WebAuthSign.midfound) {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] " + "MID:" + reqMid
					+ " not found" + "\n");
			lResponse.setStatus(INVALID_CPID);
			return lResponse;
		}
		String headerName = null;
		String headerValue = null;
		try {

			boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true")) ? true
					: false;
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] "
					+ "Received data at getNumber API: merchant txnID: " + reqMerTxnID + ", MID: " + reqMid
					+ ", signature:" + reqSign + "\n");

			if (!loadtest) {

				Enumeration<String> headerNames = request.getHeaderNames();
				String headersInfo = "";
				while (headerNames.hasMoreElements()) {
					headerName = headerNames.nextElement();
					Enumeration<String> headers = request.getHeaders(headerName);
					while (headers.hasMoreElements()) {
						headerValue = headers.nextElement();
					}
					headersInfo = headersInfo + "**getMsiSnd HEADER --> " + headerName + " : " + headerValue + ", ";
				}

				sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] " + headersInfo + "\n");

				if (TextUtils.isEmpty(reqMerTxnID)) {
					sb.append(
							new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] " + "NO TXNID" + "\n");
					lResponse.setStatus(INVALID_CPTXNID);
					return lResponse;
				}

				if (TextUtils.isEmpty(reqMid)) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] " + "NO MID" + "\n");
					lResponse.setStatus(INVALID_CPID);
					return lResponse;
				}

				if (TextUtils.isEmpty(reqSign)) {
					sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] " + "NO SIGN" + "\n");
					lResponse.setStatus(INVALID_SIGN);
					return lResponse;
				}

				String seckey = WebAuthSign.seckey;

				String hash = reqMerTxnID + reqMid;
				Object[] validateSignature = validateSignature(seckey, reqSign, hash, reqMerTxnID);
				boolean res = (boolean) validateSignature[0];
				sb.append(validateSignature[1] + "\n");
				if (!res) {
					lResponse.setStatus(INVALID_SIGN);
					return lResponse;
				}

				AuthStatus authStatus = authStatusRespRepoImpl.getAuthStatus(reqMerTxnID + "authStatus");
				if (authStatus != null && (authStatus.getStatus() != null)) {
					if (authStatus.getStatus().equals(SUCCESS)) {
						String msisdn = authStatus.getMsisdn();
						msisdn = mEncDecObj.decrypt(msisdn);
						lResponse.setMsisdn(msisdn);
						if (WebAuthSign.regnumMatchFlag) {
							String regnum = authStatus.getRegNumber();
							regnum = mEncDecObj.decrypt(regnum);
							if (msisdn.equals(regnum))
								lResponse.setStatus(REG_MATCH);
							else
								lResponse.setStatus(REG_MISMATCH);
						} else {
							lResponse.setStatus(SUCCESS);
						}
					} else {
						lResponse.setStatus(authStatus.getStatus());
					}

				}

			} else {
				lResponse.setStatus(SUCCESS);
				return lResponse;
			}

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] "
					+ "Exception E64: " + e + "\n");
			lt.start();
			sb.append(e + "\n");
			return lResponse;
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			String apiresp = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "]" + "getNumber API response:"
					+ lResponse.toString() + "\n");
			sb.append(new Timestamp(System.currentTimeMillis()) + " [" + reqMerTxnID + "] " + apiresp + "\n");
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();

			CdrInfo.setStatus(lResponse.getStatus());
			CdrInfo.setProcessingTime((td.getCurrentTimeMillis2() - td.getCurrentTimeMillis()));
			CdrInfo.setRegnum(lResponse.getMsisdn());
			CDRgetNumber.getCDRWriter().logCDR(CdrInfo);
		}

		return lResponse;
	}

	@RequestMapping(value = "/setLockCount")
	public @ResponseBody String setLockCnt(@RequestParam(value = "txnID", required = true) String aTransId,
			@RequestParam(value = "mid", required = true) String mID, @RequestParam Map<String, String> allReqParams,
			HttpServletRequest request) {

		TimeDiffLogThread td = new TimeDiffLogThread("setLockCount");
		td.setCurrentTimeMillis(System.currentTimeMillis());

		String lTxnID = "";
		String encTranID = "";
		String reqTime = CommonHelper.getFormattedDateString();

		String headerName = null;
		String headerValue = null;
		String resp = SERVER_ERROR;
		String aDecReq = "";
		TransIDReq lTrReq = null;

		try {

			boolean loadtest = (System.getenv("LOADTEST") != null && System.getenv("LOADTEST").equals("true")) ? true
					: false;

			long startTime = System.currentTimeMillis();

			LoggingThread lt185 = new LoggingThread(" [" + aTransId + "] " + aTransId);
			lt185.start();
			// Logging.getLogger().info(aTransId);

			lTxnID = getTransID();

			if (!loadtest) {

				LoggingThread lt186 = new LoggingThread(
						" [" + aTransId + "] " + "setLockCount mid:" + mID + ", setLockCount TxnID:" + aTransId);
				lt186.start();
				// Logging.getLogger().info("setLockCount mid:" + mID);
				// Logging.getLogger().info("setLockCount TxnID:" + aTransId);

				if (TextUtils.isEmpty(aTransId)) {
					LoggingThread lt187 = new LoggingThread(" [" + aTransId + "] " + "NO TXNID");
					lt187.start();
					// Logging.getLogger().info("NO TXNID");
					return SERVER_ERROR;
				}

				if (TextUtils.isEmpty(mID)) {
					LoggingThread lt188 = new LoggingThread(" [" + aTransId + "] " + "NO MID");
					lt188.start();
					// Logging.getLogger().info("NO MID");
					return SERVER_ERROR;
				}

				Enumeration<String> headerNames = request.getHeaderNames();
				String headersInfo = "";
				while (headerNames.hasMoreElements()) {
					headerName = headerNames.nextElement();
					Enumeration<String> headers = request.getHeaders(headerName);
					while (headers.hasMoreElements()) {
						headerValue = headers.nextElement();
					}
					headersInfo = headersInfo + " [" + aTransId + "] " + "**setLockCount HEADER --> " + headerName
							+ " : " + headerValue + "\n";
					// Logging.getLogger().info("**setLockCount HEADER --> " + headerName + " : " +
					// headerValue);
				}
				LoggingThread lt1 = new LoggingThread(headersInfo);
				lt1.start();

			} else {
				resp = lTxnID;
			}

		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(
					new Timestamp(System.currentTimeMillis()) + " [" + aTransId + "] " + "Exception E65: " + e + "\n");
			lt.start();
			return SERVER_ERROR;
		} finally {
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID(aTransId);
			td.start();
		}

		return resp;
	}

	@RequestMapping(value = "/UPDATE-MERCHANT-CONFIG")
	public @ResponseBody String updateMerchantdata(@RequestBody Map<String, String> JSONPayload) {
		StringBuilder sb = new StringBuilder();
		sb.append(new Timestamp(System.currentTimeMillis()) + " [Product Manager] "
				+ "Merchants configurations update initiated" + "\n");
		TimeDiffLogThread td = new TimeDiffLogThread("UPDATE-MERCHANT-CONFIG");
		td.setCurrentTimeMillis(System.currentTimeMillis());
		try {
			if (JSONPayload.get("passcode").matches("@Sh1ld")) {
//				String merConfig = JSONPayload.get("merConfig");
//				SetMerConfig.updateMerConfig(merConfig);
				updateMerConfig();
				return "Merchant file updated successfully";
			} else {
				return "Wrong passcode";
			}
		} catch (Exception e) {
			LoggingThread lt = new LoggingThread(new Timestamp(System.currentTimeMillis()) + " [" + "Product Manager"
					+ "] " + "Exception E66: " + e + "\n");
			lt.start();
		} finally {
			sb.append(new Timestamp(System.currentTimeMillis()) + " [Product Manager] "
					+ "Merchants configurations update completed" + "\n");
			td.setCurrentTimeMillis2(System.currentTimeMillis());
			td.setTxnID("Product Manager");
			String log = td.start();
			sb.append(new Timestamp(System.currentTimeMillis()) + " [Product Manager] " + log + "\n");
			LoggingThread lt = new LoggingThread(sb.toString());
			lt.start();
		}
		return "";
	}

	private void updateMerConfig() {
		List<AccountInfoEntity> allMer = mAuthDbService.getAllMer();
		SetMerConfig.updateAllMerConfig(allMer);
	}

	@RequestMapping(value = "/hello", method = RequestMethod.GET)
	public @ResponseBody String getHello(HttpServletRequest request) throws ServletException {
		LoggingThread lt = new LoggingThread(
				new Timestamp(System.currentTimeMillis()) + " [Health check probe] " + "Service is live");
		lt.start();
		return "";
	}

}
