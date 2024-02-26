package com.ashield.logging;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
//
//import org.apache.log4j.Level;
//import org.apache.log4j.LogManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.apache.log4j.PropertyConfigurator;

import com.ashield.datapojo.AuthReqDetail;
import com.ashield.datapojo.WebAuthSign;
import com.ashield.utils.AshieldEncDec;

public class CDRLogging {

//	static {
//		PropertyConfigurator.configure(Logging.class.getResourceAsStream("/log4j.properties"));
//		LogManager.getRootLogger().setLevel(Level.INFO);
//	}

	private static volatile CDRLogging minstance = null;
	private static Object lock = new Object();

	public static CDRLogging getCDRWriter() {
		if (minstance == null) {
			synchronized (lock) {
				if (minstance == null) {
					minstance = new CDRLogging();
				}
			}
		}
		return minstance;
	}

	private static final Logger log = LoggerFactory.getLogger(CDRLogging.class);

	public Logger getLogger() {
		return log;
	}

	public synchronized void logCDR(AuthReqDetail aDetail, String aMsisdn, String statuscode, String imgResp) {

		StringBuilder cdrdata = new StringBuilder();
		try {
			aDetail.setReg_num_status("NA");
			if (statuscode.equals("AS201")) {
				if (aMsisdn.equals(aDetail.getRegnum()))
					aDetail.setReg_num_status("RegNum-matched");
				else
					aDetail.setReg_num_status("RegNum-mismatched");
			}
			if (aDetail != null) {
				AshieldEncDec mEncDecObj = new AshieldEncDec();
				String uagent = aDetail.getBua() != null ? aDetail.getBua().replaceAll(",", "-") : "null";
				String df = aDetail.getDf() != null ? aDetail.getDf().replaceAll(",", "-") : "null";
				if (!WebAuthSign.debug) {
					uagent = uagent != null ? uagent : "null";
					uagent = mEncDecObj.encrypt(uagent);
					if (aDetail.getMip() != null) {
						aDetail.setMip(mEncDecObj.encrypt(aDetail.getMip()));
					}
				}
				aDetail = extractBuaInfo(aDetail);

				cdrdata.append(aDetail.getStartTime()).append(",").append(aDetail.getCpID()).append(",")
						.append(aDetail.getCpTxnID()).append(",").append(aDetail.getCpRdu()).append(",").append(aMsisdn)
						.append(",").append(statuscode).append(",").append(aDetail.getTempStatus()).append(",")
						.append(aDetail.getNewTxnID()).append(",").append(imgResp).append(",")
						.append(aDetail.getMerTxnID()).append(",").append(df).append(",")
						.append(aDetail.getChannel() != null ? aDetail.getChannel() : "null")
						// .append(",").append(aDetail.getPrimMsisdn())
						.append(",").append(aDetail.getSecMsisdn() != null ? aDetail.getSecMsisdn() : "null")
						.append(",").append(aDetail.isAuthorize()).append(",").append(uagent).append(",")
						.append(aDetail.getMip() != null ? aDetail.getMip() : "null").append(",")
						.append(aDetail.getDevOsName() != null ? aDetail.getDevOsName() : "null").append(",")
						.append(aDetail.getBrowserName() != null ? aDetail.getBrowserName() : "null").append(",")
						.append(aDetail.getDeviceModel() != null ? aDetail.getDeviceModel() : "null").append(",")
						.append(aDetail.getNetProvider() != null ? aDetail.getNetProvider() : "null").append(",")
						.append(aDetail.getOpnName() != null ? aDetail.getOpnName() : "null").append(",")
						.append(aDetail.getIsMobileNetwork() != null ? aDetail.getIsMobileNetwork() : "null")
						.append(",").append(aDetail.getTelco() != null ? aDetail.getTelco() : "null").append(",")
						.append(aDetail.getNitime() != null ? aDetail.getNitime() : "null").append(",")
						.append(aDetail.getLocation() != null ? aDetail.getLocation() != null : "null").append(",")
						.append(System.currentTimeMillis() - aDetail.getRetime()).append(",")
						.append(aDetail.getRegnum()).append(",").append(aDetail.getReg_num_status()).append(",")
						.append(new Timestamp(System.currentTimeMillis()));

				String finalCDRstring = cdrdata.toString().replaceAll("null", "NA");
             	log.debug(finalCDRstring);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public synchronized void dummylogCDRRotate() {
		log.debug("");
	}

	public String getDateString(Date dt) {
		try {
			if (dt != null)
				return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(dt);
		} catch (Exception e) {
			ErrorLogging.getLogger().error("Exception in CDR logging ", e);
		}
		return "#";
	}

	public static AuthReqDetail extractBuaInfo(AuthReqDetail pur) {
		try {
			String os = "null";
			String browser = "null";
			String deviceModel = "null";

			if (pur != null && pur.getBua().length() > 30) {
				String browserDetails = pur.getBua();
				String userAgent = browserDetails;
				String user = userAgent.toLowerCase();

				// =================DEVICE OS=======================//
				if (userAgent.toLowerCase().indexOf("windows") >= 0) {
					os = "Windows";
				} else if (userAgent.toLowerCase().indexOf("mac") >= 0) {
					os = "Mac";
				} else if (userAgent.toLowerCase().indexOf("x11") >= 0) {
					os = "Unix";
				} else if (userAgent.toLowerCase().indexOf("android") >= 0) {
					os = "Android";
				} else if (userAgent.toLowerCase().indexOf("iphone") >= 0) {
					os = "IPhone";
				} else {
					// os = "UnKnown, More-Info: "+userAgent;
					os = "NA";
				}

				// ===============DEVICE BROWSER===========================//

				if (user.contains("msie")) { // MSIE
					String substring = userAgent.substring(userAgent.indexOf("MSIE")).split(";")[0];
					browser = substring.split(" ")[0].replace("MSIE", "IE") + "-" + substring.split(" ")[1];
				} else if (user.contains("wap")) {
					browser = (userAgent.substring(userAgent.indexOf("WAP")).split(" ")[0]);
				} else if (user.contains("rv")) {
					browser = "IE-" + user.substring(user.indexOf("rv") + 3, user.indexOf(")"));
				} else if (user.contains("ucbrowser")) { // UCBrowser
					browser = (userAgent.substring(userAgent.indexOf("UCBrowser")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("puffin")) { // Puffin
					browser = (userAgent.substring(userAgent.indexOf("Puffin")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("samsungbrowser")) { // SamsungBrowser
					browser = (userAgent.substring(userAgent.indexOf("SamsungBrowser")).split(" ")[0]).replace("/",
							"-");
				} else if (user.contains("yabrowser")) { // Yandex Browser
					browser = (userAgent.substring(userAgent.indexOf("YaBrowser")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("xiaomi") || user.contains("miuibrowser")) { // XiaoMi/MiuiBrowser
					if (user.contains("xiaomi")) {
						if (userAgent.indexOf("XIAOMI") != -1) {
							browser = (userAgent.substring(userAgent.indexOf("XIAOMI")).split(" ")[0]).replace("/",
									"-");
						} else if (userAgent.indexOf("Xiaomi") != -1) {
							browser = (userAgent.substring(userAgent.indexOf("Xiaomi")).split(" ")[0]).replace("/",
									"-");
						} else {
							browser = (userAgent.substring(userAgent.indexOf("XiaoMi")).split(" ")[0]).replace("/",
									"-");
						}
					} else if (user.contains("miuibrowser")) {
						browser = (userAgent.substring(userAgent.indexOf("MiuiBrowser")).split(" ")[0]).replace("/",
								"-");
					}
				} else if (user.contains("iemobile")) { // IEMobile
					browser = (userAgent.substring(userAgent.indexOf("IEMobile")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("edge")) { // Edge Mobile
					browser = (userAgent.substring(userAgent.indexOf("Edge")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("bb")) { // Blackberry Browser
					browser = (userAgent.substring(userAgent.indexOf("BB")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("dolfin")) { // Dolfin Browser
					browser = (userAgent.substring(userAgent.indexOf("Dolfin")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("opr") || user.contains("opera") || user.contains("opios")) {

					if (user.contains("opera mobi")) { // Opera Mobi
						browser = ((userAgent.substring(userAgent.indexOf("Opera Mobi")).split(" ")[0]).replace("/",
								"-"));
					} else if (user.contains("opera mini")) { // Opera Mini
						browser = ((userAgent.substring(userAgent.indexOf("Opera Mini")).split(" ")[0]).replace("/",
								"-"));
					} else if (user.contains("opios")) { // OPiOS
						browser = ((userAgent.substring(userAgent.indexOf("OPiOS")).split(" ")[0]).replace("/", "-"));
					} else if (user.contains("opera")) { // Opera
						if (user.contains("Version")) {
							browser = (userAgent.substring(userAgent.indexOf("Opera")).split(" ")[0]).split("/")[0]
									+ "-"
									+ (userAgent.substring(userAgent.indexOf("Version")).split(" ")[0]).split("/")[1];
						} else {
							browser = (userAgent.substring(userAgent.indexOf("Opera")).split(" ")[0]).replace("/", "-");
						}
					} else if (user.contains("opr")) { // OPR
						browser = ((userAgent.substring(userAgent.indexOf("OPR")).split(" ")[0]).replace("/", "-"))
								.replace("OPR", "Opera");
					}
				} else if (user.contains("firefox") || user.contains("fxios")) { // Firefox, FxiOS
					if (user.contains("firefox")) {
						browser = (userAgent.substring(userAgent.indexOf("Firefox")).split(" ")[0]).replace("/", "-");
					} else if (user.contains("fxios")) {
						browser = (userAgent.substring(userAgent.indexOf("FxiOS")).split(" ")[0]).replace("/", "-");
					}
				} else if (user.contains("chrome")) { // Chrome
					browser = (userAgent.substring(userAgent.indexOf("Chrome")).split(" ")[0]).replace("/", "-");
				} else if (user.contains("safari")) { // Safari
					if (user.contains("version")) {
						browser = (userAgent.substring(userAgent.indexOf("Safari")).split(" ")[0]).split("/")[0] + "-"
								+ (userAgent.substring(userAgent.indexOf("Version")).split(" ")[0]).split("/")[1];
					} else {
						browser = (userAgent.substring(userAgent.indexOf("Safari")).split(" ")[0]).split("/")[0];
					}
				} else if ((user.indexOf("mozilla/7.0") > -1) || (user.indexOf("netscape6") != -1)
						|| (user.indexOf("mozilla/4.7") != -1) || (user.indexOf("mozilla/4.78") != -1)
						|| (user.indexOf("mozilla/4.08") != -1) || (user.indexOf("mozilla/3") != -1)) {
					// browser=(userAgent.substring(userAgent.indexOf("MSIE")).split("
					// ")[0]).replace("/", "-");
					browser = "Netscape-?";
				} else {
					// browser = "UnKnown, More-Info: "+userAgent;
					browser = "NA";
				}

				// ===============Device Model=====================//

				// user = (user.indexOf("(")!=-1)?user.substring(user.indexOf('(') + 1,
				// user.indexOf(')')):user;
				user = (user.indexOf("(") != -1 && user.indexOf(")") != -1)
						? (user.substring(user.indexOf('(') + 1, user.indexOf(')')))
						: user;

				if (user.contains("iphone")) {
					deviceModel = "iPhone";
				} else if (user.contains("windows phone") || user.contains("microsoft") || user.contains("lumia")
						|| user.contains("nokia")) {
					deviceModel = "Nokia";
				} else if (user.contains("micromax") || user.contains("canvas")) {
					deviceModel = "Micromax";
				} else if (user.contains("samsung") || user.contains("sm-")) {
					deviceModel = "Samsung";
				} else if (user.contains(" mi ")) {
					deviceModel = "Mi";
				} else if (user.contains("redmi")) {
					deviceModel = "Redmi";
				} else if (user.contains("vivo")) {
					deviceModel = "Vivo";
				} else if (user.contains("ultrafone")) {
					deviceModel = "Ultrafone";
				} else if (user.contains("moto") || user.contains("moto ") || user.contains("motorola")
						|| user.contains(" xt")) {
					deviceModel = "Motorola";
				} else if (user.contains("intex") || user.contains("aqua")) {
					deviceModel = "Intex";
				} else if (user.contains("lenovo")) {
					deviceModel = "Lenovo";
				} else if (user.contains("huawei") || user.contains("lio") || user.contains("che")
						|| user.contains("cro-")) {
					deviceModel = "Huawei";
				} else if (user.contains("tecno")) {
					deviceModel = "Tecno";
				} else if (user.contains("nexus")) {
					deviceModel = "Google";
				} else if (user.contains("lephone")) {
					deviceModel = "Lephone";
				} else if (user.contains("gucci") || user.contains("xiaomi")) {
					deviceModel = "Xiaomi";
				} else if (user.contains("letv") || user.contains("le ")) {
					deviceModel = "LeTV";
				} else if (user.contains("aura") || user.contains("karbonn") || user.contains("maximus")
						|| user.contains("titanium")) {
					deviceModel = "Karbonn";
				} else if (user.contains("neo") || user.contains("neo power") || user.contains("konnect")) {
					deviceModel = "Swipe";
				} else if (user.contains("asus")) {
					deviceModel = "Asus";
				} else if (user.contains("iris")) {
					deviceModel = "Lava";
				} else if (user.contains("revolution")) {
					deviceModel = "Jivi Revolution";
				} else if (user.contains(" lg") || user.contains(" lg-") || user.contains(" lgm-")) {
					deviceModel = "LG";
				} else if (user.contains("centric")) {
					deviceModel = "Centric";
				} else if (user.contains("sapphire")) {
					deviceModel = "SingTech";
				} else if (user.contains("one")) {
					deviceModel = "OnePlus";
				} else if (user.contains("exmart")) {
					deviceModel = "Exmart";
				} else if (user.contains("htc desire") || user.contains("htc") || user.contains("desire")) {
					deviceModel = "HTC";
				} else if (user.contains("oppo") || user.contains("a51f") || user.contains("f1f")
						|| user.contains("CPH")) {
					deviceModel = "Oppo";
				} else if (user.contains("panasonic")) {
					deviceModel = "Panasonic";
				} else if (user.contains("spice")) {
					deviceModel = "Spice";
				} else if (user.contains("sony") || user.contains("h4113")) {
					deviceModel = "Sony";
				} else if (user.contains("itel")) {
					deviceModel = "Itel";
				} else if (user.contains("e-tel")) {
					deviceModel = "E-tel";
				} else if (user.contains("afmid")) {
					deviceModel = "Aftron";
				} else if (user.contains("alba")) {
					deviceModel = "Alba";
				} else if (user.contains("honor") || user.contains("jat-l") || user.contains("ksa-l")) {
					deviceModel = "Honor";
				} else if (user.contains("ag-02")) {
					deviceModel = "Atouch";
				} else if (user.contains("sth100-2")) {
					deviceModel = "Blackberry";
				} else if (user.contains("Doro Liberto")) {
					deviceModel = "Doro";
				} else if (user.contains("gionee")) {
					deviceModel = "Gionee";
				} else if (user.contains("extreme")) {
					deviceModel = "Extreme";
				} else {
					deviceModel = "NA";
				}

				pur.setDevOsName(os);
				pur.setBrowserName(browser);
				pur.setDeviceModel(deviceModel);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pur;
	}

}
