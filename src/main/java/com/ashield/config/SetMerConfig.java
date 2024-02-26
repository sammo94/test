package com.ashield.config;

import java.io.FileReader;
import java.util.HashMap;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.ashield.datapojo.AccountInfoEntity;
import com.ashield.datapojo.SMSEntity;
import com.ashield.datapojo.Smsc;
import com.ashield.datapojo.WebAuthSign;

public class SetMerConfig {

	private static HashMap<String, AccountInfoEntity> sConfigs = new HashMap();;
	public static String confileloc;
	private static ArrayList<Smsc> smscs = null;

	public static void setMerConfig(String mid) {

		if (null != WebAuthSign.id && WebAuthSign.id.equalsIgnoreCase(mid)) {
			return;
		}

		smscs = new ArrayList();

		if (sConfigs.containsKey(mid)) {
			AccountInfoEntity aie = sConfigs.get(mid);
			WebAuthSign.midfound = true;
			WebAuthSign.id = aie.getCustomerId();
			WebAuthSign.avtimgurl = aie.getAvtimgurl();
			WebAuthSign.cliUrl = aie.getCliUrl();
			WebAuthSign.cliotpflag = Boolean.valueOf((String) aie.getCliotpflag());
			WebAuthSign.desdata1 = aie.getDesdata1();
			WebAuthSign.desdata2 = aie.getDesdata2();
			WebAuthSign.desotp1 = aie.getDesotp1();
			WebAuthSign.desotp2 = aie.getDesotp2();
			WebAuthSign.deswifi1 = aie.getDeswifi1();
			WebAuthSign.deswifi2 = aie.getDeswifi2();
			WebAuthSign.ftext = aie.getFtext();
			WebAuthSign.hcolor = aie.getHcolor();
			WebAuthSign.htext = aie.getHtext();
			WebAuthSign.imgurl = aie.getImgurl();
			WebAuthSign.mclkflag = aie.isMclkflag();
			WebAuthSign.rUrl = aie.getRUrl();
			WebAuthSign.signkey = aie.getSignkey();
			WebAuthSign.seckey = aie.getSecreteKey();
			WebAuthSign.wififlag = aie.isWififlag();
			WebAuthSign.ipnsignkey = aie.getIpnsignkey();
			WebAuthSign.multiDevice = aie.isMultiDevice();
			WebAuthSign.demography = aie.isDemography();
			WebAuthSign.noconsent = aie.isNoconsent();
			WebAuthSign.imgstr = aie.getImgstr();
			WebAuthSign.diurl = aie.getDiurl();
			WebAuthSign.shareurl = aie.getShareurl();
			WebAuthSign.smsurl = aie.getSmsurl();
			WebAuthSign.emailsup = aie.isEmailsup();
			WebAuthSign.flowtype = aie.getFlowtype();
			WebAuthSign.longcode = aie.getLongcode();
			WebAuthSign.mermsg = aie.getMermsg();
			WebAuthSign.regnumMatchFlag = aie.isRegnumMatchFlag();
			WebAuthSign.debug = aie.isDebug();
			WebAuthSign.pkn = aie.getPkn();
			WebAuthSign.controlFlow = aie.getControlFlow();
			List<SMSEntity> jsa = aie.getSmscs();
			if (null != jsa) {
				Iterator itr = jsa.iterator();
				while (itr.hasNext()) {
					SMSEntity smsinfo = (SMSEntity) itr.next();
					String lc = smsinfo.getLongcode();
					String op = smsinfo.getOperator();
					try {
						if (null == lc || lc.isEmpty() || null == op || op.isEmpty()) {
							throw new Exception("Mandatory config missing. SMSC Longcode and operator must be set.");
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
					float valueOf = Float.valueOf(smsinfo.getPercentage());
					int per = (int) valueOf;
					Smsc smsc = new Smsc(lc, op, per);
					smscs.add(smsc);
				}
			}
		} else {
			WebAuthSign.midfound = false;
		}
		/*
		 * WebAuthSign.midfound = false; JSONParser jsonParser = new JSONParser(); try
		 * (FileReader reader = new FileReader(confileloc)) { Object obj =
		 * jsonParser.parse(reader); JSONArray merObjs = (JSONArray) obj; //
		 * System.out.println(merObjs); Iterator iterator = merObjs.iterator(); while
		 * (iterator.hasNext()) { Object merObj = iterator.next(); //
		 * System.out.println(merObj); JSONObject merobjresp =
		 * parseConfigObjects((JSONObject) merObj, mid); if (merobjresp != null) {
		 * WebAuthSign.midfound = true; break; } } } catch (Exception e) {
		 * e.printStackTrace(); }
		 */
	}

	public static void updateMerConfig(String merConfig) {
		WebAuthSign.midfound = false;
		JSONParser jsonParser = new JSONParser();
		try (FileReader reader = new FileReader(confileloc)) {
			Object parse = jsonParser.parse(merConfig);
			JSONObject objs = (JSONObject) parse;
			String mid = (String) objs.get("_id");
			Object obj = jsonParser.parse(reader);
			JSONArray merObjs = (JSONArray) obj;
//			System.out.println(merObjs);
			Iterator iterator = merObjs.iterator();
			while (iterator.hasNext()) {
				Object merObj = iterator.next();
//				System.out.println(merObj);
				JSONObject merobjresp = updateConfigObjects((JSONObject) merObj, mid, merConfig);
				if (merobjresp != null) {
					WebAuthSign.midfound = true;
					String obj1 = "[" + "{\"" + mid + "\":" + merobjresp.toJSONString() + "}";
					JSONParser jsonParser1 = new JSONParser();
					FileReader reader1 = new FileReader(confileloc);
					Object merobj = jsonParser1.parse(reader1);
					JSONArray merObjs1 = (JSONArray) merobj;
//						System.out.println(merObjs);
					Iterator iterator1 = merObjs1.iterator();
					while (iterator1.hasNext()) {
						Object merObj1 = iterator1.next();
						obj1 = obj1 + "," + merObj1.toString();
					}
					obj1 = obj1 + "]";
//					System.out.println(obj1);
					FileWriter fileWriter = new FileWriter(confileloc);
					fileWriter.write(obj1);
					fileWriter.close();
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static JSONObject parseConfigObjects(JSONObject merObj, String mid) {

		JSONObject json = (JSONObject) merObj.get(mid);
		try {
			if (json != null) {
				WebAuthSign.id = (String) (String) json.get("_id");
				WebAuthSign.avtimgurl = (String) json.get("avtimgurl");
				WebAuthSign.cliUrl = (String) json.get("cliUrl");
				WebAuthSign.cliotpflag = Boolean.valueOf((String) json.get("cliotpflag"));
				WebAuthSign.desdata1 = (String) json.get("desdata1");
				WebAuthSign.desdata2 = (String) json.get("desdata2");
				WebAuthSign.desotp1 = (String) json.get("desotp1");
				WebAuthSign.desotp2 = (String) json.get("desotp2");
				WebAuthSign.deswifi1 = (String) json.get("deswifi1");
				WebAuthSign.deswifi2 = (String) json.get("deswifi2");
				WebAuthSign.ftext = (String) json.get("ftext");
				WebAuthSign.hcolor = (String) json.get("hcolor");
				WebAuthSign.htext = (String) json.get("htext");
				WebAuthSign.imgurl = (String) json.get("imgurl");
				WebAuthSign.mclkflag = Boolean.valueOf((String) json.get("mclkflag"));
				WebAuthSign.rUrl = (String) json.get("rUrl");
				WebAuthSign.signkey = (String) json.get("signkey");
				WebAuthSign.seckey = (String) json.get("secreteKey");
				WebAuthSign.wififlag = Boolean.valueOf((String) json.get("wififlag"));
				WebAuthSign.ipnsignkey = (String) json.get("ipnsignkey");
				WebAuthSign.multiDevice = Boolean.valueOf((String) json.get("multiDevice"));
				WebAuthSign.demography = Boolean.valueOf((String) json.get("demography"));
				WebAuthSign.noconsent = Boolean.valueOf((String) json.get("noconsent"));
				WebAuthSign.imgstr = (String) json.get("imgstr");
				WebAuthSign.diurl = (String) json.get("diurl");
				WebAuthSign.shareurl = (String) json.get("shareurl");
				WebAuthSign.smsurl = (String) json.get("smsurl");
				WebAuthSign.emailsup = Boolean.valueOf((String) json.get("emailsup"));
				WebAuthSign.flowtype = (String) json.get("flowtype");
				WebAuthSign.longcode = (String) json.get("longcode");
				WebAuthSign.mermsg = (String) json.get("mermsg");
				WebAuthSign.regnumMatchFlag = Boolean.valueOf((String) json.get("regnumMatchFlag"));
				WebAuthSign.debug = Boolean.valueOf((String) json.get("debug"));
				WebAuthSign.pkn = (String) json.get("pkn");
			}
		} catch (Exception e) {
			System.out.println(e);
		}
		return json;
	}

	private static JSONObject updateConfigObjects(JSONObject merObj, String mid, String merConfig) {

		JSONObject json = (JSONObject) merObj.get(mid);
		try {
			JSONParser jsonParser = new JSONParser();
			Object parse = jsonParser.parse(merConfig);
			JSONObject objs = (JSONObject) parse;
			if (json != null) {
				json.put("signkey", (String) objs.get("signkey"));
				json.put("secreteKey", (String) objs.get("secreteKey"));
				json.put("secreteKey", (String) json.get("noconsent"));
				json.put("flowtype", (String) objs.get("flowtype"));
				json.put("longcode", (String) objs.get("longcode"));
				json.put("mermsg", (String) objs.get("mermsg"));
				json.put("regnumMatchFlag", (String) json.get("regnumMatchFlag"));
			}
		} catch (Exception e) {
			System.out.println(e);
		}
		return json;
	}

	public static List<String> readFileInList(String fileName) {
		List<String> lines = Collections.emptyList();
		try {
			lines = Files.readAllLines(Paths.get(fileName), StandardCharsets.UTF_8);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return lines;
	}

	public static void updateAllMerConfig(List<AccountInfoEntity> allMer) {

		String merconfiginfo = "";
		for (AccountInfoEntity merchant : allMer) {
			String mid = merchant.getCustomerId();
			sConfigs.put(mid, merchant);
			String avtimgurl = merchant.getAvtimgurl();
			String cliUrl = merchant.getCliUrl();
			String cliotpflag = merchant.getCliotpflag();
			String desdata1 = merchant.getDesdata1();
			String desdata2 = merchant.getDesdata2();
			String desotp1 = merchant.getDesotp1();
			String desotp2 = merchant.getDesotp2();
			String deswifi1 = merchant.getDeswifi1();
			String deswifi2 = merchant.getDeswifi2();
			String ftext = merchant.getFtext();
			String hcolor = merchant.getHcolor();
			String htext = merchant.getHtext();
			String imgurl = merchant.getImgurl();
			String mclk = String.valueOf(merchant.isMclkflag());
			String rUrl = merchant.getRUrl();
			String signkey = merchant.getSignkey();
			String secreteKey = merchant.getSecreteKey();
			String wififlag = String.valueOf(merchant.isWififlag());
			String ipnsignkey = merchant.getIpnsignkey();
			String multiDevice = String.valueOf(merchant.isMultiDevice());
			String demography = String.valueOf(merchant.isDemography());
			String noconsent = String.valueOf(merchant.isNoconsent());
			String imgstr = merchant.getImgstr();
			String diurl = merchant.getDiurl();
			String shareurl = merchant.getShareurl();
			String smsurl = merchant.getSmsurl();
			String emailsup = String.valueOf(merchant.isEmailsup());
			String longcode = merchant.getLongcode();
			String flowtype = merchant.getFlowtype();
			String regnumMatchFlag = String.valueOf(merchant.isRegnumMatchFlag());
			String debug = String.valueOf(merchant.isDebug());
			String pkn = String.valueOf(merchant.getPkn());
			String smsinfo = String.valueOf(merchant.getSmscs());
			String info = "{\"" + mid + "\":{\"_id\":\"" + mid + "\",\"avtimgurl\":\"" + avtimgurl + "\",\"cliUrl\":\""
					+ avtimgurl + "\",\"cliUrl\":\"" + cliUrl + "\",\"cliotpflag\":\"" + cliotpflag
					+ "\",\"desdata1\":\"" + desdata1 + "\",\"desdata2\":\"" + desdata2 + "\",\"desotp1\":\"" + desotp1
					+ "\",\"desotp2\":\"" + desotp2 + "\",\"deswifi1\":\"" + deswifi1 + "\",\"deswifi2\":\"" + deswifi2
					+ "\",\"ftext\":\"" + ftext + "\",\"hcolor\":\"" + hcolor + "\",\"htext\":\"" + htext
					+ "\",\"imgurl\":\"" + imgurl + "\",\"rUrl\":\"" + rUrl + "\",\"signkey\":\"" + signkey
					+ "\",\"secreteKey\":\"" + secreteKey + "\",\"wififlag\":\"" + wififlag + "\",\"ipnsignkey\":\""
					+ ipnsignkey + "\",\"mclk\":\"" + mclk + "\",\"multiDevice\":\"" + multiDevice
					+ "\",\"multiDevice\":\"" + multiDevice + "\",\"demography\":\"" + demography
					+ "\",\"noconsent\":\"" + noconsent + "\",\"imgstr\":\"" + imgstr + "\",\"diurl\":\"" + diurl
					+ "\",\"shareurl\":\"" + shareurl + "\",\"smsurl\":\"" + smsurl + "\",\"emailsup\":\"" + emailsup
					+ "\",\"longcode\":\"" + longcode + "\",\"flowtype\":\"" + flowtype + "\",\"regnumMatchFlag\":\""
					+ regnumMatchFlag + "\",\"debug\":\"" + debug + "\",\"pkn\":\"" + pkn + "\",\"smscs\":\"" + smsinfo
					+ "\"}},";
			merconfiginfo = merconfiginfo + info;
		}
//		merconfiginfo = merconfiginfo + "{\"xx\":{\"xx\"}}";
		merconfiginfo = "[" + merconfiginfo + "]";
//		System.out.println(merconfiginfo);
		// TODO : Later this must be removed
		// Keeping this time being because so many methods in this class still uses the
		// config file
		try {
			FileWriter fw = new FileWriter(confileloc);
			fw.write(merconfiginfo);
			fw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static ArrayList<Smsc> getSmscs() {
		return smscs;
	}

}
