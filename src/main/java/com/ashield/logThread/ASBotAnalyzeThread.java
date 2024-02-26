package com.ashield.logThread;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.beans.factory.annotation.Value;

import com.ashield.utils.Constants;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ASBotAnalyzeThread extends Thread implements Constants {

	private String acpTxnID;
	private String mobileIp;
	private String msisdn;
	private String browserAgent;
	private String acpID;
	private String acpt;
	private String referer;
	private String xRequestedWithReferer;
	private String aChannel;

	private String resp = null;
	private boolean abn = false;

	@Value("${ashield.authbot.url}")
	String mAuthBotUrl;

	@Value("${mchttpTimeout}")
	int mcHttpTimeout;

	public ASBotAnalyzeThread(String acpTxnID, String mobileIp, String msisdn, String browserAgent, String acpID,
			String acpt, String referer, String xRequestedWithReferer, String aChannel) {
		setAcpTxnID(acpTxnID);
		setMobileIp(mobileIp);
		setMsisdn(msisdn);
		setBrowserAgent(browserAgent);
		setAcpID(acpID);
		setAcpt(acpt);
		setReferer(referer);
		setXRequestedWithReferer(xRequestedWithReferer);
		setAChannel(aChannel);
	}

	@Override
	public void run() {
		getBotAnalyze(getAcpTxnID(), getMobileIp(), getMsisdn(), getBrowserAgent(), getAcpID(), getAcpt(), getReferer(),
				getXRequestedWithReferer(), getAChannel());
		try {
			if (resp != null)
				abn = true;
			Thread.sleep(10);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		super.run();
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
				LoggingErrorThread let2 = new LoggingErrorThread("[" + acpTxnID + "] " + imgresponse);
				let2.start();
				// Logging.getLogger().error(imgresponse);
				// System.out.println(imgresponse);
			}
			resp = respStr.toString();
			LoggingThread lt = new LoggingThread("[" + acpTxnID + "] " + "BotRespVal : " + resp);
			lt.start();
			// Logging.getLogger().info("BotRespVal : " + resp);

		} catch (Exception e) {
			ErrorLoggingThread elt4 = new ErrorLoggingThread(
					"[" + acpTxnID + "] " + "Auth Bot error " + e.getMessage());
			elt4.start();
			// ErrorLogging.getLogger().info("Auth Bot error " + e.getMessage());
		}

		return resp;
	}

}
