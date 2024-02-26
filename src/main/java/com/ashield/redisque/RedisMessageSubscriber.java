package com.ashield.redisque;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.time.DateUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.TextUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.ashield.datapojo.AuthReqDetail;
import com.ashield.datapojo.AuthReqDetailForExpiry;
import com.ashield.datapojo.AuthWebResp;
import com.ashield.datapojo.DemoGraphyResp;
import com.ashield.logging.CDRLogging;
import com.ashield.logging.ErrorLogging;
import com.ashield.logging.Logging;
import com.ashield.redisrepo.AuthReqTransactionIDRepoImpl;
import com.ashield.redisrepo.AuthTransactionIDRepoImpl;
import com.ashield.redisrepo.AuthwebRespTokenRepoImpl;
import com.ashield.redisrepo.MCDiscoverRespRespoImpl;
import com.ashield.utils.AshieldEncDec;
import com.ashield.utils.CommonHelper;
import com.github.tsohr.JSONObject;
import com.google.gson.Gson;

@Component
public class RedisMessageSubscriber implements MessageListener {

	public static List<AuthReqDetailForExpiry> messageList = new CopyOnWriteArrayList<AuthReqDetailForExpiry>();

	@Autowired
	MCDiscoverRespRespoImpl mMCDiscoverRespRespoImpl;

	@Autowired
	AuthTransactionIDRepoImpl mMCTrackTransRespoImpl;

	@Autowired
	AuthReqTransactionIDRepoImpl mReqTrackTransRespoImpl;

	@Autowired
	AuthwebRespTokenRepoImpl mTokenRespRepoImpl;

	@Autowired
	AshieldEncDec mEncDecObj;

	@Value("${ashield.authreq.expiry.time}")
	int authReqExpiryInMin;

	@Value("${ashield.token.expiry.time}")
	int tokenExpiryInMin;

	@Value("${ashield.zom.loc.time}")
	int locExpiryInMin;

	@Value("${ashield.dgraphylurl.url}")
	String mDGlocUrl;

	@Value("${ashield.initotp.cliname}")
	String mZoClientName;

	@Value("${ashield.zom.dgsecclientid}")
	String mZomClientID;

	@Value("${ashield.zom.dgsecclientsec}")
	String mZomClientSec;

	@Value("${ashield.zom.dgclientid}")
	String mZomClientIDen;

	@Value("${mchttpTimeout}")
	int mcHttpTimeout;

	Gson gson = new Gson();

	@Override
	public void onMessage(final Message message, final byte[] pattern) {
		try {

			if (message != null) {

				String orig_msg = new String(message.getBody());
				String optxn = "";
				String token = "";

				AuthReqDetailForExpiry expiryDetail = new AuthReqDetailForExpiry();

				if (orig_msg.contains("WEBASHIELD")) {
					token = orig_msg.substring(orig_msg.indexOf("WEBASHIELD") + 10, orig_msg.lastIndexOf("#"));
					optxn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(token + "new");
					expiryDetail.setToken(token);
				} else if (orig_msg.contains("ZOMASHIELD")) {
					optxn = orig_msg.substring(orig_msg.indexOf("ZOMASHIELD") + 10, orig_msg.lastIndexOf("#"));
					expiryDetail.setToken("zom");
				} else if (orig_msg.contains("ASHIELD")) {
					optxn = orig_msg.substring(orig_msg.indexOf("ASHIELD") + 7, orig_msg.lastIndexOf("#"));
					expiryDetail.setToken("");
				} else {
					optxn = orig_msg.substring(orig_msg.indexOf("DFVAL") + 5, orig_msg.lastIndexOf("#"));
					expiryDetail.setToken("defin");
				}

				String reqTime = orig_msg.substring(orig_msg.lastIndexOf("#") + 1);

				expiryDetail.setOptxn(optxn);
				expiryDetail.setRequestTime(reqTime);
				messageList.add(expiryDetail);
			}
		} catch (Exception e) {
			ErrorLogging.getLogger().error("Exception in RedisMessageSubscriber-onMessage : ", e);
		}
	}

	@Scheduled(fixedDelay = 1000)
	public void ExpiredImagesTaskConsumerFromRedis() throws ParseException {
		// Logging.getLogger().info("ExpiredImagesTaskConsumerFromRedis ");
		try {
			if (messageList != null || !messageList.isEmpty()) {
				for (AuthReqDetailForExpiry imgExpDetails : messageList) {
					if (imgExpDetails != null) {
						Date reqDateTime = CommonHelper.getDateFromString(imgExpDetails.getRequestTime());
						Date rightNowTime = Calendar.getInstance().getTime();

						String ltoken = imgExpDetails.getToken();
						// Logging.getLogger().info("ExpiredImagesTaskConsumerFromRedis ltoken :" +
						// ltoken);

						if (!TextUtils.isEmpty(ltoken) && ltoken.contentEquals("zom")) {
							Date expiryDateTime = DateUtils.addMinutes(reqDateTime, locExpiryInMin);

							AuthReqDetail validationDetail = mReqTrackTransRespoImpl
									.getValueFromAshiledReqRedisRepo(imgExpDetails.getOptxn() + "req");

							if (validationDetail != null) {
								/*
								 * Logging.getLogger().info("expiryDateTime : " + expiryDateTime +
								 * ", rightNowTime :" + rightNowTime);
								 */
								if (!expiryDateTime.after(rightNowTime)) {

									String count = mMCTrackTransRespoImpl
											.getValueFromAshiledAuthTranRepo(imgExpDetails.getOptxn() + "locret");

									Logging.getLogger().info("expiryDateTime : " + expiryDateTime + " ,count: " + count
											+ ", txn: " + imgExpDetails.getOptxn());

									int countval = Integer.parseInt(count);

									if (countval < 3) {
										Logging.getLogger().info("expiryDateTime : " + expiryDateTime + " ,countval: "
												+ countval + ", txn: " + imgExpDetails.getOptxn());
										countval = countval + 1;
										mMCTrackTransRespoImpl.saveToAshiledAuthTranRepo(
												imgExpDetails.getOptxn() + "locret", String.valueOf(countval));
										String resp = processLocation(imgExpDetails.getOptxn());

										if (resp.contentEquals("CONSENT_PENDING")) {
											messageList.remove(imgExpDetails);

											AuthReqDetailForExpiry expiryDetail = new AuthReqDetailForExpiry();
											String reqTime = CommonHelper.getFormattedDateString();

											expiryDetail.setToken("zom");
											expiryDetail.setOptxn(imgExpDetails.getOptxn());
											expiryDetail.setRequestTime(reqTime);
											messageList.add(expiryDetail);

										} else {
											if (resp.contains("SUCCESS")) {
												DemoGraphyResp demresp = new DemoGraphyResp();
												demresp.setLocation(resp);

												String strresp = gson.toJson(demresp);
												sendDiResp(imgExpDetails.getOptxn(), validationDetail.getMerTxnID(),
														strresp);

											}
											deleteredis(imgExpDetails.getOptxn());
											messageList.remove(imgExpDetails);
										}
									} else {
										deleteredis(imgExpDetails.getOptxn());
										messageList.remove(imgExpDetails);
									}
								}
							} else {
								messageList.remove(imgExpDetails);
							}
						} else if (!TextUtils.isEmpty(ltoken) && ltoken.contentEquals("defin")) {
							Date expiryDateTime = DateUtils.addMinutes(reqDateTime, tokenExpiryInMin);

							String validationDetail = mMCTrackTransRespoImpl
									.getValueFromAshiledAuthTranRepo(imgExpDetails.getOptxn() + "df");

							if (validationDetail != null) {
								if (!expiryDateTime.after(rightNowTime)) {
									deleteredis(imgExpDetails.getOptxn());
									/*
									 * mMCTrackTransRespoImpl.
									 * deleteValueFromAshiledAuthTranRepo(imgExpDetails.getOptxn() + "df");
									 */
									messageList.remove(imgExpDetails);
								}
							} else {
								messageList.remove(imgExpDetails);
							}
						} else if (TextUtils.isEmpty(ltoken)) {
							Date expiryDateTime = DateUtils.addMinutes(reqDateTime, authReqExpiryInMin);
							AuthReqDetail validationDetail = mReqTrackTransRespoImpl
									.getValueFromAshiledReqRedisRepo(imgExpDetails.getOptxn() + "req");
							if (validationDetail != null) {
								if (!expiryDateTime.after(rightNowTime)) {
									Logging.getLogger().info("Auth Transaction timeout : " + imgExpDetails.getOptxn());
									// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(imgExpDetails.getOptxn()
									// + "req");
									CDRLogging.getCDRWriter().logCDR(validationDetail, "0", "AS205", "NA");
									deleteredis(imgExpDetails.getOptxn());
									messageList.remove(imgExpDetails);
								}
							} else {
								messageList.remove(imgExpDetails);
							}
						} else {
							Date expiryDateTime = DateUtils.addMinutes(reqDateTime, tokenExpiryInMin);
							AuthWebResp resp = mTokenRespRepoImpl.getValueFromAshiledReqRedisRepo(ltoken + "resp");
							if (resp != null) {
								AuthReqDetail validationDetail = mReqTrackTransRespoImpl
										.getValueFromAshiledReqRedisRepo(imgExpDetails.getOptxn() + "req");
								if (!expiryDateTime.after(rightNowTime)) {
									Logging.getLogger().info("Token Transaction timeout : " + imgExpDetails.getOptxn());
									CDRLogging.getCDRWriter().logCDR(validationDetail, "0", "AS205", "NA");
									mTokenRespRepoImpl.deleteValueFromAshiledReqRedisRepo(ltoken + "resp");
									// mReqTrackTransRespoImpl.deleteValueFromAshiledReqRedisRepo(imgExpDetails.getOptxn()
									// + "req");
									mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(ltoken + "new");
									deleteredis(imgExpDetails.getOptxn());
									messageList.remove(imgExpDetails);
								}
							} else {
								messageList.remove(imgExpDetails);
							}
						}
					}
				}
			}
		} catch (Exception e) {
			ErrorLogging.getLogger().error("Exception in ExpiredImagesTaskConsumerFromRedis : ", e);
		}
	}

	private String processLocation(String aTransID) {

		AuthReqDetail authReqDetail = mReqTrackTransRespoImpl.getValueFromAshiledReqRedisRepo(aTransID + "req");

		String locResp = "";

		if (authReqDetail != null) {
			try {

				String lAuthStr = mEncDecObj.decrypt(mZomClientID, authReqDetail.isIPhone()) + ""
						+ mEncDecObj.decrypt(mZomClientSec, authReqDetail.isIPhone());

				Logging.getLogger().info("lAuthStr : " + lAuthStr);

				String lInitOtpResp = "";
				// String lAuthStr =mZomClientID + mZomClientSec;

				String lMsisdn = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "mn");
				String lRefID = mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "refid");

				CloseableHttpClient client = HttpClients.createDefault();
				StringBuilder lDiscoveryRespStr = new StringBuilder();

				JSONObject locReq = new JSONObject();

				locReq.put("mdn", lMsisdn);
				locReq.put("requestedAccuracy", "CELL");

				String reqTime = CommonHelper.getFormattedDateStringZOM();

				JSONObject conzoom = new JSONObject();
				JSONObject optZom = new JSONObject();

				conzoom.put("refId", lRefID);
				locReq.put("consent", conzoom);

				optZom.put("mobileCoordinates", true);
				optZom.put("mobilePhysicalAddress", true);
				locReq.put("options", optZom);

				Logging.getLogger().info("mDGlocUrl : " + mDGlocUrl);

				HttpPost httpPost = new HttpPost(mDGlocUrl);

				Logging.getLogger().info("locReq req : " + locReq.toString());

				StringEntity mEntity = new StringEntity(locReq.toString());
				httpPost.setEntity(mEntity);
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
					// System.out.println(imgresponse);
				}
				lInitOtpResp = lDiscoveryRespStr.toString();
				Logging.getLogger().info("Location : " + lInitOtpResp);
				Logging.getLogger().info("Location Resp length " + lInitOtpResp.length());

				if (lInitOtpResp.length() > 0) {
					JSONObject lOtprespJson = new JSONObject(lInitOtpResp);

					String status = lOtprespJson.getString("status");

					if (status.contentEquals("SUCCESS")) {
						return lInitOtpResp;
					} else {
						locResp = "CONSENT_PENDING";
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return locResp;
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
						Logging.getLogger().error(imgresponse.toString());
						System.out.println(imgresponse);
					}
					Logging.getLogger().info("sendDIresp : " + imageStr.toString());
				} else {
					Logging.getLogger().info("sendDIresp : " + "Demography Url not set");
				}
			} else {
				Logging.getLogger().info("sendDIresp : " + "Demography Url not set");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void sendDiResp(String DiUrl, String resp) {

		StringBuilder imageStr = new StringBuilder();

		try {
			if (DiUrl != null) {

				HttpPost httpPost = new HttpPost(DiUrl);

				StringEntity entity = new StringEntity(resp);
				httpPost.setEntity(entity);

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
						imageStr.append(readLine);
					}
				} else {
					Logging.getLogger().error(imgresponse.toString());
					System.out.println(imgresponse);
				}
				Logging.getLogger().info("sendDIresp : " + imageStr.toString());

			} else {
				Logging.getLogger().info("sendDIresp : " + "Demography Url not set");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
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

		if (mMCTrackTransRespoImpl.getValueFromAshiledAuthTranRepo(aTransID + "locret") != null) {
			mMCTrackTransRespoImpl.deleteValueFromAshiledAuthTranRepo(aTransID + "locret");
		}
	}
}
