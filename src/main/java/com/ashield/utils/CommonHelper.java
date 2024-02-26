package com.ashield.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import com.github.tsohr.JSONArray;
import com.github.tsohr.JSONException;
import com.github.tsohr.JSONObject;

public class CommonHelper {

	public static String generateSign(String secretKey, String data) throws NoSuchAlgorithmException,
	InvalidKeyException, UnsupportedEncodingException {
		//"HmacSHA512"
		Mac mac = Mac.getInstance("HmacSHA512");
		mac.init(new SecretKeySpec(secretKey.getBytes(), "HmacSHA512"));
		byte[] hexBytes = new Hex().encode(mac.doFinal(data.getBytes()));
		return new String(hexBytes, "UTF-8");
	}
	
	public static boolean isJSONValid(String test) {
	    try {
	        new JSONObject(test);
	    } catch (JSONException ex) {
	        // edited, to include @Arthur's comment
	        // e.g. in case JSONArray is valid as well...
	        try {
	            new JSONArray(test);
	        } catch (JSONException ex1) {
	            return false;
	        }
	    }
	    return true;
	}

	public static String getFormattedDateString() {
		String dateFormatNow = "dd-MM-yyyy HH:mm:ss";
		SimpleDateFormat sdf = new SimpleDateFormat(dateFormatNow);
		return sdf.format(new Date());
	}

	public static Date getDateFromString(String dateStr) throws ParseException {
		String dateFormatNow = "dd-MM-yyyy HH:mm:ss";
		SimpleDateFormat sdf = new SimpleDateFormat(dateFormatNow);
		return sdf.parse(dateStr);
	}

	public static String getFormattedDateStringZOM() {
		String dateFormatNow = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
		SimpleDateFormat sdf = new SimpleDateFormat(dateFormatNow);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(new Date());
	}

	public static String getOtp() {

		int v = (int) (Math.random() * 9999);
		if (v < 1000) {
			v += 1000;
		}
		return String.valueOf(v);
	}

}
