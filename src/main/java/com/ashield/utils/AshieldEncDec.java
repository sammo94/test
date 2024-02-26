package com.ashield.utils;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.ashield.logging.ErrorLogging;

@Service
public class AshieldEncDec {
	//private String iv = "Y!1&S#!zsRbw6@1*";//Dummy value=aaaaaaaaaaaaaaaa iv (CHANGE IT!)Y!1&S#!zsRbw6@1*
	private String iv = "Y!1&S#!zsRbw6@1*";
	private IvParameterSpec ivspec;
	private SecretKeySpec keyspec;
	private SecretKeySpec keyspec_iphone;
	private Cipher cipher;
	//private String SecretKey = "3DIDAOCresponsep";//Dummy secretKey (CHANGE IT!) it should be not more than 16
	private String SecretKey = "3DIDAOCresponsep";
	private String SecretKey_iphone = "3DIDAOCresponsep";
	
	
	public AshieldEncDec() {

		ivspec = new IvParameterSpec(iv.getBytes());
		keyspec = new SecretKeySpec(SecretKey.getBytes(), "AES");
		keyspec_iphone = new SecretKeySpec(SecretKey_iphone.getBytes(), "AES");
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public synchronized String encrypt(String text) throws Exception {
		String str_encrypted = "";
        if(text == null || text.length() == 0) {
        	return str_encrypted;
        }            
        byte[] encrypted = null;
        try {
        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            encrypted = cipher.doFinal(padString(text).getBytes());
            str_encrypted =  bytesToHex(encrypted);
        } catch (Exception e) {
            //throw new Exception("[encrypt] " + e.getMessage());
            ErrorLogging.getLogger().error("[encrypt] " + e.getMessage());
        }
        return str_encrypted;
    }

    public synchronized String decrypt(String code) throws Exception {
    	String str_decrypted = "0";
        if(code == null || code.length() == 0) {
        	return str_decrypted;
        }            
        byte[] decrypted = null;
        try {
        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            decrypted = cipher.doFinal(hexToBytes(code));
            str_decrypted = new String(decrypted);
        } catch (Exception e) {
            //throw new Exception("[decrypt] " + e.getMessage());
            ErrorLogging.getLogger().error("[decrypt] " + e.getMessage());
        }
        str_decrypted = str_decrypted.trim();
        return str_decrypted;
    }
    
    
    public synchronized String encrypt(String text, boolean iphone) throws Exception {
		String str_encrypted = "";
        if(text == null || text.length() == 0) {
        	return str_encrypted;
        }            
        byte[] encrypted = null;
        try {
        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        	if(iphone) {
        		cipher.init(Cipher.ENCRYPT_MODE, keyspec_iphone, ivspec);
        	} else {
        		cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
        	}
            
            encrypted = cipher.doFinal(padString(text).getBytes());
            str_encrypted =  bytesToHex(encrypted);
        } catch (Exception e) {
            //throw new Exception("[encrypt] " + e.getMessage());
            ErrorLogging.getLogger().error("[encrypt] " + e.getMessage());
        }
        return str_encrypted;
    }

    public synchronized String decrypt(String code, boolean iphone) throws Exception {
    	String str_decrypted = "0";
        if(code == null || code.length() == 0) {
        	return str_decrypted;
        }            
        byte[] decrypted = null;
        try {
        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        	if(iphone) {
        		cipher.init(Cipher.DECRYPT_MODE, keyspec_iphone, ivspec);
        	} else {
        		cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
        	}
            decrypted = cipher.doFinal(hexToBytes(code));
            str_decrypted = new String(decrypted);
        } catch (Exception e) {
           // throw new Exception("[decrypt] " + e.getMessage());
            ErrorLogging.getLogger().error("[decrypt] " + e.getMessage());
        }
        str_decrypted = str_decrypted.trim();
        return str_decrypted;
    }
    
    public synchronized String encrypt(String text, String key) throws Exception {
    	int length = key.getBytes().length;
    	SecretKeySpec lkeyspec = new SecretKeySpec(key.getBytes(), "AES");
		String str_encrypted = "";
        if(text == null || text.length() == 0) {
        	return str_encrypted;
        }            
        byte[] encrypted = null;
        try {
        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, lkeyspec, ivspec);
            encrypted = cipher.doFinal(padString(text).getBytes());
            str_encrypted =  bytesToHex(encrypted);
        } catch (Exception e) {
            //throw new Exception("[encrypt] " + e.getMessage());
            ErrorLogging.getLogger().error("[encrypt] " + e.getMessage());
        }
        return str_encrypted;
    }

    public synchronized String decrypt(String code, String key) throws Exception {
    	SecretKeySpec lkeyspec = new SecretKeySpec(key.getBytes(), "AES");;
    	String str_decrypted = "0";
        if(code == null || code.length() == 0) {
        	return str_decrypted;
        }            
        byte[] decrypted = null;
        try {
        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, lkeyspec, ivspec);
            decrypted = cipher.doFinal(hexToBytes(code));
            str_decrypted = new String(decrypted);
        } catch (Exception e) {
            //throw new Exception("[decrypt] " + e.getMessage());
            ErrorLogging.getLogger().error("[decrypt] " + e.getMessage());
        }
        str_decrypted = str_decrypted.trim();
        return str_decrypted;
    }
    
    public static String bytesToHex(byte[] data) {
        if (data==null) {
            return null;
        }
        int len = data.length;
        String str = "";
        for (int i=0; i<len; i++) {
            if ((data[i]&0xFF)<16)
                str = str + "0" + Integer.toHexString(data[i]&0xFF);
            else
                str = str + Integer.toHexString(data[i]&0xFF);
        }
        return str;
    }

    public static byte[] hexToBytes(String str) {
        if (str==null) {
            return null;
        } else if (str.length() < 2) {
            return null;
        } else {
            int len = str.length() / 2;
            byte[] buffer = new byte[len];
            for (int i=0; i<len; i++) {
                buffer[i] = (byte) Integer.parseInt(str.substring(i*2,i*2+2),16);
            }
            return buffer;
        }
    }
    
    private static String padString(String source) {
        char paddingChar = ' ';
        int size = 16;
        int x = source.length() % size;
        int padLength = size - x;
        for (int i = 0; i < padLength; i++) {
            source += paddingChar;
        }
        return source;
    }

}
