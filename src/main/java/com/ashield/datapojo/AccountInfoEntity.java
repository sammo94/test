package com.ashield.datapojo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

import org.json.simple.JSONArray;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
//@Document(collection="acctInfo")
@Document(collection = "webauthsign")
public class AccountInfoEntity {

	@Id
	private String customerId;

	private String apiKey;

	private String username;
	private String password;
	private String email;
	private String mobile;
	private String role;

	private String dateCreated;
	private String dateModified;
	private String vendorId;

	private String domain;
	private String name;
	private String country;
	private String webhookUrl;

//	private String secretKey;
	private String secreteKey;
	private String longcode;
	private String flowtype;

	// new variables
	private String avtimgurl;
	private String cliUrl;
	private String cliotpflag;
	private String desdata1;
	private String desdata2;
	private String desotp1;
	private String desotp2;
	private String deswifi1;
	private String deswifi2;
	private String ftext;
	private String hcolor;
	private String htext;
	private String imgurl;
	boolean mclkflag;
	private String rUrl;
	private String signkey;
	boolean wififlag;
	private String ipnsignkey;
	boolean demography;
	boolean noconsent;
	private String imgstr;
	private String smsurl;
	private boolean regnumMatchFlag;

	private boolean multiDevice;
	private String diurl;
	private String shareurl;
	private boolean emailsup;
	private String mermsg;
	private boolean debug;
	private String pkn;
	private List<SMSEntity> smscs;
	// Cotrolling/Testing old and new flow
	private int controlFlow;

}
