package com.ashield.datapojo;

import java.util.Date;

import org.hibernate.validator.constraints.UniqueElements;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

@Document(collection = "ashieldauthshare")
public class AuthShareEntity {

	@Id
	private String id;

	private String mid;
	private String txnid;

	@Indexed
	private String newtxnid;

	private String msisdn;
	private String share1;
	private String share2;
	private String share3;
	private String devicefin;
	private String mertxnid;
	private String opn;
	private boolean authed;

	// new variables
	private String passkey;
	private long timestamp;
	private String regnum;
	private boolean regnumMatchFlag;
	private Date updatedAt;
	private String status;

}
