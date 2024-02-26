package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthMobResp implements Serializable {

	private static final long serialVersionUID = 1L;
	String status;
	String mertxnID;
	String msisdn;
}
