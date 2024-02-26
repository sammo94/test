package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthStatus implements Serializable {

	private static final long serialVersionUID = 3265164661159846647L;

	private String mertxnID;
	private String status;
	private String msisdn;
	private String regNumber = "";

}
