package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TxnResp {
	private String mertxnid;
	private String status;
	private String pmdn;
	private String smdn;
	private String astxnid;
}
