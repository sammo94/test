package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MobResp implements Serializable{

	private static final long serialVersionUID = 1L;
	private String pmdn;
	private String status;
	private String mertxnid;
	private String smdn;
	private String astxnid;
}
