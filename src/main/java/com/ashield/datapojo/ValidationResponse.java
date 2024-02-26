package com.ashield.datapojo;

import java.io.Serializable;

import org.springframework.data.annotation.Id;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class ValidationResponse implements Serializable {

	private static final long serialVersionUID = 7598865443964138854L;

	@Id
	private String mertxnID;
	private String msisdn;
	private String status;

}
