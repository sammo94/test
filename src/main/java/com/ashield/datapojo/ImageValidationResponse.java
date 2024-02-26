package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ImageValidationResponse implements Serializable{

	private static final long serialVersionUID = 1L;
	private String result;
	private String statusCode;
	private String optxn;
}
