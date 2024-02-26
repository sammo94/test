package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WebDesignParam implements Serializable {
	private String cpID;
	private String cpTxnID;
	private boolean wififlag;
	private String htext;
	private String hcolor;
	private String ftext;
	private boolean mclkflag; // multiclick
	private String desdata1;
	private String desdata2;
	private String deswifi1;
	private String deswifi2;
	private String desotp1;
	private String desotp2;
	private String logoimg;
	private String avtimg;
	private String imgstr;
	private String gifstr;
}
