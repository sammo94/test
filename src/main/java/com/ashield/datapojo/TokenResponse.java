package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenResponse implements Serializable{
 private String access_token;
 private String token_type;
 private float expires_in;
 private String scope;
 private String id_token;
}