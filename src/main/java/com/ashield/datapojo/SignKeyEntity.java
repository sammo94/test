package com.ashield.datapojo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
//@Document(collection="authSettings")
@Document(collection = "webauthsign")
public class SignKeyEntity {

	@Id
	private String customerId;
	private String authType;
	private String autoMfa;

	private String cpBodyText;
	private String cpFooter;
	private String cpHeader;
	private boolean cpEnableMultiClick;
	private String cpSubheader;

	private String opSubHeader;
	private String opBodyText;

	private String identityCallbackUrl;
	private String tokenRedirectUrl;
	private boolean multiDevice;

	private boolean enableOtpFlow;
	private boolean generateOtp;
	private String otpText;
	private boolean enableEmailOtp;
	private boolean noconsent;

	public SignKeyEntity() {
		setCustomerId(WebAuthSign.id);
		setIdentityCallbackUrl(WebAuthSign.cliUrl);
		setNoconsent(WebAuthSign.noconsent);
		setMultiDevice(WebAuthSign.multiDevice);
	}

}
