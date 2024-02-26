package com.ashield.logThread;

import com.ashield.datapojo.ValidationResponse;
import com.ashield.logging.Logging;
import com.ashield.redisrepo.AuthResponseToCustomerRepoImpl;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class VerifyObjectDeleteThread extends Thread {

	private String merTxnId;

	private AuthResponseToCustomerRepoImpl mAuthResponseToCustomer;

	public VerifyObjectDeleteThread(String merTxnID, AuthResponseToCustomerRepoImpl mAuthResponseToCustomer2) {
		setMerTxnId(merTxnID);
		setMAuthResponseToCustomer(mAuthResponseToCustomer2);
	}

	@Override
	public synchronized void run() {
		try {
			Logging.getLogger().info("Validation Object Deletion Started from redis for merTxnID:" + getMerTxnId());
			wait(60 * 1000);
			ValidationResponse getvalueFromRedis = getMAuthResponseToCustomer().getvalueFromRedis(getMerTxnId());
			if (getvalueFromRedis != null) {
				Logging.getLogger().info("Timer Over for merTxnID:" + getMerTxnId());
				getMAuthResponseToCustomer().deletevalueFromRedis(getMerTxnId());
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
