package com.ashield.redisrepo;

import com.ashield.datapojo.ValidationResponse;

public interface AuthResponseToCustomerRepo {

	void savevalueToRedis(String mertxnID, String signature, String status);

	ValidationResponse getvalueFromRedis(String mertxnID);

	public void deletevalueFromRedis(String mertxnID);

}
