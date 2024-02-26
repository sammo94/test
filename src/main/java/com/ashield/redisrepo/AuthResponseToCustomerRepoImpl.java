package com.ashield.redisrepo;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.ValidationResponse;
import com.ashield.logThread.ErrorLoggingThread;
import com.ashield.logThread.LoggingThread;

@Repository
public class AuthResponseToCustomerRepoImpl implements AuthResponseToCustomerRepo {

	private RedisTemplate<String, ValidationResponse> redisReqTemplate;
	private ValueOperations<String, ValidationResponse> valueReqOperation;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
	public AuthResponseToCustomerRepoImpl(RedisTemplate redisTemplate) {
		this.redisReqTemplate = redisTemplate;
	}

	@PostConstruct
	public void init() {
		valueReqOperation = redisReqTemplate.opsForValue();
	}

	@Override
	public ValidationResponse getvalueFromRedis(String mertxnID) {
		ValidationResponse verifyRequest = null;
		try {
			verifyRequest = valueReqOperation.get(mertxnID);
			if (verifyRequest != null)
				return verifyRequest;
		} catch (Exception e) {
			ErrorLoggingThread elt14 = new ErrorLoggingThread();
			elt14.setInfo("Validation data responding error for mertxnID:" + mertxnID + ", " + e.getMessage());
			elt14.start();
			return null;
		}
		return verifyRequest;
	}

	@Override
	public void savevalueToRedis(String mertxnID, String msisdn, String status) {
		try {
			ValidationResponse value = new ValidationResponse();
			value.setMertxnID(mertxnID);
			value.setMsisdn(msisdn);
			value.setStatus(status);
			valueReqOperation.set(mertxnID, value);
		} catch (Exception e) {
			ErrorLoggingThread elt14 = new ErrorLoggingThread();
			elt14.setInfo("Validation data saving error for mertxnID:" + mertxnID + ", " + e.getMessage());
			elt14.start();
		}

	}

	@Override
	public void deletevalueFromRedis(String mertxnID) {
		try {
			valueReqOperation.getOperations().delete(mertxnID);
			LoggingThread lt210 = new LoggingThread();
			lt210.setInfo("Validation Object Deletion Over from redis for merTxnID:" + mertxnID);
			lt210.start();
		} catch (Exception e) {
			ErrorLoggingThread elt14 = new ErrorLoggingThread();
			elt14.setInfo("Validation data delete error for mertxnID:" + mertxnID + ", " + e.getMessage());
			elt14.start();
		}
	}

}
