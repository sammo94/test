package com.ashield.redisrepo;

import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

@Repository
public class AuthTransactionIDRepoImpl implements AuthTransactionIDRepo {

	private RedisTemplate<String, String> redisTemplate;
	private ValueOperations<String, String> valueOperation;

	@Value("${txnID.time}")
	int txnID_time;

	@Value("${dup.req.max.time.diff}")
	int dup_req_max_time_diff;

	@Value("${reg.info.redis.time}")
	int reg_info_redis_time;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
	public AuthTransactionIDRepoImpl(RedisTemplate redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@PostConstruct
	public void init() {
		valueOperation = redisTemplate.opsForValue();
	}

	@Override
	public void saveToAshiledAuthTranRepo(String key, String dfEncValue) {
		valueOperation.set(key, dfEncValue);
	}

	@Override
	public void saveToAshieldAuthRepoWithTimeout(String key, String dfEncValue) {
		valueOperation.set(key, dfEncValue, reg_info_redis_time, TimeUnit.SECONDS);
	}

	@Override
	public String getValueFromAshiledAuthTranRepo(String key) {
		return valueOperation.get(key);
	}

	@Override
	public void deleteValueFromAshiledAuthTranRepo(String key) {
		valueOperation.getOperations().delete(key);
	}

	@Override
	public void saveTxnID(String key, String txnID) {
		valueOperation.set(key, txnID, txnID_time, TimeUnit.SECONDS);
	}

	@Override
	public String getTxnID(String key) {
		return valueOperation.get(key);
	}

	@Override
	public void deleteTxnID(String key) {
		valueOperation.getOperations().delete(key);
	}

	@Override
	public void saveAuthTS(String key, String ts) {
		valueOperation.set(key, ts, dup_req_max_time_diff, TimeUnit.SECONDS);
	}

	@Override
	public String getAuthTS(String key) {
		return valueOperation.get(key);
	}

}
