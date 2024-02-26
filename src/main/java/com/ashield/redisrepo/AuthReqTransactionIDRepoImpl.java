package com.ashield.redisrepo;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthReqDetail;

@Repository
public class AuthReqTransactionIDRepoImpl implements AuthReqTransactionIDRepo{

	private RedisTemplate<String, AuthReqDetail> redisReqTemplate;
	private ValueOperations<String, AuthReqDetail> valueReqOperation;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
	public AuthReqTransactionIDRepoImpl(RedisTemplate redisTemplate) {
		this.redisReqTemplate = redisTemplate;
	}

	@PostConstruct
	public void init() {
		valueReqOperation = redisReqTemplate.opsForValue();
	}
	@Override
	public void saveToAshiledReqRedisRepo(String key, AuthReqDetail value) {
		valueReqOperation.set(key, value);		
	}

	@Override
	public AuthReqDetail getValueFromAshiledReqRedisRepo(String key) {
		return valueReqOperation.get(key);
	}

	@Override
	public void deleteValueFromAshiledReqRedisRepo(String key) {
		valueReqOperation.getOperations().delete(key);		
	}
}
