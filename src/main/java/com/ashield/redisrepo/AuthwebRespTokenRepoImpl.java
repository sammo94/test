package com.ashield.redisrepo;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthWebResp;


@Repository
public class AuthwebRespTokenRepoImpl implements AuthwebRespTokenRepo{

	private RedisTemplate<String, AuthWebResp> redisReqTemplate;
	private ValueOperations<String, AuthWebResp> valueReqOperation;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
	public AuthwebRespTokenRepoImpl(RedisTemplate redisTemplate) {
		this.redisReqTemplate = redisTemplate;
	}

	@PostConstruct
	public void init() {
		valueReqOperation = redisReqTemplate.opsForValue();
	}
	@Override
	public void saveToAshiledReqRedisRepo(String key, AuthWebResp value) {
		valueReqOperation.set(key, value);		
	}

	@Override
	public AuthWebResp getValueFromAshiledReqRedisRepo(String key) {
		return valueReqOperation.get(key);
	}

	@Override
	public void deleteValueFromAshiledReqRedisRepo(String key) {
		valueReqOperation.getOperations().delete(key);		
	}
}
