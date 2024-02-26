package com.ashield.redisrepo;

import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthStatus;

@Repository
public class AuthStatusRespRepoImpl implements AuthStatusRespRepo {

	private RedisTemplate<String, AuthStatus> redisTemplate;
	private ValueOperations<String, AuthStatus> valueOperation;

	@Value("${status.time}")
	int status_time;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
	public AuthStatusRespRepoImpl(RedisTemplate redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@PostConstruct
	public void init() {
		valueOperation = redisTemplate.opsForValue();
	}

	@Override
	public void saveAuthStatus(String key, AuthStatus authStatus) {
		valueOperation.set(key, authStatus, status_time, TimeUnit.SECONDS);
	}

	@Override
	public AuthStatus getAuthStatus(String key) {
		return valueOperation.get(key);
	}

}
