package com.ashield.redisrepo;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.DiscoveryResponse;


@Repository
public class MCDiscoverRespRespoImpl implements MCDiscoverRespRepo{

	private RedisTemplate<String, DiscoveryResponse> redisTemplate;
	private ValueOperations<String, DiscoveryResponse> valueOperation;
	
	public MCDiscoverRespRespoImpl() {
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
    public MCDiscoverRespRespoImpl(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
	
	@PostConstruct
    public void init() {
        valueOperation = redisTemplate.opsForValue();
    }
	@Override
	public DiscoveryResponse getValueFromAshiledMCRedisRepo(String key) {		
		return valueOperation.get(key);
	}

	@Override
	public void deleteValueFromAshiledMCRedisRepo(String key) {
		valueOperation.getOperations().delete(key);		
	}

	@Override
	public void saveToAshiledMCRedisRepo(String key, DiscoveryResponse value) {
		valueOperation.set(key, value);
	}

}
