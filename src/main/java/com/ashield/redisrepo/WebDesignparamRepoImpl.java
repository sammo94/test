package com.ashield.redisrepo;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.WebDesignParam;

@Repository
public class WebDesignparamRepoImpl implements WebDesignParamRepo{

	private RedisTemplate<String, WebDesignParam> redisTemplate;
	private ValueOperations<String, WebDesignParam> valueOperation;
	
	public WebDesignparamRepoImpl() {
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Autowired
    public WebDesignparamRepoImpl(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
	
	@PostConstruct
    public void init() {
        valueOperation = redisTemplate.opsForValue();
    }
		
	@Override
	public void saveToWebDesignparamRepo(String key, WebDesignParam value) {
		valueOperation.set(key, value);	
	}

	@Override
	public WebDesignParam getValueFromWebDesignparamRepo(String key) {
		return valueOperation.get(key);
	}

	@Override
	public void deleteValueFromWebDesignparamRepo(String key) {
		valueOperation.getOperations().delete(key);				
	}

}
