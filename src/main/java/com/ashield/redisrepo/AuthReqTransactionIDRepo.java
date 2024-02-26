package com.ashield.redisrepo;

import com.ashield.datapojo.AuthReqDetail;

public interface AuthReqTransactionIDRepo {
	void saveToAshiledReqRedisRepo(String key, AuthReqDetail value);
	AuthReqDetail getValueFromAshiledReqRedisRepo(String key);
	void deleteValueFromAshiledReqRedisRepo(String key);
}
