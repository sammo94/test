package com.ashield.redisrepo;

import com.ashield.datapojo.AuthWebResp;

public interface AuthwebRespTokenRepo {
	void saveToAshiledReqRedisRepo(String key, AuthWebResp value);

	AuthWebResp getValueFromAshiledReqRedisRepo(String key);

	void deleteValueFromAshiledReqRedisRepo(String key);
}
