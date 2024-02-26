package com.ashield.redisrepo;

import com.ashield.datapojo.DiscoveryResponse;

public interface MCDiscoverRespRepo {
	void saveToAshiledMCRedisRepo(String key, DiscoveryResponse value);
	DiscoveryResponse getValueFromAshiledMCRedisRepo(String key);
	void deleteValueFromAshiledMCRedisRepo(String key);
}
