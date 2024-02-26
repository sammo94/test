package com.ashield.redisrepo;

import com.ashield.datapojo.AuthStatus;

public interface AuthStatusRespRepo {

	void saveAuthStatus(String key, AuthStatus mResp);

	AuthStatus getAuthStatus(String key);

}
