package com.ashield.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.ashield.redisque.RedisMessageSubscriber;

@Configuration
public class RedisConfiguration {

	@Value("${redis.host.name}")
	String redisHost;

	@Value("${redis.host.cred}")
	String redisCred;

	@Value("${redis.host.port}")
	int redisPort;

	@Bean
	JedisConnectionFactory jedisConnectionFactory() {
		JedisConnectionFactory jedisConFactory = new JedisConnectionFactory();
		jedisConFactory.setHostName(redisHost);
		jedisConFactory.setPort(redisPort);
		jedisConFactory.setPassword(redisCred);
		return jedisConFactory;
	}

	@Bean
	StringRedisSerializer stringRedisSerializer() {
		return new StringRedisSerializer();
	}

	@Bean
	public RedisTemplate<String, Object> redisTemplate() {
		RedisTemplate<String, Object> template = new RedisTemplate<>();
		template.setConnectionFactory(jedisConnectionFactory());
		template.setKeySerializer(stringRedisSerializer());
		return template;
	}
	
	@Autowired
	RedisMessageSubscriber redisMessageSubscriber;

	@Bean
	MessageListenerAdapter messageListener( ) {
		return new MessageListenerAdapter(redisMessageSubscriber);
	}

	@Value("${ashield.authreq.expiry.time}")
	int imageExpiryInMin;

	@Bean
	RedisMessageListenerContainer redisContainer() {
		RedisMessageListenerContainer container = new RedisMessageListenerContainer();
		container.setConnectionFactory(jedisConnectionFactory());
		container.addMessageListener(messageListener(), topic());
		container.setMaxSubscriptionRegistrationWaitingTime(imageExpiryInMin * 60 * 1000);
		return container;
	}

	//set up a topic to which the publisher will send messages, and the subscriber will receive them
	@Bean
	ChannelTopic topic() {
		return new ChannelTopic("ashieldauthQueue");
	}
}
