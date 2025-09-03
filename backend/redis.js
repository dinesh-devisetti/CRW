const { createClient } = require('redis');

// Create Redis client
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 50, 500)
  }
});

// Handle Redis connection events
redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

redisClient.on('ready', () => {
  console.log('Redis client ready');
});

redisClient.on('end', () => {
  console.log('Redis connection ended');
});

// Connect to Redis
const connectRedis = async () => {
  try {
    await redisClient.connect();
    console.log('Redis connected successfully');
  } catch (error) {
    console.error('Failed to connect to Redis:', error);
    // Don't exit the process, just log the error
  }
};

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await redisClient.quit();
    console.log('Redis connection closed');
  } catch (error) {
    console.error('Error closing Redis connection:', error);
  }
});

// Utility functions for common Redis operations
const redisUtils = {
  // Set a key with expiration
  setex: async (key, seconds, value) => {
    try {
      return await redisClient.setEx(key, seconds, JSON.stringify(value));
    } catch (error) {
      console.error('Redis SETEX error:', error);
      return null;
    }
  },

  // Get a key
  get: async (key) => {
    try {
      const value = await redisClient.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error('Redis GET error:', error);
      return null;
    }
  },

  // Delete a key
  del: async (key) => {
    try {
      return await redisClient.del(key);
    } catch (error) {
      console.error('Redis DEL error:', error);
      return 0;
    }
  },

  // Set a key without expiration
  set: async (key, value) => {
    try {
      return await redisClient.set(key, JSON.stringify(value));
    } catch (error) {
      console.error('Redis SET error:', error);
      return null;
    }
  },

  // Check if key exists
  exists: async (key) => {
    try {
      return await redisClient.exists(key);
    } catch (error) {
      console.error('Redis EXISTS error:', error);
      return 0;
    }
  },

  // Publish to a channel
  publish: async (channel, message) => {
    try {
      return await redisClient.publish(channel, JSON.stringify(message));
    } catch (error) {
      console.error('Redis PUBLISH error:', error);
      return 0;
    }
  }
};

module.exports = {
  redisClient,
  connectRedis,
  redisUtils
};
