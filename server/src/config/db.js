import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/possessed_butler';

let isConnected = false;

export async function connectDB() {
  if (isConnected) return;

  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 4000,
      connectTimeoutMS: 5000,
    });
    isConnected = true;
    console.log(`[Database] MongoDB connected successfully to ${conn.connection.host}/${conn.connection.name}`);
  } catch (err) {
    console.warn(`[Database] MongoDB connection warning: ${err.message}. Operating with fallback persistent in-memory layer.`);
    isConnected = false;
  }
}

export function getDBStatus() {
  return {
    connected: isConnected && mongoose.connection.readyState === 1,
    host: mongoose.connection?.host || 'local',
    name: mongoose.connection?.name || 'possessed_butler'
  };
}
