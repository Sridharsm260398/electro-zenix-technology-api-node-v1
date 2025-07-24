const mongoose = require('mongoose');
const dotenv = require('dotenv');

process.on('uncaughtException', err => {
  console.error('UNCAUGHT EXCEPTION Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});

dotenv.config(); // Looks for .env in root

const app = require('./app');

const DB = process.env.MONGO_URI;

if (!DB) {
  console.error('MONGO_URI not defined in .env');
  process.exit(1);
}

// Connect to MongoDB
mongoose
  .connect(DB)
  .then(() => console.log('MongoDB connection successful'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

//  Start server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`App running on port ${PORT}...`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', err => {
  console.error('UNHANDLED REJECTION Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

//Handle process termination (e.g. for Render or Railway)
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated!');
  });
});
