const path = require('path');
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const compression = require('compression');
const cors = require('cors');

const AppError = require('./utils/app.error');
const globalErrorHandler = require('./controllers/error.controller');
const userRouter = require('./routes/user.routes');
const invoiceRouter = require('./routes/invoice.routes');

const dotenv = require('dotenv');
dotenv.config(); // Looks for .env in root

// Start express app
const app = express();

app.enable('trust proxy');

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

// 1) GLOBAL MIDDLEWARES
// Implement CORS
app.use(cors());
// Access-Control-Allow-Origin *
// api.natours.com, front-end natours.com
// app.use(cors({
//   origin: 'https://www.natours.com'
// }))

app.options('*', cors());
// app.use(cors({
//   origin: 'http://localhost:4200', 
//   credentials: true               
// }));
// app.options('/api/v1/tours/:id', cors());

// Serving static files
app.use(express.static(path.join(__dirname, 'public')));

// Set security HTTP headers
// app.use(
//   helmet.contentSecurityPolicy({
//     directives: {
//       defaultSrc: ["'self'"],
//       scriptSrc: ["'self'", "https://js.stripe.com"],
//       connectSrc: ["'self'", "https://js.stripe.com"],
//       frameSrc: ["'self'", "https://js.stripe.com"],
//       objectSrc: ["'none'"],
//       upgradeInsecureRequests: [],
//     },
//   })
// );


// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit requests from same API
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100,
//   standardHeaders: true,
//   legacyHeaders: false,
//   validateProxy: false, 
// });

// app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());



app.use(compression());

// Test middleware
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  // console.log(req.cookies);
  next();
});

// 3) ROUTES
app.use('/api/v1/users', userRouter);
app.use('/api/v1/invoice', invoiceRouter);
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
