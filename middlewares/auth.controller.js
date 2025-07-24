const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const catchAsync = require('../utils/catch.async');
const AppError = require('../utils/app.error');
const Email = require('../utils/email');

const otpStore = new Map();

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id);

const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure: req.secure || req.headers['x-forwarded-proto'] === 'https', // For HTTPS in production
    };

    res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    statusCode,
    expiresIn:3600,
    status: 'success',
    token,
    data: { user }
  });
};


exports.signup = catchAsync(async (req, res, next) => {
  // 1) Check if email already exists
  const existingUserByEmail = await User.findOne({ email: req.body.email });
  if (existingUserByEmail) {
    return next(new AppError('This email is already registered. Please use a different email or log in.', 409)); // 409 Conflict
  }

  // 2) Check if phone number already exists (if provided)
  if (req.body.phone) {
    const existingUserByPhone = await User.findOne({ phone: req.body.phone });
    if (existingUserByPhone) {
      return next(new AppError('This phone number is already registered. Please use a different phone number or log in.', 409)); // 409 Conflict
    }
  }

  // Create new user
  const newUser = await User.create({
    fullName: req.body.fullName,
    email: req.body.email,
    phone: req.body.phone,
    photo: req.file ? req.file.filename : undefined,
    role: req.body.role || 'user', // Default to 'user' if not provided
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    isProfileComplete :true,
    terms: req.body.terms || false // Default to false if not provided
  });

  // Send welcome email
  await new Email(newUser, '').sendWelcome(); // Assuming Email class and sendWelcome method

  // Create and send token
  createSendToken(newUser, 201, req, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body; // 'email' field can also contain phone number for login

  // 1) Check if email/phone and password are provided
  if (!email || !password) {
    return next(new AppError('Please provide your email/phone and password!', 400));
  }

  const user = await User.findOne({
    $or: [{ email }, { phone: email }] // Allows login with either email or phone
  }).select('+password');

  // console.log(user); // Keep for debugging if needed

  // 3) Check if user exists and password is correct
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email/phone or password. Please try again.', 401)); // 401 Unauthorized
  }

  // 4) If everything is ok, send token to client
  createSendToken(user, 200, req, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email/phone and password!', 400));
  }

  const user = await User.findOne({
    $or: [{ email }, { phone: email }]
  }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email/phone or password', 401));
  }

  createSendToken(user, 200, req, res);
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
};

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log in to get access.', 401));
  }

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user belonging to this token does no longer exist.', 401));
  }

  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('User recently changed password! Please log in again.', 401));
  }

  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});

exports.isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);

      const currentUser = await User.findById(decoded.id);
      if (!currentUser || currentUser.changedPasswordAfter(decoded.iat)) {
        return next();
      }

      res.locals.user = currentUser;
      return next();
    } catch (err) {
      return next();
    }
  }
  next();
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({
    $or: [{ email: req.body.email }, { phone: req.body.email }]
  });
  if (!user) {
    return next(new AppError('There is no user with this contact.', 404));
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  try {
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/reset-password/${resetToken}`;
    //await new Email(user, resetURL).sendPasswordReset();

    res.status(200).json({ status: 'success', message: 'Token sent to contact!', resetToken: resetToken });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the token. Try again later!', 500));
  }
});

// exports.resetPassword = catchAsync(async (req, res, next) => {
//   const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

//   const user = await User.findOne({
//     passwordResetToken: hashedToken,
//     passwordResetExpires: { $gt: Date.now() }
//   });

//   if (!user) {
//     return next(new AppError('Token is invalid or has expired', 400));
//   }
// console.log(req.body)
//   user.password = req.body.newPassword;
//   user.confirmPassword = req.body.confirmPassword;
//   user.passwordResetToken = undefined;
//   user.passwordResetExpires = undefined;
//   await user.save();

//   createSendToken(user, 200, req, res);
// });


exports.resetPassword = catchAsync(async (req, res, next) => {
  const { contact, newPassword, confirmPassword } = req.body;
  const token = req.params.token;

  // Validate required fields
  if (!contact || !newPassword || !confirmPassword || !token) {
    return next(new AppError('All fields and token are required', 400));
  }

  if (newPassword !== confirmPassword) {
    return next(new AppError('Passwords do not match', 400));
  }

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const userByToken = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!userByToken) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  // Ensure the contact also matches the user
  const isEmail = contact.includes('@');
  const query = isEmail ? { email: contact } : { phone: contact };

  const userByContact = await User.findOne(query).select('+password');

  if (!userByContact || userByContact.id !== userByToken.id) {
    return next(new AppError('User mismatch or not found with this contact', 404));
  }

  // Prevent using same password again
  const isSame = await userByContact.correctPassword(newPassword, userByContact.password);
  if (isSame) {
    return next(new AppError('New password cannot be same as old password', 400));
  }

  // All checks passed, update password
  userByContact.password = newPassword;
  userByContact.confirmPassword = confirmPassword;
  userByContact.passwordResetToken = undefined;
  userByContact.passwordResetExpires = undefined;
  await userByContact.save();

  res.status(200).json({
    status: 'success',
    message: 'Password updated successfully. Please log in.',
  });
});



exports.updatePassword = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  await user.save();

  createSendToken(user, 200, req, res);
});


// controllers/authController.js or userController.js

// exports.updatePassword = catchAsync(async (req, res, next) => {
//   const user = await User.findById(req.user.id).select('+password');

//   if (!user) {
//     return next(new AppError('User not found', 404));
//   }

//   const { password, confirmPassword } = req.body;

//   // Validate presence
//   if (!password || !confirmPassword) {
//     return next(new AppError('Please provide both new and confirm password', 400));
//   }

//   // Check if passwords match
//   if (password !== confirmPassword) {
//     return next(new AppError('Passwords do not match', 400));
//   }

//   // Prevent reusing old password
//   const isSame = await user.correctPassword(password, user.password);
//   if (isSame) {
//     return next(new AppError('New password must be different from current password', 400));
//   }

//   // Update and save
//   user.password = password;
//   user.confirmPassword = confirmPassword;
//   await user.save();

//   // Optionally: re-login user with new token
//   createSendToken(user, 200, req, res);
// });

exports.sendOtp = catchAsync(async (req, res, next) => {
  const { contact } = req.body;
  if (!contact) return next(new AppError('Please provide email or phone', 400));

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(contact, otp);

  res.status(200).json({
    status: 'success',
    message: 'OTP sent successfully!',
    otp
  });
});

exports.verifyOtp = catchAsync(async (req, res, next) => {
  const { contact, otp } = req.body;
  if (!contact || !otp) {
    return next(new AppError('Please provide contact and OTP', 400));
  }

  const storedOtp = otpStore.get(contact);
  if (!storedOtp || storedOtp !== otp) {
    return next(new AppError('Invalid or expired OTP', 401));
  }

  otpStore.delete(contact);

  const user = await User.findOne({
    $or: [{ email: contact }, { phone: contact }]
  });

  if (!user) {
    return next(new AppError('No user found with this contact', 404));
  }

  createSendToken(user, 200, req, res);
});




// --- Google Sign-Up (for the /register route) ---
exports.googleSignUp = catchAsync(async (req, res, next) => {
    const { token: idToken } = req.body; // Renamed 'token' to 'idToken' for clarity

    if (!idToken) {
        return next(new AppError('Google ID token is required.', 400));
    }

    const ticket = await client.verifyIdToken({
        idToken: idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    if (!email) {
        return next(new AppError('Google signup failed. No email found in token.', 400));
    }

    // 1. Check if user already exists by email or googleId
    let user = await User.findOne({ $or: [{ email }, { googleId }] });

    if (user) {
        // If user already exists:
        // Case A: User exists with this email (traditional signup) but no googleId
        if (!user.googleId) {
            // Link the Google account to the existing traditional account
            user.googleId = googleId;
            if (!user.fullName) user.fullName = name;
            if (!user.photo) user.photo = picture;
            await user.save({ validateBeforeSave: false }); // Skip validation for password/phone if not present
            // Treat this as a successful sign-in after linking
            return createSendToken(user, 200, req, res);
        }
        // Case B: User already exists with this googleId (or email linked to a different googleId)
        // This means they are trying to sign up again or email is already linked to another Google account.
        return next(new AppError('An account with this Google account or email already exists. Please sign in instead.', 409));
    }

    // 2. If user does NOT exist, create a new user (Google signup)
    const newUser = await User.create({
        fullName: name,
        email,
        photo: picture,
        googleId,
        password: crypto.randomBytes(16).toString('hex'), // Generate a random placeholder password
        // confirmPassword: crypto.randomBytes(16).toString('hex'), // Not strictly needed if password is not used for login
        role: 'user',
        terms: true, // Assuming terms are accepted by using Google signup
        isProfileComplete: false, // Phone number is missing, so profile is incomplete
    });

    // Send token. Frontend will check `isProfileComplete`
    createSendToken(newUser, 201, req, res); // 201 Created for new resource
});

// --- Google Sign-In (for the /login route) ---
exports.googleSignIn = catchAsync(async (req, res, next) => {
    const { token: idToken } = req.body; // Renamed 'token' to 'idToken' for clarity

    if (!idToken) {
        return next(new AppError('Google ID token is required.', 400));
    }

    const ticket = await client.verifyIdToken({
        idToken: idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    if (!email) {
        return next(new AppError('Google login failed. No email found in token.', 400));
    }

    // 1. Find user by googleId or email
    let user = await User.findOne({ $or: [{ googleId }, { email }] });

    if (!user) {
        // If user not found, they need to register first
        return next(new AppError('No account found with this Google ID or email. Please register first.', 404));
    }

    // 2. If user exists:
    // Case A: User exists by email but doesn't have googleId (traditional user signing in with Google for first time)
    if (!user.googleId && user.email === email) {
        user.googleId = googleId;
        if (!user.fullName) user.fullName = name;
        if (!user.photo) user.photo = picture;
        await user.save({ validateBeforeSave: false }); // Skip validation for password/phone if not present
    }
    // Case B: User exists with googleId, ensure it matches (standard Google sign-in)
    else if (user.googleId && user.googleId !== googleId) {
        // This is an edge case: email exists, but linked to a different googleId or
        // the same email is trying to sign in with a different Google account.
        // You might want to prompt for account linking or throw a specific error.
        return next(new AppError('This email is already associated with a different Google account. Please use the correct Google account or sign in traditionally.', 409));
    }

    // Send token. Frontend will check `isProfileComplete`
    createSendToken(user, 200, req, res);
});
// --- Unified Google Auth (for /google-auth route) ---
exports.googleAuth = catchAsync(async (req, res, next) => {
    const { token: idToken } = req.body;

    if (!idToken) {
        return next(new AppError('Google ID token is required.', 400));
    }

    const ticket = await client.verifyIdToken({
        idToken: idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    if (!email) {
        return next(new AppError('Google authentication failed. No email found in token.', 400));
    }

    let user = await User.findOne({ $or: [{ googleId }, { email }] });

    if (user) {
        if (!user.googleId) {
            user.googleId = googleId;
            if (!user.fullName) user.fullName = name;
            if (!user.photo) user.photo = picture;
            await user.save({ validateBeforeSave: false });
        }
        else if (user.googleId !== googleId) {
            return next(
                new AppError(
                    'This email is already associated with a different Google account. Please use the correct account or sign in traditionally.',
                    409
                )
            );
        }

        return createSendToken(user, 200, req, res);
    }

    const newUser = await User.create({
        fullName: name,
        email,
        photo: picture,
        googleId,
        password: crypto.randomBytes(16).toString('hex'), 
        role: 'user',
        terms: true,
        isProfileComplete: false,
    });

    return createSendToken(newUser, 201, req, res);
});

// --- Endpoint to complete profile (e.g., add phone number) ---
exports.completeProfile = catchAsync(async (req, res, next) => {
    // This route should be protected by your authentication middleware
    // req.user will be populated by the middleware from the JWT token
    const userId = req.user.id; // Assuming your JWT payload has 'id'
    const { phone } = req.body;

    if (!phone) {
        return next(new AppError('Phone number is required to complete your profile.', 400));
    }

    // Validate phone format if needed
    // if (!isValidPhoneNumber(phone)) { return next(new AppError('Invalid phone number format.', 400)); }

    try {
        // Check if this phone number is already taken by another user
        const existingUserWithPhone = await User.findOne({ phone });
        if (existingUserWithPhone && existingUserWithPhone._id.toString() !== userId) {
            return next(new AppError('This phone number is already registered to another account.', 409));
        }

        const user = await User.findById(userId);
        if (!user) {
            return next(new AppError('User not found.', 404));
        }

        user.phone = phone;
        user.isProfileComplete = true; // Mark profile as complete

        await user.save(); // Mongoose will validate the phone number uniqueness here

        // Re-issue token with updated `isProfileComplete` status
        createSendToken(user, 200, req, res);

    } catch (error) {
        // Handle Mongoose unique validation error for phone if it occurs here
        if (error.code === 11000) { // Duplicate key error
            return next(new AppError('This phone number is already registered to another account.', 409));
        }
        console.error('Error completing profile:', error);
        return next(new AppError('Failed to update profile. Please try again.', 500));
    }
});
