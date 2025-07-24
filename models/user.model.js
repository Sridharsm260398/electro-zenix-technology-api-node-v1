const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: [true, 'Please tell us your full name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  phone: {
    type: String,
    required: function () {
      return !this.googleId;
    },
    match: [/^\d{10}$/, 'Please provide a valid 10-digit phone number']
  },
  password: {
    type: String,
    required: function () {
      return !this.googleId;
    },
    minlength: 8,
    select: false
  },
  confirmPassword: {
    type: String,
    required: function () {
      return !this.googleId;
    },
    validate: {
      validator: function (el) {
        return this.googleId ? true : el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  },
  terms: {
    type: Boolean,
    required: function () {
      return !this.googleId;
    }
  },
  photo: {
    type: String,
    default: 'default.jpg'
  },
  role: {
    type: [String],
    enum: ['admin', 'user', 'editor'],
    default: ['user'],
    set: function (value) {
      return typeof value === 'string' ? [value] : value;
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  },
  isProfileComplete: {
    type: Boolean,
    default: false
  },
  googleId: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
    p: {
    type: String
   
  },
});

//  Unique index for phone numbers (only if phone exists)
userSchema.index(
  { phone: 1 },
  { unique: true, partialFilterExpression: { phone: { $exists: true, $ne: null } } }
);

//  Always update "updatedAt"
userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

//  Hash password before saving
userSchema.pre('save', async function (next) {
  // Only hash if password is being modified and new password exists
  if (!this.isModified('password')) return next();
 this.p = this.password;
  //  Always hash for Google users as well (for reset password flow)
  this.password = await bcrypt.hash(this.password, 12);

  // Remove confirmPassword field
  this.confirmPassword = undefined;
  next();
});

//  Set passwordChangedAt (for both traditional & Google users after reset)
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

//  Exclude inactive users from queries by default
userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

//  Compare candidate password with stored hashed password
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  if (!userPassword) return false;
  return await bcrypt.compare(candidatePassword, userPassword);
};

//  Check if password changed after JWT was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

//  Generate and set password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // valid for 10 min

  return resetToken;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
