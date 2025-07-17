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
    unique: true, // Email should still be unique for all users
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  phone: {
    type: String,
    // REMOVED unique: true and sparse: true from here.
    // The unique constraint for non-null phone numbers will be handled by a separate index definition below.
    required: function () {
      // Phone is required if it's not a Google-signed-up user
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
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  },
  isProfileComplete: { // Crucial flag for phone number completion
    type: Boolean,
    default: false,
  },
  googleId: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  }

});

// --- IMPORTANT: Define the unique index for 'phone' with partialFilterExpression here ---
// This index ensures uniqueness only for documents where 'phone' exists and is not null.
// This replaces the 'unique: true, sparse: true' directly in the schema field.
userSchema.index(
  { phone: 1 }, // Index on the phone field (ascending order)
  {
    unique: true,
    partialFilterExpression: { phone: { $exists: true, $ne: null } }
  }
);


userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});
// Hash password before saving
userSchema.pre('save', async function (next) {
  // Only hash password if it's being modified and it's not a Google login (where password might be absent)
  if (!this.isModified('password') || this.googleId) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.confirmPassword = undefined; // remove confirmPassword field
  next();
});

// Set passwordChangedAt
userSchema.pre('save', function (next) {
  // Only update passwordChangedAt if password was modified and it's not a new document
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Exclude inactive users from find queries
userSchema.pre(/^find/, function (next) {
  // 'this' refers to the query object
  this.find({ active: { $ne: false } });
  next();
});

// Compare entered password with hashed password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  // Ensure userPassword exists before comparing
  if (!userPassword) return false;
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if password was changed after token issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

// Generate reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // Token expires in 10 minutes

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
