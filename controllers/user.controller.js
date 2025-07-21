const multer = require('multer');
const sharp = require('sharp');
const User = require('../models/user.model');
const catchAsync = require('../utils/catch.async');
const AppError = require('../utils/app.error');
const factory = require('./handler.factory');
const crypto = require('crypto');
// const multerStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'public/img/users');
//   },
//   filename: (req, file, cb) => {
//     const ext = file.mimetype.split('/')[1];
//     cb(null, `user-${req.user.id}-${Date.now()}.${ext}`);
//   }
// });
const multerStorage = multer.memoryStorage();

const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Not an image! Please upload only images.', 400), false);
  }
};

const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter
});

exports.uploadUserPhoto = upload.single('photo');

exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next();

  req.file.filename = `user-${req.user.id}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat('jpeg')
    .jpeg({ quality: 90 })
    .toFile(`public/img/users/${req.file.filename}`);

  next();
});

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

exports.getMe = (req, res, next) => {
  req.params.id = req.user.id;
  next();
};

exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Create error if user POSTs password data
  if (req.body.password || req.body.confirmPassword) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updateMyPassword.',
        400
      )
    );
  }

  // 2) Filtered out unwanted fields names that are not allowed to be updated
  const filteredBody = filterObj(req.body, 'name', 'email');
  if (req.file) filteredBody.photo = req.file.filename;

  // 3) Update user document
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: 'success',
    data: null
  });
});



exports.createUser = catchAsync(async (req, res, next) => {
  // 1) Check if email already exists
  const existingUserByEmail = await User.findOne({ email: req.body.email });
  if (existingUserByEmail) {
    return next(
      new AppError(
        'This email is already registered. Please use a different email or log in.',
        409
      )
    );
  }

  // 2) Check if phone already exists (if provided)
  if (req.body.phone) {
    const existingUserByPhone = await User.findOne({ phone: req.body.phone });
    if (existingUserByPhone) {
      return next(
        new AppError(
          'This phone number is already registered. Please use a different phone number or log in.',
          409
        )
      );
    }
  }

  // 3) Generate random password if not provided
  const randomPassword =
    req.body.password ||
    crypto.randomBytes(6).toString('hex'); 

  // 4) Create new user
  const newUser = await User.create({
    fullName: req.body.fullName,
    email: req.body.email,
    phone: req.body.phone , 
    photo: req.file ? req.file.filename : 'default.jpg',
    role: req.body.role || 'user',
    password: randomPassword,
    googleId:null,
    confirmPassword: randomPassword,
    isProfileComplete: true,
    terms: req.body.terms ?? true,
  });

  // 5) Send welcome email with password (optional)
  try {
    await new Email(newUser, '').sendWelcome();
  } catch (err) {
    console.log('Welcome email failed, but user created successfully:', err);
  }

  // 6) Respond to admin
  res.status(201).json({
    status: 'success',
    data: {
      user: {
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        phone: newUser.phone,
        role: newUser.role,      },
    },
  });
});


exports.getUser = factory.getOne(User);
exports.getAllUsers = factory.getAll(User);

// Do NOT update passwords with this!
exports.updateUser = factory.updateOne(User);
exports.deleteUser = factory.deleteOne(User);
