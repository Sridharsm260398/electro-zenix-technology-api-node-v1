const multer = require('multer');
const sharp = require('sharp');
const Invoice = require('../models/invoice.model');
const catchAsync = require('../utils/catch.async');
const AppError = require('../utils/app.error');
const factory = require('./handler.factory');


    // assuming you already have this

//  Create new invoice
exports.createInvoice = catchAsync(async (req, res, next) => {
  const invoice = await Invoice.create(req.body);
  res.status(201).json({
    status: 'success',
    data: { invoice }
  });
});

//  Get all invoices
exports.getAllInvoices = catchAsync(async (req, res, next) => {
  const invoices = await Invoice.find();
  res.status(200).json({
    status: 'success',
    results: invoices.length,
    data: { invoices }
  });
});

//  Get single invoice (by id)
exports.getInvoice = catchAsync(async (req, res, next) => {
  const invoice = await Invoice.findOne({ id: req.params.id });

  if (!invoice) {
    return next(new AppError('No invoice found with that number', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { invoice }
  });
});

//  Update invoice
exports.updateInvoice = catchAsync(async (req, res, next) => {
  const updatedInvoice = await Invoice.findOneAndUpdate(
    { id: req.params.id },
    req.body,
    { new: true, runValidators: true }
  );

  if (!updatedInvoice) {
    return next(new AppError('No invoice found with that number', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { invoice: updatedInvoice }
  });
});

//  Delete invoice
exports.deleteInvoice = catchAsync(async (req, res, next) => {
  const deleted = await Invoice.findOneAndDelete({ id: req.params.id });

  if (!deleted) {
    return next(new AppError('No invoice found with that number', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null
  });
});
