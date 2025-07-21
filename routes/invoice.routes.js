const express = require('express');
const invoiceController = require('../controllers/invoice.controller');
const authController = require('./../middlewares/auth.controller');
const router = express.Router();
//router.use(authController.protect);
// Routes for Invoices (Admin or User)
router
  .route('/')
  .get(invoiceController.getAllInvoices)   // GET all invoices
  .post(invoiceController.createInvoice);  // Create new invoice

router
  .route('/:id')
  .get(invoiceController.getInvoice)       // Get single invoice by id
  .patch(invoiceController.updateInvoice)  // Update existing invoice
  .delete(invoiceController.deleteInvoice);// Delete invoice

module.exports = router;
