 
const mongoose = require('mongoose');

const InvoiceSchema = new mongoose.Schema({
  id: String,
  invoiceDate: Date,
  dueDate: Date,
  terms: String,
  poNo: String,
  placeOfSupply: String,
  billTo: String,
  items: [
    {
      description: String,
      hsn: String,
      qty: Number,
      rate: Number,
      cgst: Number,
      sgst: Number
    }
  ],
  paymentMade: Number,
  notes: String,
  company: {
    name: String,
    address: String,
    gst: String,
    contact: String,
    email: String
  },
  subTotal: Number,
  cgstTotal: Number,
  sgstTotal: Number,
  total: Number,
  balanceDue: Number
});

module.exports = mongoose.model('Invoice', InvoiceSchema);
