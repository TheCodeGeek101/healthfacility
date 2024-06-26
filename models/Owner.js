// models/Owner.js
const mongoose = require('mongoose');

const ownerSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
});

module.exports = mongoose.model('Owner', ownerSchema);
