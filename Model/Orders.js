const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const OrderSchema = new Schema({

    
    
  user: {
    type: Schema.Types.ObjectId,
    ref: 'user'
  },
    products:{type:Array, required:true},
    amount: { type: Number, required: true },
    adress: { type: Object, required: true },
    status: { type: String, default: "pending" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Order", OrderSchema);
