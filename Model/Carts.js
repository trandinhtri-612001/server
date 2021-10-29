const mongoose = require("mongoose");
const Schema =
	mongoose.Schema;

const CartSchema = new Schema(
	{
		productid: { type: String, required: true },
		image: { type: String, required: true },
		title: { type: String, required: true },
		color: { type: String, required: true },
		size: { type: String, required: true },
		price: { type: String, required: true },
		quantity: { type: Number, required: true },
		score: {type:Number, required:true},
		user: {
			type: Schema.Types
				.ObjectId,
			ref: "user",
		},
		createdAt: {
			type: Date,
			default: Date.now,
		},
	},
);

module.exports =
	mongoose.model(
		"Carts",
		CartSchema,
	);
