const express = require("express");
const router =
	express.Router();
const verifyToken = require("../meddleware/auth");
const verifyAdminToken = require("../meddleware/admin");
const Carts = require("../Model/Carts");

// router.get('/', async(req, res) => {
//     res.json({success:true})
// })

//CREATE
// post
//api/cart/
router.post(
	"/",
	verifyToken,
	async (req, res) => {
		const {productid, image, title, color, size, price, quantity, score } =
			req.body;
		if (!productid || !image ||!title ||! color||!size||!price||!quantity||!score) {
			
			return res
				.status(400)
				.json({
					success: false,
					message:
						"missing product infomation",
				});
		}

		try {
			const newCart =
				new Carts({
					productid,
					image,
					title,
					color,
					size,
					price,
					quantity,
					score,
					user: req.userId,
				});

			const savedCart =
				await newCart.save();

			res.status(200).json({
				suceess: true,
				messsage:
					"save product success",
				savedCart,
			});
		} catch (err) {
			res.status(500).json({
				suceess: false,
				messsage:
					"internal server error",
				err,
			});
		}
	},
);

//UPDATE
//method put
//api/cart/:id
router.put(
	"/:id",
	verifyToken,
	async (req, res) => {
		const {
			color,
			size,
			quantity,
			score
			
		} = req.body;
		// if (
			
			
		// ) {
		// 	return res
		// 		.status(400)
		// 		.json({
		// 			success: false,
		// 			message:
		// 				"missing product infomation",
		// 		});
		// }
		try {
			let dataCartUpdate = {
				color,
				size,
				quantity,
				score
				
			};

			const updatedCart =
				await Carts.findByIdAndUpdate(
					 req.params.id,
					dataCartUpdate,
					{ new: true },
				);
			res.status(200).json({
				success: true,
				messsage:
					"update product success",
				updatedCart,
			});
		} catch (err) {
			console.log(err);
			res.status(500).json({
				suceess: false,
				messsage:
					"internal server error",
			});
		}
	},
);

//DELETE
//delete
//api/cart/:id
router.delete(
	"/:id",
	verifyToken,
	async (req, res) => {
		try {
			
			const product =
				await Carts.findOne(
					{ _id:req.params.id, user:req.userId}
				);
			if (!product) {
				return res
					.status(400)
					.json({
						success: false,
						message:
							"product not found",
					});
			}
			if (
				req.userId !=
				product.user
			) {
				return res
					.status(400)
					.json({
						success: false,
						message:
							"fucking, you not hacking me app",
					});
			}
			
			const resdeletproduct =
				await Carts.findOneAndDelete(
					{
						_id: req.params
							.id
					},
				);
			if (!resdeletproduct) {
				return res
					.status(400)
					.json({
						success: false,
						message:
							"it not delete found",
					});
			}

			res.status(200).json({
				success: true,
				message:
					"Cart has been deleted... success",
				resdeletproduct,
			});
		} catch (err) {
			console.log(err);
			res.status(500).json({
				suceess: false,
				messsage:
					"internal server error",
			});
		}
	},
);

//GET USER CART
//method get
//api/cart/find/
router.get(
	"/find",
	verifyToken,
	async (req, res) => {
		try {
			const rescart =
				await Carts.find({
					user: req.userId,
				});
			res.status(200).json({
				success: true,
				message:
					"get product cart success",
				rescart,
			});
		} catch (err) {
			res.status(500).json({
				suceess: false,
				messsage:
					"internal server error",
			});
		}
	},
);

// //GET ALL

router.get(
	"/",
	verifyAdminToken,
	async (req, res) => {
		try {
			const rescarts =
				await Carts.find().populate(
					{
						path: "user",
						select:
							"username",
					},
				);
			res.status(200).json({
				success: true,
				message:
					"get product cart success",
				rescarts,
			});
		} catch (err) {
			res
				.status(500)
				.json(err);
		}
	},
);

module.exports = router;

module.exports = router;
