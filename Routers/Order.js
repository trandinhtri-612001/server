const express = require('express');
const router = express.Router();
const verifyToken = require('../meddleware/auth');
const verifyAdminToken = require('../meddleware/admin')
const Orders = require('../Model/Orders');




//CREATE
// post
//api/cart/order
router.post('/', verifyToken, async (req, res) => {
    const {products, adress,amount } = req.body;
    if (!products || !adress ||!amount) {
        return res.status(400).json({
            success: false,
            message:"you missing product or adress"
        })
    }
    try {
        const newOrder = new Orders({
          user:req.userId,
          products,
          adress,
           amount    
  });
    const savedOrder = await newOrder.save();
      res.status(200).json({
          success: true,
          message: "create order successfull",
          savedOrder
          
    });
  } catch (err) {
        res.status(500).json({
            success: false,
            message: "internal server error",
            err
    });
  }
});

//UPDATE
router.put("/:id", verifyAdminToken, async (req, res) => {
    const { amount, adress, status } = req.body;
    if (!amount || !adress || !status) {
         return res.status(400).json({
            success: false,
            message: "missing infor update",
            
    });
    }
    try {
        let data = {
            amount,
            adress,
            status
      }
    const updatedOrder = await Orders.findByIdAndUpdate(
        req.params.id,
        data,
      { new: true }
    );
     res.status(200).json({
          suceess: true,
          messsage: "update order success",
          updatedOrder
    });
  } catch (err) {
    res.status(500).json(err);
  }
});

//DELETE
router.delete("/:id", verifyAdminToken, async (req, res) => {
    try {
        const resorder = await Orders.findById(req.params.id);
        if (!resorder) {
            return res.status(400).json({
            success: false,
            message:"order not found"
        })
        }
      const redeleteorder = await Orders.findByIdAndDelete(req.params.id);
      
      if (!redeleteorder) {
          return res.status(400).json({
            success: false,
            message:"do not delete"
        })
      }
    res.status(200).json({
            success: true,
            message: "delete order success",
            redeleteorder
        });
    } catch (err) {
        console.log(err)
     return res.status(401).json({
            success: false,
         message: "internal server error",
            err
        })
  }
});

//GET USER ORDERS
router.get("/find/:userId", verifyToken, async (req, res) => {
  try {
    const orders = await Orders.find({ userId: req.params.userId });
    res.status(200).json(orders);
  } catch (err) {
    res.status(500).json(err);
  }
});

 //GET ALL

router.get("/", verifyAdminToken, async (req, res) => {
  try {
    const resdeleteorder = await Orders.find();
      res.status(200).json({
            success: true,
            message: "get full order success",
            resdeleteorder
        
    });
  } catch (err) {
    return res.status(401).json({
            success: false,
            message:"internal server error"
        })
  }
});

// // GET MONTHLY INCOME

// router.get("/income", verifyTokenAndAdmin, async (req, res) => {
//   const productId = req.query.pid;
//   const date = new Date();
//   const lastMonth = new Date(date.setMonth(date.getMonth() - 1));
//   const previousMonth = new Date(new Date().setMonth(lastMonth.getMonth() - 1));

//   try {
//     const income = await Order.aggregate([
//       {
//         $match: {
//           createdAt: { $gte: previousMonth },
//           ...(productId && {
//             products: { $elemMatch: { productId } },
//           }),
//         },
//       },
//       {
//         $project: {
//           month: { $month: "$createdAt" },
//           sales: "$amount",
//         },
//       },
//       {
//         $group: {
//           _id: "$month",
//           total: { $sum: "$sales" },
//         },
//       },
//     ]);
//     res.status(200).json(income);
//   } catch (err) {
//     res.status(500).json(err);
//   }
// });

module.exports = router;