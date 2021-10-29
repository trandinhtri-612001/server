const express = require('express');
const router = express.Router();
const verifyAdminToken = require('../meddleware/admin')
const Posts = require('../Model/Posts');




// router.post('/', (req, res) => {
//     res.json({ success: false, message: 'missing product infomation' });
// })
// create post product
//api/post
router.post('/', verifyAdminToken, async (req, res) => {
    const { title, description, image, category, status, price } = req.body;
    if (!title || !description || !image || !category || !status || !price) {
        return res.status(400).json({
            success: false,
            message: 'missing product infomation'
        });

    }
    try {
        const respost = await Posts.findOne({ title: title });
        if (respost) {
            return res.status(400).json({
                success: false,
                message: 'product it taked'
            })

        }
        const newPost = new Posts({
            title: title,
            description,
            image,
            category,
            status,
            price,
            user:req.userId
        })
        await newPost.save();
        res.json({
            success: true,
            message: 'product creat successful',
            newPost
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: 'Internal server error'
            
        })
    }
    
})
//get full product
//api/post
router.get('/', async(req, res) => {
    const querym = req.query.m;
    try {
      let resfullPost 
        if (querym) {
            console.log(querym)
            resfullPost = await Posts.find().sort('price').limit(8);
            
        } else {
            resfullPost = await Posts.find()
        }
        
        
        res.json({
            success: true,
            message: "full posts find success",
            resfullPost
        })
        
    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        })
    }
})
// get product findone
//api/post/find/:id
router.get('/find/:id', async(req, res) => {
    
    try {
        
        const resPost = await Posts.findOne({ _id: req.params.id });
        
        if (!resPost) {
           return res.status(400).json({
            success: false,
            message: " posts  not found",
            resPost
           })
            
        }
         res.json({
            success: true,
            message: "get posts find success",
            resPost
        })
        
    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        })
    }
})

// update post
//api/post/id
router.put('/:id',verifyAdminToken, async (req, res) => {
    const { title, description, image, category, status, price } = req.body;
    if (!title || !description || !image || !category || !status || !price) {
        return res.status(400).json({
            success: false,
            message: 'missing product infomation'
        });

    }
    try {
        const resPost = await Posts.findOne({ title: title });
        if (resPost) {
            return res.status(400).json({
                success: false,
                message: 'product it taked'
            });

        }
        let dataPostUpdate = {
            title: title,
            description,
            image,
            category,
            status,
            price
            
        }
        const updateCondition = { _id: req.params.id };
        const resupdatepost = await Posts.findByIdAndUpdate(
            updateCondition,
            dataPostUpdate,
            { new: true }
        )
        if (!resupdatepost) {
            return res.status(401).json({
				success: false,
				message: 'Product/post not found or user not authorised'
			})
        }
        console.log(resupdatepost)
        res.json({
            success: true,
            message: "post update sucessfylly",
            resupdatepost
    
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        })
    }

})
 
//delete product
//api/post/id
router.delete('/:id',verifyAdminToken, async (req, res) => {
    try {
          const updateCondition = { _id: req.params.id };
    const respost = await Posts.findByIdAndDelete(updateCondition);
    if (!respost) {
        return res.status(401).json({
            success: false,
            message: "product/post not found or user not authorised"
        });

        }
        res.json({
            success: true,
            message: "product/post delete successfull",
            respost
        });

    } catch (error) {
        
    }
  
})















module.exports = router;