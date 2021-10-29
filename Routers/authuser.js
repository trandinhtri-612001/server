const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const Users = require('../Model/user');
const verifyToken = require('../meddleware/auth');
const verifyAdminToken  = require('../meddleware/admin')


//GET USER
//api/auth
router.get('/', verifyToken, async (req, res) => {
  try {
    const user = await Users.findOne({_id:req.userId});
      if (!user) {
     return res.status(200).json({
           success: false,
          message: " user not foud "
        
    })
      }
      
      res.status(200).json({
           success: true,
          message: "get user success ",
            user:user
        
    });
  } catch (err) {
    res.status(500).json(err);
  }
});

//GET ALL USER
//api/auth/find
router.get('/find', verifyAdminToken, async (req, res) => {
  const query = req.query.new;
  try {
    const users = query
      ? await Users.find().sort({ _id: -1 }).limit(10)
      : await Users.find();
      res.status(200).json({
           success: true,
          message: "get all user success ",
            users
      });
  } catch (err) {
    res.status(500).json(err);
  }
});

//create user
//api/auth/register

router.post('/register', async(req, res) => {
    const { username, password, email, phonenumber } = req.body;
    if (!username || !password || !email || !phonenumber) {
        return res.status(400).json({
            success: false,
            message: "missing infor "
        });

    }
    try {
        const resuser = await Users.findOne({ username: username });
        if (resuser) {
            return res.status(400).json({
                success: false,
            message: "username taken "
            })
        }
        const hashpassword = await argon2.hash(password);
        const newuser = new Users({
             username,
            password: hashpassword,
            email: email,
            phonenumber: phonenumber,
            adress:''
        })
        await newuser.save();
        const accessToken = await jwt.sign(
            { userId: newuser._id },
            process.env.ACCESS_TOKEN_SECRET);

        res.json({
            success: true,
            message: " create account success ",
            accessToken

        })
    } catch (error) {
           console.log(error)
            res.status(500).json({
            success: false,
             message: 'internal server erro',
            error
        })
    }
})
 

// login user
 //api/auth/login

router.post('/login', async (req, res) => {
    const { username,password } = req.body;
    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message:"missing username or password"
        })
    }
    try {
        const user = await Users.findOne({ username: username });
        if (!user) {
             return res.status(400).json({
            success: false,
            message:"incorrect username or password"
        })
        }
        const verifyPassword = await argon2.verify(
            user.password,
            password
        );
        if (!verifyPassword) {
            return res.status(401).json({
                success: false,
                message: "incorrect username or password"
            })
        }
        const accsessToken = await jwt.sign(
            { userId: user._id },
            process.env.ACCESS_TOKEN_SECRET
        )
        res.json({
            success: true,
            message: 'login successfull',
            accsessToken
    })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            
            success: false,
            message: 'internal server error',
            error
        })
    }
})
 
// update user
// api/auth/:id
router.put('/:id', verifyToken, async (req, res) => {
    const { username, password, email, phonenumber, adress,oldpassword } = req.body;
        if (!username || !password || !email || !phonenumber) {
        return res.status(400).json({
            success: false,
            message: "missing infor "
        })
                }
    try {
       
        const user = await Users.findById({ _id: req.params.id});
        if (!user) {
           return res.status(400).json({
                success: false,
            message: 'account not found'
            })
        }

        const resuser = await Users.findOne({ username: username })
        if (resuser) {
         return res.status(400).json({
                success: false,
            message: "username taken "
            })
        }
        const verifyPassword = await argon2.verify(user.password, oldpassword);
        if (!verifyPassword) {
           return res.status(400).json({
                success: false,
            message: 'old password incorrect'
            })
        }
        const hashpassword = await argon2.hash(password)
        let userUpdate = {
            username,
            password:hashpassword,
            email,
            phonenumber,
            adress:adress
        }
        const iduser = {_id:req.params.id}

         userUpdate = await Users.findOneAndUpdate(iduser, userUpdate )
        res.json({
            success: true,
            message: "user update successfull",
            userUpdate
        })
                    

     } catch (error) {
                
       console.log(error)
        res.status(500).json({
             success: false,
            message: 'internal server error',
            error

        })
            }


    
})

//delete user
//api/auth/
router.delete('/:id', verifyToken, async (req, res) => {


    try {
        const user = await Users.findOne({_id:req.params.id});
        if (!user) {
            res.status(400).json({
                success: false,
            message: 'account not found'
            })
        }
        const iduser = {_id:req.params.id}
        const userdelete = await Users.findOneAndDelete(iduser)
        if (!userdelete) {
            return res.status(401).json({
                success: false,
                message: "user not found or user not authorised"
            })
        }
            res.status(200).json({
            success: true,
            message: "user delete successfull",
            userdelete
            })
        
    } catch (error) {
               console.log(error)
        res.status(500).json({
             success: false,
            message: 'internal server error',
            error

        })
    }
    
    
})


module.exports = router;
