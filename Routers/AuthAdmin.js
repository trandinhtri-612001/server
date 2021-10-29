const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const AdUsers  = require('../Model/AdminUsers')
const verifyAdminToken = require('../meddleware/admin')

//get full adminuser
// api/auth/admin/find
router.get('/find', verifyAdminToken, async(req, res) => {
    

    try {
        
        const User = await AdUsers.find();
        if (!User) {
            return res.status(400).json({
                success: false,
                message: "user not file"
            })
        }
    
    res.json({ success: true, message: "find user success", user:User })
    } catch (error){
        console.log(error )
        res.status(500).json({
            success: false,
            message: 'internal server erro',
            error
        })
    }

    
   
})

//get  adminuser
//api/auth/admin/
router.get('/', verifyAdminToken, async(req, res) => {
    

    try {
        
        const User = await AdUsers.findOne({_id:req.userId});
        if (!User) {
            return res.status(400).json({
                success: false,
                message: "user not file"
            })
        }
    
        res.json({
            success: true,
            message: "find user success",
            user: User
        })
    } catch (error){
        console.log(error )
        res.status(500).json({
            success: false,
            message: 'internal server erro',
            error
        })
    }

    
   
})


// api/auth/admin/login
router.post('/login', async(req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "missing username or passwordl"
        });
        
    }
    try {
        const resUser = await AdUsers.findOne({ username: username });
        if (!resUser) {
            return res.status(400).json({
                success: false,
                message: "incorect username or password"
            });

        }
        const passwordValida = await argon2.verify(
            resUser.password,
            password
        );
        if (!passwordValida) {
            return res.status(400).json({
                success: false,
                message: "incorect username or password"
            })
        }
        // return jsonweb token
        const accessToken = await jwt.sign({
            userId: resUser._id
        }, process.env.ACCESS_TOKEN_SECRET)
        res.json({
            success: true,
            message: 'login successfully',
            accessToken
        })
    } catch (error) {
        console.log(error )
        res.status(500).json({
            success: false,
            message: 'internal server erro',
            error
        })
    }
    
})
 
// api/auth/admin/register
router.post('/register',verifyAdminToken, async (req, res) => {
    const { username, password, email, phonenumber } = req.body;
    if (!username || !password) 
        return res.status(400).json({
            success: false,
            message: "missing username or password"
        });

    
    try {
        const resUser = await AdUsers.findOne({ username: username });
        
        if (resUser) {
            return res.status(400).json({
                success: false,
                message: "Username already taken "
            });

        }
        // all good
        const hashpassword = await argon2.hash(password);
        const newuser = new AdUsers({
            username,
            password: hashpassword,
            email: email,
            phonenumber: phonenumber,
            isadmin:true
        });
        await newuser.save();
        //return accesstokent
        const accsessToken = await jwt.sign({ userId: newuser._id }, process.env.ACCESS_TOKEN_SECRET);

        res.json({
            success: true,
            message: 'account create success',
            accsessToken
        });

    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: 'internal server erro',
            error
        })
    }
})


// update adminuser
// api/auth/admin/:id
router.put('/:id', verifyAdminToken, async (req, res) => {
    const { username, password, email, phonenumber,isadmin } = req.body;

        if (!username || !password || !email || !phonenumber) {
        return res.status(400).json({
            success: false,
            message: "missing infor "
        })
                }
    try {
       
        const user = await AdUsers.findById({ _id: req.params.id});
        if (!user) {
           return res.status(400).json({
                success: false,
            message: 'Ad account not found'
            })
        }

        let key = user.username == username ? false : username ;
        const resuser = await AdUsers.findOne({ username: key });
        console.log(key)
        console.log(resuser)
        if (resuser) {
         return res.status(400).json({
                success: false,
            message: "username taken "
            })
        }
        
        const hashpassword = await argon2.hash(password)
        let AduserUpdate = {
            username,
            password:hashpassword,
            email,
            phonenumber,
            isadmin:isadmin,
            
        }
        const idAduser = {_id:req.params.id}

         AduserUpdate = await AdUsers.findOneAndUpdate(idAduser, AduserUpdate )
        res.json({
            success: true,
            message: "user update successfull",
            AduserUpdate
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
//api/auth/admin/:id
router.delete('/:id', verifyAdminToken, async (req, res) => {


    try {
        const aduser = await AdUsers.findOne({_id:req.params.id});
        if (!aduser) {
            res.status(400).json({
                success: false,
            message: 'account not found'
            })
        }
        const idAduser = {_id:req.params.id}
        const Aduserdelete = await AdUsers.findOneAndDelete(idAduser)
        if (!Aduserdelete) {
            return res.status(401).json({
                success: false,
                message: "ad user not found or user not authorised"
            })
        }
            res.status(200).json({
            success: true,
            message: "ad user delete successfull",
            Aduserdelete
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