const jwt = require('jsonwebtoken')
const AdUser = require('../Model/AdminUsers')
const verifyToken = (req, res, next) => {
	const authHeader = req.header('Authorization')
	const token = authHeader && authHeader.split(' ')[1]

	if (!token)
		return res
			.status(401)
			.json({ success: false, message: 'Access token not found' })

	try {
		const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        req.userId = decoded.userId
        
		next();
	} catch (error) {
		console.log(error)
		return res.status(403).json({ success: false, message: 'Invalid token' })
	}
}
const verifyAdminToken = (req, res, next) => {


    verifyToken(req, res, async() => {
		try {
			
			const resadmin = await AdUser.findById({ _id: req.userId });
			if (!resadmin) {
				  	return res.status(401).json({
					success: false,
					message: "you are not admin count"
				})
			  }
			
            if (resadmin.isadmin) {
                next();
			} else {
				return res.status(401).json({
					success: false,
					message: "you are not admin count"
				})
			}
		} catch (error) {
			console.log(error)
			res.status(403).json({
				seuccess: false,
				message: "You are not alowed to do that!",
				error:error.data
			});
        }
    })
    
}

module.exports = verifyAdminToken;