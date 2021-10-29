const express = require('express');
const app = express();
const PORT = 5000 || process.env.PORT;
require("dotenv").config();
const cors = require('cors')
const mongoose = require('mongoose');

const connectDB = async() => {
     try {
		await mongoose.connect(`mongodb+srv://myblogapp:1234@cluster0.w3eg5.mongodb.net/myblogapp?retryWrites=true&w=majority`,
			{
				useNewUrlParser: true,
				useUnifiedTopology: true,
				
				
			}
		)

		console.log('MongoDB connected')
	} catch (error) {
		console.log(error)

	}
}
connectDB();

app.use(express.json());
app.use(cors())

const RouterAuthAdmin = require('./Routers/AuthAdmin');
const RouterPost = require('./Routers/Posts');
const Routeruser = require('./Routers/authuser');
const RouterCart = require('./Routers/Carts');
const RouterOrder = require('./Routers/Order')

app.use('/api/auth/admin', RouterAuthAdmin);
app.use('/api/post', RouterPost);
app.use('/api/auth', Routeruser);
app.use('/api/cart', RouterCart);
app.use('/api/cart/order', RouterOrder)



app.listen(PORT, () => {
    console.log('server runing successfully');
})