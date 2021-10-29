const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const UserSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique:true
    },
    password: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique:true
        
    },
    phonenumber: {
        type: String,
        required: true,
        unique:true
    },
    isadmin: {
        type: Boolean,
        default:true
    },
    createdAt: {
        type: Date,
        default:Date.now
    }
 
})


module.exports= mongoose.model('AdUser', UserSchema);