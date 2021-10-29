const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const PostSchema = new Schema({
   title: {
        type: String,
        required: true,
        unique:true
    },
    description: {
        type: String,
        required: true
    },
    image: {
        type: String,
        required: true
    },
    category: {
        type: String,
        required: true
    },
    status: {
        type: String,
       enum:['STOCKING', 'OUT OF STOCK']
    },
    price: {
        type: Number,
        required:true
    },
    user: {
        type: Schema.Types.ObjectId,
        ref:'Users'
    },
    createdAt: {
        type: Date,
        default:Date.now
    }
})


module.exports= mongoose.model('Post', PostSchema);