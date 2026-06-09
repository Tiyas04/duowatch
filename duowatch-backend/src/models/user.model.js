import mongoose from "mongoose"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

const UserSchema = new mongoose.Schema(
    {
    name:{
        type:String,
        required:true,
        trim:true,
    },
    email:{
        type:String,
        required:true,
        trim:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    profilepic:{
        type:String,
        default:"https://cdn-icons-png.flaticon.com/512/149/149071.png"
    },
    username:{
        type:String,
        required:true,
        trim:true,
        unique:true,
    },
    refreshToken :{
        type:String
    }
},
{
    timestamps:true
}
)

UserSchema.pre('save',async function (next){
    if(!this.isModified("password")) return next()
    
    this.password = await bcrypt.hash(this.password,10)
    next()
    
})

UserSchema.methods.comparePassword = async function(password){
    return await bcrypt.compare(password,this.password)
}

UserSchema.methods.generateAccessToken = async function(){
    return jwt.sign(
        {
            _id:this._id,
            username:this.username,
            email:this.email,
            name:this.name
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn:process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

UserSchema.methods.generateRefreshToken = async function(){
    return jwt.sign(
        {
            _id:this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn:process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User",UserSchema)