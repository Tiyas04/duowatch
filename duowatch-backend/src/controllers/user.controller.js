import { asyncHandler } from "../utils/asyncHandler.js"
import { User } from "../models/user.model.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { uploadOnCloudinary } from "../utils/uploadOnCloudinary.js"
import mongoose from "mongoose"

const generateAccessandRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }
    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHandler(async(req,res)=>{
    const {name,email,password,username} = req.body
    
    if([name,email,password,username].some((field)=>(field?.trim()===""))){
        throw new ApiError(400,"All fields are required")
    }

    const existinguser = await User.findOne({
        $or:[
            {email},
            {username}
        ]
    })

    if(existinguser){
        throw new ApiError(400,"User already exists")
    }

    const profilePicLocalPath = req.files?.profilepic[0]?.path;
    
    //upload file on cloudinary
    const profilePic = await uploadOnCloudinary(profilePicLocalPath)

    if(!profilePic){
        throw new ApiError(400,"Profile picture is required")
    }

    const user = await User.create({
        name,
        email,
        password,
        username,
        profilepic:profilePic.url
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    const {accessToken, refreshToken} = await generateAccessandRefreshToken(user._id)

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(200,
            {
                user : createdUser,
                accessToken,
                refreshToken
            },
            "User registered successfully"
        )
    )
})

const loginUser = asyncHandler(async (req,res)=>{
    const {email,password,username} = req.body

    if(!email && !username){
        throw new ApiError(400,"Email or username is required")
    }

    const user = await User.findOne({
        $or:[{email},{username}]
    })

    if(!user){
        throw new ApiError(400,"User not found")
    }

    const isPasswordValid = await user.comparePassword(password)

    if(!isPasswordValid){
        throw new ApiError(400,"Invalid password")
    }

    const {accessToken, refreshToken} = await generateAccessandRefreshToken(user._id)

    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(200,
            {
                user : createdUser,
                accessToken,
                refreshToken
            },
            "User logged in successfully"
        )
    )
}) 

const logoutUser = asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user_id,
        {
            $unset:{
                refreshToken:1
            }
        },
        {
            new:true
        }
    )

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(
        new ApiResponse(200,
            {},
            "User logged out successfully"
        )
    )
})

export {
    registerUser,
    loginUser,
    logoutUser
}