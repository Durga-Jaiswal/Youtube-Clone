import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from './utils/ApiError.js';
import {User} from './models/user.model.js';
import { uploadOnCloudinary } from './utils/uploadOnCloudinary.js'
import { ApiResponse } from './utils/ApiResponse.js'

const registerUser = asyncHandler( async (req, res) => {

    //get user details from frontend
    //validation - not empty
    //check if user already exists - username , email
    // check for images and avatar
    // upload them to cloudinary
    //create user object - create entry in db
    //remove password and refresh token from response
    //check for user creation
    // return res

   const {fullName, userName, password, email} = req.body;

    if(
        [fullName, password, userName, email].some(( field )=> field?.trim() === "")
    ){
        return new ApiError(400, "All fields are required.")
    }

    const existedUser = await User.findOne({
        $or: [{userName}, {email}]
    })

    if(existedUser){
        throw new ApiError(409, "userName and email already exists.")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    const coverImageLocalPath = req.files?.avatar[0]?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar is required.")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar is required.")
    }

    const user = await User.create({
        fullName,
        userName: userName.toLowercase(),
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering User")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User created successfully.")
    )

})

export {registerUser}