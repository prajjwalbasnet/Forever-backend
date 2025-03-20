import userModel from '../models/userModel.js'
import validator from 'validator'
import bycrypt from 'bcrypt'
import jwt from 'jsonwebtoken'


const createToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: '1d'})
}

// Route for user Login
const loginUser = async (req, res) => {

    try {
        const {email, password} = req.body

        const user = await userModel.findOne({email})
        if (!user){
            return res.status(404).json({success:false, message:"User does not exists"})
        }

        const isMatch = await bycrypt.compare(password, user.password)

        if (isMatch){
            const token = createToken(user._id)
            res.json({success:true, token})
        }
        else{
            res.json({success:false, message: "Invalid credentials"})
        }
    } catch (error) {
        console.log(error)
        res.json({success:false, message: error.message})
    }
}


// Route for user Register
const registerUser = async (req,res) => {

    try {
        const {name, email, password} = req.body

        // checking if user exists
        const exists = await userModel.findOne({email})
        if (exists){
            return res.json({success: false, message: "User already exists"})
        }

        // Validating email format & strong password
        if (!validator.isEmail(email)) {
            return res.json({success: false, message: "Please enter a valid email"})
        }

        if (password.length < 8) {
            return res.json({success: false, message: "Please enter a strong password"})
        }

        //hashing password
        const salt = await bycrypt.genSalt(10)
        const hashedPassword = await bycrypt.hash(password, salt)

        const newUser = new userModel({
            name, 
            email,
            password:hashedPassword
        })

        const user= await newUser.save()


        const token = createToken(user._id) 

        res.json({success: true, token})

    } catch (error) {
        console.log(error)
        res.json({success:false, message: error.message})
    }
}

// Route for admin login
const adminLogin = async(req, res) => {

    try {
        const { email, password} = req.body

        if(email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {

            const token = jwt.sign(
                {
                    email, 
                    isAdmin: true
                },
                process.env.JWT_SECRET,
                {expiresIn: '1d'}
            )
            res.json({success:true, token})
        }
        else{
            res.status(401).json({success:false, message:"Invalid credentials"})
        }
    } catch (error) {
        console.log(error)
        res.json({success:false, message: error.message})
    }
}


export {loginUser, registerUser, adminLogin}