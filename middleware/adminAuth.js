import jwt from "jsonwebtoken"

const adminAuth = async (req, res, next) => {
     
    try {
        
        const authHeader = req.headers.authorization
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({success:false, message:"Not Authorized: Invalid token format"})
        }

        const token = authHeader.split(' ')[1]

        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        if(!decoded.isAdmin){
            return res.status(403).json({success:false, message: "Not Authorized"})
        }

        req.admin = decoded
        
        next()

    } catch (error) {
        console.log(error)
        res.json({success:false, message: error.message})
    }
}

export default adminAuth