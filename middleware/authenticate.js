const jwt=require('jsonwebtoken');
const userdb=require('../models/userSchema');
const dotenv=require('dotenv');
dotenv.config();
const Secret_key=process.env.JWTSECRET;

const authenticate=async (req,res,next)=>{
    try {
        const token=req.headers.authorization;
        const verifytoken=jwt.verify(token,Secret_key);
        const rootUser=await userdb.findOne({_id:verifytoken._id});
        if(!rootUser){
            throw new Error("user not found")
        }
        req.token=token;
        req.rootUser=rootUser;
        req.userId=rootUser._id;
        next();
    } catch (error) {
        res.status(401).json({error:"Unauthorized no token provided"})
    }
}

module.exports=authenticate;