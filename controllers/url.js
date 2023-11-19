const userdb = require("../models/userSchema");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Secret_key = process.env.JWTSECRET;
const dotenv = require('dotenv');
dotenv.config();
const nodemailer = require('nodemailer');


//email config
let transporter = nodemailer.createTransport({

    service: "gmail",
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL, // generated ethereal user
        pass: process.env.PASSWORD, // generated ethereal password
    },
});

//register user
async function registeruser(req, res) {
    if (!req.body.name || !req.body.email || !req.body.password || !req.body.cpassword) {
        return res.status(400).json({ error: "fill all the details" })
    }
    try {
        const preuser = await userdb.findOne({ email: req.body.email });
        if (preuser) {
            res.status(400).json({ error: "user already exists!!" })
        } else if (req.body.password !== req.body.cpassword) {
            res.status(400).json({ error: "password and confirm password does not match" })
        } else {
            let newuser = await new userdb({
                name: req.body.name,
                email: req.body.email,
                password: req.body.password,
                cpassword: req.body.cpassword
            });
            //password hashing
            const storeddata = await newuser.save();
            res.status(200).json({ status: 200, storeddata });
        }

    } catch (error) {
        res.status(400).json({ error: "Some error occurred" });
    }
}


//login user
async function loginuser(req, res) {
    if (!req.body.email || !req.body.password) {
        return res.status(400).json({ error: "fill all the details" })
    }
    try {
        const uservalid = await userdb.findOne({ email: req.body.email });
        if (uservalid) {
            const ismatch = await bcrypt.compare(req.body.password, uservalid.password);
            //  console.log(ismatch)
            if (!ismatch) {
                res.status(400).json({ error: "invalid details" })
            } else {
                const token = await uservalid.generateAuthtoken();
                const result = { uservalid, token }
                res.status(200).json({ status: 200, result });
            }
        } else {
            res.status(400).json({ error: "User does not exist!!!" })
        }
    } catch (error) {
        console.log(error)
        res.status(400).json({ error: "Some error occurred" });
    }
}

//valid user
async function validateUser(req, res) {
    try {
        const validuserone = await userdb.findOne({ _id: req.userId });
        // console.log(validuserone)
        res.status(200).json({ status: 200, validuserone })
    } catch (error) {
        res.status(400).json({ status: 400, error });
    }
}

//logout user
async function logoutUser(req, res) {
    try {
        req.rootUser.tokens = req.rootUser.tokens.filter(e => {
            return e.token !== req.token
        })
        req.rootUser.save();
        res.status(200).json({ status: 200, message: req.rootUser });
    } catch (error) {
        res.status(400).json({ status: 400, error })
    }
}

//send reset password link
async function sendPasswordLink(req, res) {
    if (!req.body.email) {
        return res.status(401).json({ status: 400, error: "Enter Your Email" })
    }
    try {
        const finduser = await userdb.findOne({ email: req.body.email });
        if (finduser) {
            const token = jwt.sign({ _id: finduser._id }, Secret_key, {
                expiresIn: "120s"
            });
            const setusertoken = await userdb.findByIdAndUpdate(finduser._id, {
                verifytoken: token
            }, { new: true })
            if (setusertoken) {
                const mailOptions = {
                    from: "dharani94667@gmail.com",
                    to: req.body.email,
                    subject: "Password Reset Link",
                    text: `This link is valid for 2 minutes https://ecommerce-frontend-gold.vercel.app/forgotpassword/${finduser._id}/${setusertoken.verifytoken}`
                }
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error)
                        res.status(400).json({ status: 400, "error": "Email not sent" })
                    } else {
                        res.status(200).json({ status: 200, "message": "Email sent successfully!!" })
                    }
                })
            }
        } else {
            res.status(400).json({ error: "User Not found" })
        }
    } catch (error) {
        res.status(400).json({ error: "Some error occurred" });
    }

}

async function verifyuser(req, res) {
    const id = req.params.id;
    const token = req.params.token;
    try {
        const validuser = await userdb.findOne({ _id: id, verifytoken: token });
        const verifyToken = jwt.verify(token, Secret_key);
        if (validuser && verifyToken._id) {
            res.status(200).json({ status: 200, validuser })
        } else {
            res.status(401).json({ status: 400, error: "user not exist" })
        }

    } catch (error) {
        res.status(401).json({ status: 400, error: "some error occurred" })
    }
}

async function changepassword(req, res) {
    const id = req.params.id;
    const token = req.params.token;
    try {
        const validuser = await userdb.findOne({ _id: id, verifytoken: token });
        const verifyToken = jwt.verify(token, Secret_key);
        if (validuser && verifyToken._id) {
            const newpassword = await bcrypt.hash(req.body.password, 12);
            const setnewpassword = await userdb.findByIdAndUpdate(id, {
                password: newpassword
            })
            await setnewpassword.save();
            res.status(200).json({ status: 200, setnewpassword })
        }
        else {
            res.status(401).json({ status: 401, "message": "user not exist" })
        }

    } catch (error) {
        res.status(401).json({ status: 401, error })
    }
}


module.exports ={registeruser,loginuser,validateUser,logoutUser,sendPasswordLink,verifyuser,changepassword}
