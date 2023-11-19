const express=require('express');
const { loginuser, registeruser, validateUser, logoutUser, sendPasswordLink, verifyuser, changepassword } = require('../controllers/url');
const router=new express.Router();
const authenticate = require('../middleware/authenticate');

//register a new user
router.post('/register',registeruser);

//login user
router.post('/login',loginuser);

//valid user
router.get('/validuser',authenticate,validateUser);

//user logout
router.get('/logout',authenticate,logoutUser);

//send link for reset password
router.post('/sendpasswordlink',sendPasswordLink)

//verify user for forgot password
router.get("/forgotpassword/:id/:token",verifyuser)

//change password
router.post('/:id/:token',changepassword);

module.exports = router;