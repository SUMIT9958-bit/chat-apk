import jwt from "jsonwebtoken"

const generateTokenAndSetCokkie =(userId, res) =>{
  const token = jwt.sign({userId}, process.env.jwt_SECRET,{
    expiresIn: '15d',
  })

  res.cookie("jwt",token,{
    maxAge: 15 * 24 * 60 * 60 * 1000, //MS
    httpOnly:true,
    sameSite:"strict",
    secure: process.env.NODE_ENV !== "development",
  })
}

export default generateTokenAndSetCokkie;