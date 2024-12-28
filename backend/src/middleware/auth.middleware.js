import jwt, { decode } from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        //if no token
        if (!token) {
            return res.status(401).json({ message: "Unautorized - no token provided" });
        }
        //if false token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded) { 
            return res.status(401).json({ message: "Unautorized -  invalid token" });
        }
        //if all checks passed now finding the user in the database
        const user  = await User.findById(decoded.userId).select("-password");
        //incase user not found
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        req.user = user; //adding user to the req
        next();

        
    } catch (error) {
        console.log("Error in protectRoute middleware: ", error.message);
        res.status(500).json({ message: "Internal server error" });
    }
};