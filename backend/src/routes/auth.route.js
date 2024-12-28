import express from "express";
import { login, logout, signup, updateProfile, checkAuth } from "../controllers/auth.controller.js";
import { protectRoute } from "../middleware/auth.middleware.js";

const router= express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/update-profile", protectRoute,  updateProfile);  //protectRoute included to allow user change profile ony when logged in / authenticated
router.get("/check", protectRoute, checkAuth);

export default router;