const router = require("express").Router();
const bcrypt = require("bcrypt");
const User = require("../models/User");
const { forgotPassword, varifyToken } = require("../utils/password");
// Bring in the User Registration function
const {
  userAuth,
  userLogin,
  checkRole,
  userRegister,
  serializeUser,
} = require("../utils/Auth");

// Users Registeration Route
router.post("/register-user", async (req, res) => {
  await userRegister(req.body, "user", res);
});

// Admin Registration Route
router.post("/register-admin", async (req, res) => {
  await userRegister(req.body, "admin", res);
});

// Super Admin Registration Route
router.post("/register-super-admin", async (req, res) => {
  await userRegister(req.body, "superadmin", res);
});

router.put("/forgot-password", forgotPassword);

router.put("/reset-password/:token", varifyToken, async (req, res) => {
  const { password } = req.body;
  let isMatch = await bcrypt.compare(password, req.user.password);
  if (isMatch) {
    return res.status(500).json({
      message:
        "This is one of the passwords you've previously used !! PLEASE ENTER A NEW ONE",
      success: false,
    });
  } else {
    // Get the hashed password
    const newPassword = await bcrypt.hash(password, 12);
    await User.updateOne(
      { _id: req.user._id },
      { password: newPassword },
      (err, success) => {
        if (err) {
          return res.status(500).json({
            message: "Unable to update your password.",
            success: false,
          });
        } else {
          return res.status(200).json({
            message: "Your password has been updated !! Kindly Login",
            success: true,
          });
        }
      }
    );
  }
});

// Users Login Route
router.post("/login-user", async (req, res) => {
  await userLogin(req.body, "user", res);
});

// Admin Login Route
router.post("/login-admin", async (req, res) => {
  await userLogin(req.body, "admin", res);
});

// Super Admin Login Route
router.post("/login-super-admin", async (req, res) => {
  await userLogin(req.body, "superadmin", res);
});

// Profile Route
router.get("/profile", userAuth, async (req, res) => {
  return res.json(serializeUser(req.user));
});

// Users Protected Route
router.get(
  "/user-protectd",
  userAuth,
  checkRole(["user"]),
  async (req, res) => {
    return res.json("Hello User");
  }
);

// Admin Protected Route
router.get(
  "/admin-protectd",
  userAuth,
  checkRole(["admin"]),
  async (req, res) => {
    return res.json("Hello Admin");
  }
);

// Super Admin Protected Route
router.get(
  "/super-admin-protectd",
  userAuth,
  checkRole(["superadmin"]),
  async (req, res) => {
    return res.json("Hello Super Admin");
  }
);

// Super Admin Protected Route
router.get(
  "/super-admin-and-admin-protectd",
  userAuth,
  checkRole(["superadmin", "admin"]),
  async (req, res) => {
    return res.json("Super admin and Admin");
  }
);

module.exports = router;
