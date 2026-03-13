import mongoose from "mongoose";
import bcrypt from "bcrypt";


const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 60
    },

    email: {
      type: String,
      trim: true,
      lowercase: true,
      unique: true,
      sparse: true  // sparse: true avoids index conflicts
    },

    phone: {
      type: String,
      unique: true,
      sparse: true
    },

    passwordHash: {
      type: String,
      required: true,
      minlength: 8,
      select: false
    },

    isEmailVerified: {
      type: Boolean,
      default: false
    },

    isPhoneVerified: {
      type: Boolean,
      default: false
    },

    roles: {
      type: [String],
      default: ["user"]
    },

    status: {
      type: String,
      enum: ["active", "suspended"],
      default: "active"
    },

    failedLoginAttempts: {
      type: Number,
      default: 0
    },

    lockUntil: {
      type: Date,
      default: null
    },

    lastLoginAt: Date,
    lastPasswordChangeAt: Date
  },
  { timestamps: true }
);


// Ensure email OR phone exists(if both not exist return error message)
userSchema.pre("validate", function (next) {
  if (!this.email && !this.phone) {
    this.invalidate("email", "Email or phone is required");
  }
  next();
});

// Hash password before saving
userSchema.pre("save", async function (next) {

  // Only hash if password is new or modified
  if (!this.isModified("password")) return next();

  const saltRounds = 12;
  this.password = await bcrypt.hash(this.password, saltRounds);

  next();
});


// Compare password method
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};


const User = mongoose.model("User", userSchema);

export default User;

