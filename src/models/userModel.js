import mongoose from "mongoose";

const userSchema = mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
        },
        email: {
            type: String,
            required: true,
            unique: false,
        },
        password: {
            type: String,
            required: true,
        },
        resetPasswordToken: String,
        resetPasswordExpiration: Date,
    },
    {timestamps: true}
);

export default mongoose.model("User", userSchema);
