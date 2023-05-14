const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, "Please add a name"]
    },

    email: {
        type: String,
        required: [true, "Please add a email"],
        unique: true,
        trim: true,
        match: [
                    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                  "Please add a valid email address"
        ]
    },

    password: {
        type: String,
        required: [true, "Please add a valid password"],
        minLenght: [6, "Password must be at least 6 characters"],
        // maxLenght: [23, "Password must be more than 23 characters"]
    },
    photo: {
        type: String,
        default: ""
    },

    phone: {
        type: String,
        default: "+234"
    },
    bio: {
        type: String,
        default: "bio"
    }
}, {
    timestamps: true,
}
);

  //Encrypt password before saving to DB

  userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) {
        return next()
    }
  
    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
  })


const User = mongoose.model('User', userSchema)
module.exports = User