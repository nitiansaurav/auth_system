// generate secure random token which is used for - (refresh token,email verification token , password reset token )
// hash token before storing in db for safe comparison

import crypto from "crypto";

// generate random token
export const generateRandomToken = (bytes = 32) => {
    return crypto.randomBytes(bytes).toString("hex");
};

// hash token , we will not hash this by bcrypt , this random token will be too long (maybe 32 64 bits)
// by bcrypt, it takes very long time , as it very slow , we have to hash for every logged in user , on every refresh so 
// it will not good option , we will use sha-256(crypto) for this token as it is very fast , one-way , deterministic ,
//  secure for random data .

//store this hash token in db instead of raw tokrn(security)
export const hashToken = (token) =>{
    return crypto.createHash("sha256").update(token).digest("hex");
};

// safe constant-time comparison
//prevent timing attacks

export const safeCompare = (a,b) =>{
    if(!a || !b) return false;

    const bufferA = Buffer.from(a);
    const bufferB = Buffer.from(b);

    if(bufferA.length !== bufferB.length) return false;
    return crypto.timingSafeEqual(bufferA , bufferB);  // crypto cant compare string directly so we change this into objectok
};