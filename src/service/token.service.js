// refresh token heart
// login refresh , logout , security breach handling

import RefreshTokenModel from "../models/RefreshToken.model.js";
import { generateRandomToken , hashToken } from "../utils/crypto.js";

export const createRefreshToken = async ( user , req ) => {
    const rawToken = generateRandomToken(32);
    const tokenHash = hashToken(rawToken);
    
    // setting expirriing time
    const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000
    );

    // save in db
    await RefreshTokenModel.create({
        userId: user._id,
        tokenHash,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        deviceId: req.headers["user-agent"]  // simple device identification
    });

    return rawToken;
};


// to regenerate access token
export const rotateRefreshToken = async(oldRawtoken , req) =>{
    
    // hash raw token
    const rawToken = oldRawtoken;
    const rawTokenHash = hashToken(rawToken); 

    // find this hashed token in db
    const isTokenExist = await RefreshTokenModel.findOne({refreshtokenHash: rawTokenHash});

    // token not found
    if(!isTokenExist){
        throw new Error("Invalid refresh token");
    }

    // if token is revoked means token is already used once and is blocked
    if(isTokenExist.revokedAt){
        await RefreshTokenModel.updateMany({ userId: isTokenExist.userId },{ revokedAt: new Date()}); // revoke all session in every device
    
        //
        throw new Error("Refresh token reuse detected");
    }

    // if client token exist and not revoked so revoke this token and generate new
    isTokenExist.revokedAt = new Date();
    await isTokenExist.save();

    const newRawToken = generateRandomToken(32);
    const newTokenHash = hashToken(newRawToken);

    await RefreshTokenModel.create({
        userId : isTokenExist.userId,
        refreshtokenHash : newTokenHash,
        expiresAt : new Date(Date.now() + 7*24*60*60*1000),
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        deviceId: req.headers["user-agent"]
    });

    // return new Raw token into user device cookies
    return {
       newRefreshToken: newRawToken,
       userId: isTokenExist.userId
      };


}