import jwt from 'jsonwebtoken';
import { getDbConnection } from "../db"
import bcrypt from 'bcrypt';


export const logInRoute = {
    path : "/api/login",
    method : "post",
    handler : async(req,res) =>{
        const { email, password } = req.body;

        const db = getDbConnection("react-auth-db");
        const user = await db.collection('users').findOne({ email });

        if(!user) return res.sendStatus(401);

        const { _id:id, isVerified, passwordHash, info } = user;
        console.log(user.passwordHash)
        const isCorrect = await bcrypt.compare(password, passwordHash);

        if(isCorrect){
            jwt.sign( {id, isVerified, email, info},
                process.env.JWT_SECRET,
                { expiresIn : "2d" },
                (err, token)=>{
                    if (err){
                        res.status(401).json(err); 
                    }
                    res.status(200).json( {token} ); 
                }, )
        } else{
            res.sendStatus(401);
        }
    }
}