import jwt from 'jsonwebtoken';


const generateToken = (userId: string) => {
  const jwtSecret = process.env.JWT_SECRET || "secreto_super_seguro";
  return jwt.sign(
    { id: userId },
    jwtSecret,
    { expiresIn: '1h' }
  );
};

const verifyToken = (token: string) => {
  return jwt.verify(token, "secreto_super_seguro");
};

export default {
  generateToken,
  verifyToken
}