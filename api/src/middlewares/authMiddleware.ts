import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export function verifyToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    res.status(401).json({ error: 'Access denied' });
    return;
  }
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  try {
    const decoded = jwt.verify(token, 'your-secret');
    if (typeof decoded !== 'object' || !decoded?.userId) {
      res.status(401).json({ error: 'Access denied' });
      return;
    }
    req.userId = decoded.userId;
    req.role = decoded.role;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Access denied' });
  }
}

export function verifyAdmin(req: Request, res: Response, next: NextFunction) {
  const role = req.role;
  if (role !== 'admin') {
    res.status(401).json({ error: 'Access denied' });
    return;
  }
  next();
}