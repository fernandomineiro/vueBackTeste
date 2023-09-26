import express from 'express';
import {
  loginUserHandler,
  logoutHandler,
  refreshAccessTokenHandler,
  registerUserHandler,
  verifyEmailHandler,
} from '../controllers/auth.controller';
import { deserializeUser } from '../middleware/deserializeUser';
import { requireUser } from '../middleware/requireUser';
import { validate } from '../middleware/validate';
import {
  createUserSchema,
  loginUserSchema,
  verifyEmailSchema,
} from '../schemas/user.schema';

const router = express.Router();


router.post('/register', validate(createUserSchema), registerUserHandler);


router.post('/login', validate(loginUserSchema), loginUserHandler);


router.get('/logout', deserializeUser, requireUser, logoutHandler);


router.get('/refresh', refreshAccessTokenHandler);


router.get(
  '/verifyemail/:verificationCode',
  validate(verifyEmailSchema),
  verifyEmailHandler
);

export default router;
