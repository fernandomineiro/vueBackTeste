import { CookieOptions, NextFunction, Request, Response } from 'express';
import config from 'config';
import crypto from 'crypto';
import {
  CreateUserInput,
  LoginUserInput,
  VerifyEmailInput,
} from '../schemas/user.schema';
import {
  createUser,
  findUser,
  findUserByEmail,
  findUserById,
  signTokens,
} from '../services/user.service';
import AppError from '../utils/appError';
import redisClient from '../utils/connectRedis';
import { signJwt, verifyJwt } from '../utils/jwt';
import { User } from '../entities/user.entity';
import Email from '../utils/email';

const cookiesOptions: CookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
};

if (process.env.NODE_ENV === 'production') cookiesOptions.secure = true;

const accessTokenCookieOptions: CookieOptions = {
  ...cookiesOptions,
  expires: new Date(
    Date.now() + config.get<number>('accessTokenExpiresIn') * 60 * 1000
  ),
  maxAge: config.get<number>('accessTokenExpiresIn') * 60 * 1000,
};

const refreshTokenCookieOptions: CookieOptions = {
  ...cookiesOptions,
  expires: new Date(
    Date.now() + config.get<number>('refreshTokenExpiresIn') * 60 * 1000
  ),
  maxAge: config.get<number>('refreshTokenExpiresIn') * 60 * 1000,
};

export const registerUserHandler = async (
  req: Request<{}, {}, CreateUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, password, email } = req.body;

    const newUser = await createUser({
      name,
      email: email.toLowerCase(),
      password,
    });

    const { hashedVerificationCode, verificationCode } =
      User.createVerificationCode();
    newUser.verificationCode = hashedVerificationCode;
    await newUser.save();

    const redirectUrl = `${config.get<string>(
      'origin'
    )}/verifyemail/${verificationCode}`;

    try {
      await new Email(newUser, redirectUrl).sendVerificationCode();

      res.status(201).json({
        status: 'success',
        message:
          'Um e-mail com um código de verificação foi enviado para seu e-mail',
      });
    } catch (error) {
      newUser.verificationCode = null;
      await newUser.save();

      return res.status(500).json({
        status: 'error',
        message: 'Ocorreu um erro ao enviar o e-mail, tente novamente',
      });
    }
  } catch (err: any) {
    if (err.code === '23505') {
      return res.status(409).json({
        status: 'fail',
        message: 'Já existe usuário com esse e-mail',
      });
    }
    next(err);
  }
};

export const loginUserHandler = async (
  req: Request<{}, {}, LoginUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = req.body;
    const user = await findUserByEmail({ email });

    if (!user) {
      return next(new AppError(400, 'Inválido email ou senha'));
    }

    if (!user.verified) {
      return next(
        new AppError(
          401,
          'Você não foi verificado, verifique seu e-mail para verificar sua conta'
        )
      );
    }

    if (!(await User.comparePasswords(password, user.password))) {
      return next(new AppError(400, 'Inválido email ou senha'));
    }

    const { access_token, refresh_token } = await signTokens(user);

    res.cookie('access_token', access_token, accessTokenCookieOptions);
    res.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);
    res.cookie('logged_in', true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    res.status(200).json({
      status: 'success',
      access_token,
    });
  } catch (err: any) {
    next(err);
  }
};

export const verifyEmailHandler = async (
  req: Request<VerifyEmailInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const verificationCode = crypto
      .createHash('sha256')
      .update(req.params.verificationCode)
      .digest('hex');

    const user = await findUser({ verificationCode });

    if (!user) {
      return next(new AppError(401, 'Não foi verificado o email'));
    }

    user.verified = true;
    user.verificationCode = null;
    await user.save();

    res.status(200).json({
      status: 'success',
      message: 'Email verificado com sucesso',
    });
  } catch (err: any) {
    next(err);
  }
};

export const refreshAccessTokenHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const refresh_token = req.cookies.refresh_token;

    const message = 'Não foi possível atualizar o token de acesso';

    if (!refresh_token) {
      return next(new AppError(403, message));
    }


    const decoded = verifyJwt<{ sub: string }>(
      refresh_token,
      'refreshTokenPublicKey'
    );

    if (!decoded) {
      return next(new AppError(403, message));
    }

    const session = await redisClient.get(decoded.sub);
    if (!session) {
      return next(new AppError(403, message));
    }

    const user = await findUserById(JSON.parse(session).id);

    if (!user) {
      return next(new AppError(403, message));
    }

    const access_token = signJwt({ sub: user.id }, 'accessTokenPrivateKey', {
      expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
    });

    res.cookie('access_token', access_token, accessTokenCookieOptions);
    res.cookie('logged_in', true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    res.status(200).json({
      status: 'success',
      access_token,
    });
  } catch (err: any) {
    next(err);
  }
};

const logout = (res: Response) => {
  res.cookie('access_token', '', { maxAge: 1 });
  res.cookie('refresh_token', '', { maxAge: 1 });
  res.cookie('logged_in', '', { maxAge: 1 });
};

export const logoutHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = res.locals.user;

    await redisClient.del(user.id);
    logout(res);

    res.status(200).json({
      status: 'success',
    });
  } catch (err: any) {
    next(err);
  }
};
