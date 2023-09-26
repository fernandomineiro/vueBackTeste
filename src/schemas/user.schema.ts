import { object, string, TypeOf, z } from 'zod';
import { RoleEnumType } from '../entities/user.entity';

export const createUserSchema = object({
  body: object({
    name: string({
      required_error: 'Nome é obrigatório',
    }),
    email: string({
      required_error: 'Email é obrigatório',
    }).email('Email inválido'),
    password: string({
      required_error: 'Senha é obrigatóriod',
    })
      .min(8, 'Senha tem que ter mais de 8 caracteres')
      .max(32, 'senha tem que ter menos de 32 caracteres'),
    passwordConfirm: string({
      required_error: 'Por favor confirme sua senha',
    }),
    role: z.optional(z.nativeEnum(RoleEnumType)),
  }).refine((data) => data.password === data.passwordConfirm, {
    path: ['passwordConfirm'],
    message: 'Senha não estão iguais',
  }),
});

export const loginUserSchema = object({
  body: object({
    email: string({
      required_error: 'Email é obrigatório',
    }).email('Email inválido'),
    password: string({
      required_error: 'é obrigatório',
    }).min(8, 'Email e senha inválidos'),
  }),
});

export const verifyEmailSchema = object({
  params: object({
    verificationCode: string(),
  }),
});

export type CreateUserInput = Omit<
  TypeOf<typeof createUserSchema>['body'],
  'passwordConfirm'
>;

export type LoginUserInput = TypeOf<typeof loginUserSchema>['body'];
export type VerifyEmailInput = TypeOf<typeof verifyEmailSchema>['params'];
