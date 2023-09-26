import { object, string, TypeOf } from 'zod';

export const createPostSchema = object({
  body: object({
    title: string({
      required_error: 'Título é obrigatório',
    }),
    content: string({
      required_error: 'Conteudo é obrigatório',
    }),
    image: string({
      required_error: 'Imagem é obrigatório',
    }),
  }),
});

const params = {
  params: object({
    postId: string(),
  }),
};

export const getPostSchema = object({
  ...params,
});

export const updatePostSchema = object({
  ...params,
  body: object({
    title: string(),
    content: string(),
    image: string(),
  }).partial(),
});

export const deletePostSchema = object({
  ...params,
});

export type CreatePostInput = TypeOf<typeof createPostSchema>['body'];
export type GetPostInput = TypeOf<typeof getPostSchema>['params'];
export type UpdatePostInput = TypeOf<typeof updatePostSchema>;
export type DeletePostInput = TypeOf<typeof deletePostSchema>['params'];
