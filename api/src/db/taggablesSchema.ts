// db/taggablesSchema.ts
import { pgTable, integer, varchar } from 'drizzle-orm/pg-core';
import { z } from 'zod';
import { tagsTable } from './tagsSchema';

export const taggablesTable = pgTable('taggables', {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  tag_id: integer().references(() => tagsTable.id),
  objeto_id: integer(),
  tipo_objeto: varchar({ length: 50 }),
});

export const insertTaggableSchema = z.object({
  tag_id: z.number().int(),
  objeto_id: z.number().int(),
  tipo_objeto: z.string().max(50),
});

export const updateTaggableSchema = z.object({
  tag_id: z.number().int().optional(),
  objeto_id: z.number().int().optional(),
  tipo_objeto: z.string().max(50).optional(),
}).partial();
