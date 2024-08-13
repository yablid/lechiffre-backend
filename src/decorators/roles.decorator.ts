// src/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const Roles = (role: number) => SetMetadata('role', role);
