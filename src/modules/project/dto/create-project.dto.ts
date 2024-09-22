// modules/project/dto/create-project.dto.ts

import { IsNotEmpty } from 'class-validator';

export class CreateProjectDTO {
  @IsNotEmpty()
  file: Express.Multer.File;
}