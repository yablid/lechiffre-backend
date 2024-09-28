// modules/project/dto/create-project.dto.ts

import { IsNotEmpty } from 'class-validator';

export class UploadDPGFDTO {
  @IsNotEmpty()
  file: Express.Multer.File;
}

export class UploadDPGFResponseDTO {
  status: string;
  filename: string;
  file_key: string;
  summary: Record<string, string[]>
  details: {
    worksheet_count: number;
    worksheets: {
      name: string;
      head: Record<string, string[]>[];
      df: Record<string, string[]>[];
    }[];
  };
}
