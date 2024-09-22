import {
  Controller,
  Post,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  HttpStatus,
  Res,
  HttpException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ProjectService } from './project.service';
import { Response } from 'express';
import { RolesGuard } from '../../guards/roles.guard';
import { Roles } from '../../decorators/roles.decorator';

@Controller('project')
@UseGuards(RolesGuard)
@Roles(10)
export class ProjectController {
  constructor(private readonly projectService: ProjectService) {}

  // todo: file validation: https://docs.nestjs.com/techniques/file-upload

  @Post('uploadDPGF')
  @UseInterceptors(FileInterceptor('file'))  // File upload handling
  async uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @Res() res: Response,
  ) {
    if (!file) {
      throw new HttpException('No file uploaded', HttpStatus.BAD_REQUEST);
    }

    try {
      // Send file to the ProjectService for processing (or forwarding to Python backend)
      const result = await this.projectService.processDPGF(file);

      return res.status(HttpStatus.OK).json({
        message: 'File uploaded and processed successfully',
        result,
      });
    } catch (error) {
      throw new HttpException(
        'Failed to process file',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
