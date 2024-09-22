// modules/project/project.service.ts
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as FormData from 'form-data';  // To handle form-data for file upload
import { ApiService } from '../../common/http/api.service';
import { CreateProjectDTO } from "./dto/create-project.dto";

@Injectable()
export class ProjectService {
  constructor(private apiService: ApiService) {}

  async processDPGF(file: CreateProjectDTO['file']) {
    const form = new FormData();
    form.append('file', file.buffer, file.originalname);  // Attach the file buffer and name

    try {
      // Log file name and other properties for debugging
      console.log(`project.service received: ${file.originalname} (${file.size} bytes) (${file.mimetype})`);

      const apiClient = this.apiService.getApiClient();

      // Send the file to the FastAPI backend
      console.log("Sending file to lechiffrai backend...")
      const response = await apiClient.post('/project/create', form, {
        headers: {
          ...form.getHeaders(),  // Set proper headers for form-data
        },
      });
      console.log("Response: ", response.data);
      return response.data;
    } catch (error) {
      throw new HttpException('Failed to upload file to FastAPI', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
