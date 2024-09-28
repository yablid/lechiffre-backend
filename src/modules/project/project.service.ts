// modules/project/project.service.ts
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as FormData from 'form-data';  // To handle form-data for file upload
import { ApiService } from '../../common/http/api.service';
import { UploadDPGFDTO, UploadDPGFResponseDTO } from "./dto/uploadDPGF.dto";

@Injectable()
export class ProjectService {
  constructor(private apiService: ApiService) {}

  async uploadDPGF(file: UploadDPGFDTO['file']): Promise<UploadDPGFResponseDTO> {
    const form = new FormData();
    form.append('file', file.buffer, file.originalname);  // Attach the file buffer and name

    try {
      // Log file name and other properties for debugging
      console.log(`project.service.uploadDPGF received: ${file.originalname} (${file.size} bytes) (${file.mimetype})`);

      const apiClient = this.apiService.getApiClient();

      // Send the file to the FastAPI backend
      console.log("Sending file to leChiffrai backend...")
      const response = await apiClient.post('dpgf/upload', form, {
        headers: {
          ...form.getHeaders(),  // Set proper headers for form-data
        },
      });
      console.log("project.service.upload DPGF response: ", response.data);
      return response.data;
    } catch (error) {
      throw new HttpException('Failed to upload file to FastAPI', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
