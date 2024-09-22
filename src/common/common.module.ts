// common/common.module.ts
import { Module } from '@nestjs/common';
import { ApiService } from './http/api.service';  // Import shared service(s)

@Module({
  providers: [ApiService],  // Provide shared services
  exports: [ApiService],    // Export shared services to be available in other modules
})
export class CommonModule {}
