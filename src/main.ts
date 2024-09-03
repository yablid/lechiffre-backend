// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { join } from 'path';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Request, Response } from 'express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // CORS
  app.enableCors({
    origin: ['http://localhost:5174', 'http://localhost:5173'],  // Match the origin with your frontend
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods if necessary
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'], // Specify allowed headers
    credentials: true, // If you need to allow cookies or other credentials
  });
  app.use(cookieParser());

  // ---TEMP LOGGING REQUEST ORIGIN FOR DEVELOPMENT ---
  app.use((req, res, next) => {
    console.log('Origin:', req.headers.origin);
    next();
  });
  // --- END TEMP LOGGING REQUEST ORIGIN FOR DEVELOPMENT ---

  if (process.env.NODE_ENV === 'production') {
    // Serve static files from the React app
    app.useStaticAssets(join(__dirname, '..', 'build'));

    // Serve the index.html for any other routes (to handle client-side routing)
    app.use('*', (req: Request, res: Response) => {
      res.sendFile(join(__dirname, '..', 'build', 'index.html'));
    });
  }

  await app.listen(4001);
  console.log("Server is running on http://localhost:4001");
}
bootstrap().catch(console.error);
