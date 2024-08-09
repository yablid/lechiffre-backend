import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CORS
  app.enableCors({
    origin: 'http://localhost:5174',  // Match the origin with your frontend
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods if necessary
    allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
    credentials: true, // If you need to allow cookies or other credentials
  });

  // temp logging request origin for development
  app.use((req, res, next) => {
    console.log('Origin:', req.headers.origin);
    next();
  });

  await app.listen(4001);
  console.log("Server is running on http://localhost:4001");
}
bootstrap();
