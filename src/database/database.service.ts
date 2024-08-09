// src/database/database.service.ts
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class DatabaseService implements OnModuleInit, OnModuleDestroy {
  private pool: Pool;

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    this.pool = new Pool({
      user: this.configService.get<string>('DB_USER'),
      host: this.configService.get<string>('DB_HOST'),
      port: this.configService.get<number>('DB_PORT'),
      database: this.configService.get<string>('DB_NAME'),
      password: this.configService.get<string>('DB_PASS'),
    });

    try {
      await this.pool.connect();
      console.log('Connected to db.');
    } catch (error) {
      console.error('Failed to connect to db:', error);
      throw error;
    }

    try {
      console.log("Creating tables if not exist...");
      await this.createTables();
    } catch (error) {
      console.error('Error creating tables:', error);
      throw error;
    }

  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async query(text: string, params?: any[]) {
    try {
      const res = await this.pool.query(text, params);
      return res;
    } catch (error) {
      console.error('Database query error:', error);
      throw error;
    }
  }

  async onModuleDestroy() {
    try {
      await this.pool.end();
      console.log('Database connection pool closed.');
    } catch (error) {
      console.error('Error closing the database connection pool:', error);
    }
  }

  private async createTables() {
    const sqlFiles = [
      'create_roles_table.sql',
      'create_users_table.sql',
      'create_users_roles_table.sql'
    ];
    const sqlDirectory = path.join(__dirname, '..', 'sql');

    for (const file of sqlFiles) {
      const filePath = path.join(sqlDirectory, file);
      const sql = fs.readFileSync(filePath, 'utf8');
      try {
        await this.query(sql);
        console.log(`Executed ${file}`);
      } catch (error) {
        console.error(`Error executing ${file}:`, error);
      }
    }
  }
}
