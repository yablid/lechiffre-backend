// src/database/database.service.ts
import { Injectable, OnModuleInit, OnModuleDestroy, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import * as fs from 'fs';
import * as path from 'path';

/* todo: for typing, may want to return generics from query ie. (but lost db client methods like rowcount)
async query<T>(text: string, params?: any[]): Promise<T[]> ...
 */

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

    await this.createTables();
    await this.populateRoles();
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async query(text: string, params?: any[]) {
    try {
      return await this.pool.query(text, params);
    } catch (error) {
      console.error('Database query error:', error);
      throw new InternalServerErrorException('Database query error');
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

    try {
      const sqlFiles = [
        'create_roles_table.sql',
        'create_users_table.sql',
        'create_users_roles_table.sql',
        'create_auth_requests_table.sql'
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
    } catch (error) {
      console.error('Error creating tables:', error);
      throw new InternalServerErrorException('Error creating tables');
    }
  }

  private async populateRoles() {
    try {
      const filePath = path.join(__dirname, '../modules/roles/roles.json');
      const jsonData = fs.readFileSync(filePath, 'utf8');
      const roles = JSON.parse(jsonData);

      for (const role of roles) {
        const result = await this.query('SELECT * FROM roles WHERE role_id = $1', [role.role_id]);
        if (result.rowCount === 0) {
          await this.query(
            'INSERT INTO roles (role_id, name) VALUES ($1, $2)',
            [role.role_id, role.name]
          );
          console.log(`Inserted role: ${role.name}`);
        }
      }
      console.log("Populated roles.")
    } catch (error) {
      console.error('Error populating roles:', error);
      throw new InternalServerErrorException('Error populating roles');
    }
  }
}
