import { Injectable, BadRequestException, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import * as argon2 from 'argon2';
import { CreateUserDto } from './dto/create-user.dto';
import User from './schema/users.model';
import { DatabaseService } from '../../database/database.service';

@Injectable()
export class UsersService {
  constructor(private readonly databaseService: DatabaseService) {}

  async create(createUserDto: CreateUserDto): Promise<Omit<User, 'password'>> {

    console.log("users.service creating user with payload: ", createUserDto);

    // todo: temp solution
    const password = 'testtest' // this.generatePassword();

    const hash = await argon2.hash(password);
    if (!hash) {
      throw Error("Error hashing password.")
    }

    const roleExists = await this.databaseService.query(
      'SELECT * FROM roles WHERE role_id = $1',
      [createUserDto.role_id]
    );

    if (roleExists.rowCount === 0) {
      throw new BadRequestException(`Role with id ${createUserDto.role_id} not found`);
    }

    const role = roleExists.rows[0];

    const userResult = await this.databaseService.query(
      'INSERT INTO users (email, password, role_id) VALUES ($1, $2, $3) RETURNING id, email, role_id, date_created',
      [createUserDto.email, hash, createUserDto.role_id]
    );

    const newUser = userResult.rows[0];
    return {
      id: newUser.id,
      email: newUser.email,
      role_id: newUser.role_id,
      date_created: newUser.date_created
    };
  }

  async findAll(): Promise<User[]> {
    const result = await this.databaseService.query(
      `SELECT u.id, u.email, u.role_id, u.date_created
       FROM users u`
    );

    return result.rows.map(row => ({
      id: row.id,
      email: row.email,
      password: 'REDACTED', // Do not include the password in the returned data
      role_id: row.role_id,
      date_created: row.date_created,
    }));
  }

  async findByEmail(email: string): Promise<User> {
    const result = await this.databaseService.query(
      `SELECT u.id, u.email, u.password, u.role_id, u.date_created 
       FROM users u
       WHERE u.email = $1`,
      [email]
    );

    if (result.rowCount === 0) {
      throw new NotFoundException(`User with email ${email} not found`);
    }

    const row = result.rows[0];
    return {
      id: row.id,
      email: row.email,
      password: row.password,
      role_id: row.role_id,
      date_created: row.date_created,
    };
  }

  async findById(id: string): Promise<User> {
    const result = await this.databaseService.query(
      `SELECT u.id, u.email, u.role_id, u.date_created
       FROM users u
       WHERE u.id = $1`,
      [id]
    );

    if (result.rowCount === 0) {
      throw new NotFoundException(`User with id ${id} not found`);
    }

    const row = result.rows[0];
    return {
      id: row.id,
      email: row.email,
      password: 'REDACTED', // Do not include the password in the returned data
      role_id: row.role_id,
      date_created: row.date_created,
    };
  }

  private generatePassword(): string {
    return Math.random().toString(36).slice(-8); // Generates a simple 8 character password
  }
}
