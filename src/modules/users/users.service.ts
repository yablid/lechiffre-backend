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
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
      [createUserDto.email, hash]
    );

    const newUser = userResult.rows[0];
    await this.databaseService.query(
      'INSERT INTO users_roles (user_id, role_id) VALUES ($1, $2)',
      [newUser.id, createUserDto.role_id]
    );
    console.log(`Created new user with id ${newUser.id} and email ${newUser.email}`);
    return {
      id: newUser.id,
      email: newUser.email,
      roles: [{ role_id: role.role_id, name: role.name }],
      date_created: newUser.date_created
    };
  }

  async findAll(): Promise<User[]> {
    const result = await this.databaseService.query(
      `SELECT u.id, u.email, u.date_created, r.role_id, r.name 
       FROM users u
       LEFT JOIN users_roles ur ON u.id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id`
    );

    const usersMap = new Map<number, User>();

    result.rows.forEach(row => {
      if (!usersMap.has(row.id)) {
        usersMap.set(row.id, {
          id: row.id,
          email: row.email,
          password: 'REDACTED', // Do not include the password in the returned data
          roles: [],
          date_created: row.date_created,
        });
      }
      const user = usersMap.get(row.id);
      user.roles.push({ role_id: row.role_id, name: row.name });
    });

    return Array.from(usersMap.values());
  }

  async findByEmail(email: string): Promise<User> {
    const result = await this.databaseService.query(
      `SELECT u.id, u.email, u.password, u.date_created, r.role_id, r.name 
       FROM users u
       LEFT JOIN users_roles ur ON u.id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       WHERE u.email = $1`,
      [email]
    );

    if (result.rowCount === 0) {
      throw new NotFoundException(`User with email ${email} not found`);
    }

    const user = {
      id: result.rows[0].id,
      email: result.rows[0].email,
      password: result.rows[0].password,
      roles: result.rows[0].role_id ? [{ role_id: result.rows[0].role_id, name: result.rows[0].name }] : [],
      date_created: result.rows[0].date_created,
    }

    result.rows.forEach(row => {
      user.roles.push({ role_id: row.role_id, name: row.name });
    });

    return user;
  }

  async findById(id: string): Promise<User> {

    const result = await this.databaseService.query(
    `SELECT u.id, u.email, u.date_created, r.role_id, r.name 
     FROM users u
     LEFT JOIN users_roles ur ON u.id = ur.user_id
     LEFT JOIN roles r ON ur.role_id = r.role_id
     WHERE u.id = $1`,
    [id]
    );

    if (result.rowCount === 0) {
      throw new NotFoundException(`User with id ${id} not found`);
    }

    const user = {
      id: result.rows[0].id,
      email: result.rows[0].email,
      password: '', // Do not include the password in the returned data
      roles: [],
      date_created: result.rows[0].date_created,
    };

    result.rows.forEach(row => {
      user.roles.push({ role_id: row.role_id, name: row.name });
    });

    return user;
  }

  async getUserRoles(userId: string): Promise<{ role_id: number; name: string }[]> {
    const result = await this.databaseService.query(
      `SELECT r.role_id, r.name
       FROM users_roles ur
       JOIN roles r ON ur.role_id = r.role_id
       WHERE ur.user_id = $1`,
      [userId]
    );

    return result.rows;
  }

  private generatePassword(): string {
    return Math.random().toString(36).slice(-8); // Generates a simple 8 character password
  }
}
