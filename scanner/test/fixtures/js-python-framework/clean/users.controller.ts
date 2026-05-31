import { Controller, Get, Query } from '@nestjs/common';
import { Connection } from 'typeorm';
@Controller('users')
export class UsersController {
  constructor(private conn: Connection) {}
  @Get()
  async find(@Query('name') name: string) {
    return this.conn.query('SELECT * FROM users WHERE name=?', [name]);
  }
}
