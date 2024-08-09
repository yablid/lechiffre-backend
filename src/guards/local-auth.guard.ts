import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

// hitting AuthGuard('local') will trigger the LocalStrategy's validate method

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
