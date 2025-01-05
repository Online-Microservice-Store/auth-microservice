import { Controller, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { CreateEntity, LoginUserDto, RegisterUserDto } from './dto';
import { PaginationDto } from 'common';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @MessagePattern('auth.register.user')
  // registerUser(@Payload() registerUserDto : RegisterUserDto){
  //   return this.authService.registerUser(registerUserDto);
  // }

  @MessagePattern('auth.register.client')
  registerClient(@Payload() createEntity: CreateEntity ){
    return this.authService.registerClient(createEntity);
  }

  @MessagePattern('auth.register.trader')
  registerTrader(@Payload() createEntity : CreateEntity ){
    return this.authService.registerTrader(createEntity);
  }

  @MessagePattern('auth.register.admin')
  registerAdmin(@Payload() createEntity : CreateEntity ){
    return this.authService.registerAdmin(createEntity);
  }

  @MessagePattern('auth.login.user')
  loginUser(@Payload() loginUserDto : LoginUserDto){
    return this.authService.loginUser(loginUserDto);
  }

  @UseGuards()
  @MessagePattern('auth.verify.user')
  verifyToken(@Payload() token:string){
    return this.authService.verifyToken(token);
  }
  
  // GET ALL
  @MessagePattern('auth.find_all.client')
  get_all_Clients(@Payload() paginationDto: PaginationDto){
    return this.authService.get_all_clients(paginationDto);
  }
  @MessagePattern('auth.find_all.trader')
  get_all_Traders(@Payload() paginationDto: PaginationDto){
    return this.authService.get_all_traders(paginationDto);
  }
  @MessagePattern('auth.find_all.admin')
  get_all_Admins(@Payload() paginationDto: PaginationDto){
    return this.authService.get_all_admins(paginationDto);
  }

  // GET ONE

}
