import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { CreateEntity, CreatePersonDto, CreateProfileDto, LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';
import { JwtPayload2 } from './interfaces/jwt-payload.interface2';
import { PaginationDto } from 'common';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger("auth-service")

    constructor(
        private readonly jwtService : JwtService
    ){
        super();
    }
    onModuleInit() {
        this.$connect();
        this.logger.log('prisma connected');
    }

    async signJWT2(payload : JwtPayload2){
        return this.jwtService.sign(payload);
    }

    async verifyToken(token: string){
        try {
            const {sub, iat, exp, ...profile} = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });
            return {
                user: profile,
                token: await this.signJWT2(profile),
            }
        } catch (error) {
            console.log(error);
            throw new RpcException({
                status: 400,
                message: 'Invalid token'
            })
        }
    }

    // Create person
    async createPerson(createPersonDto: CreatePersonDto, profileId : string){
        const { name, lastname, identification} = createPersonDto;
        try {
            const person = await this.person.findUnique({
                where: {identification}
            });
            // Verficacaion de persona
            if(person){
                throw new RpcException({
                    status: 400,
                    message: 'Identification already registered'
                });
            }
            const newPerson = await this.person.create({
                data: {
                    name,
                    lastname,
                    identification,
                    profileId: profileId
                }
            });
            
            return newPerson;
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }
    // Create profile
    async createProfile(createProfileDto : CreateProfileDto, identification:string){
        const { username, email, password, ocupation  } = createProfileDto;
        try {
            const person = await this.person.findUnique({
                where: {identification}
            });
            // Verficacaion de persona
            if(person){
                throw new RpcException({
                    status: 400,
                    message: 'Identification already registered'
                });
            }
            const profile = await this.profile.findUnique({
                where: {email}
            });
    
            if (profile){
                throw new RpcException({
                    status: 400,
                    message: 'Email already registered'
                })
            }
            
            const newProfile = await this.profile.create({
                data: {
                    username,
                    email,
                    password: bcrypt.hashSync(password, 10),
                    ocupation,
                }
            })
    
            const {password: __, ...rest} = newProfile;
            return{
                profile: rest,
                token: await this.signJWT2(rest)
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
        
        
    
    }
    // Register CLIENT
    async registerClient(createEntity: CreateEntity){
        const person : CreatePersonDto = {
            name: createEntity.name,
            lastname: createEntity.lastname,
            identification: createEntity.identification
        }
        const profile : CreateProfileDto = {
            username: createEntity.username,
            password: createEntity.password,
            email: createEntity.email,
            ocupation: createEntity.ocupation
        }
        try {
            const newProfile = await this.createProfile(profile, person.identification);
            const newPerson = await this.createPerson(person, newProfile.profile.id);
            const newClient = await this.client.create({
                data: {
                    personId: newPerson.id
                }
            })
            return {
                person: newPerson,
                profile: newProfile,
                client: newClient
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }
    // Register TRADER
    async registerTrader(createEntity: CreateEntity){
        const person : CreatePersonDto = {
            name: createEntity.name,
            lastname: createEntity.lastname,
            identification: createEntity.identification
        }
        const profile : CreateProfileDto = {
            username: createEntity.username,
            password: createEntity.password,
            email: createEntity.email,
            ocupation: createEntity.ocupation
        }
        try {
            const newProfile = await this.createProfile(profile, person.identification);
            const newPerson = await this.createPerson(person, newProfile.profile.id);
            const newTrader = await this.trader.create({
                data: {
                    personId: newPerson.id
                }
            })
            return {
                person: newPerson,
                profile: newProfile,
                trader: newTrader
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }
    // Register ADMIN
    async registerAdmin(createEntity: CreateEntity){
        const person : CreatePersonDto = {
            name: createEntity.name,
            lastname: createEntity.lastname,
            identification: createEntity.identification
        }
        const profile : CreateProfileDto = {
            username: createEntity.username,
            password: createEntity.password,
            email: createEntity.email,
            ocupation: createEntity.ocupation
        }
        try {
            const newProfile = await this.createProfile(profile, person.identification);
            const newPerson = await this.createPerson(person, newProfile.profile.id);
            const newAdmin = await this.admin.create({
                data: {
                    personId: newPerson.id
                }
            })
            return {
                person: newPerson,
                profile: newProfile,
                admin: newAdmin
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto){
        const { email, password } = loginUserDto;
        try {
            const profile = await this.profile.findUnique({
                where: {email}
            });
            if( !profile ){
                throw new RpcException({
                    status: 400,
                    message: 'Invalid credentials'
                });
            } 

            const isPasswordValid = bcrypt.compareSync(password, profile.password);
            if(!isPasswordValid){
                throw new RpcException({
                    status: 400,
                    message: 'Email/password not valid'
                })
            }


            const {password: __, ...rest} = profile; 
            return {
                user: rest,
                token: await this.signJWT2(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    // GET_ALL
    async get_all_clients(paginationDto: PaginationDto){
        const { page, limit } = paginationDto;

        const totalPages = await this.client.count(
        // { where: { available: true } }
        );
        const lastPage = Math.ceil(totalPages / limit);

        const clients =await this.client.findMany({
            skip: (page - 1) * limit,
            take: limit,
        });

        const detailedClients = await Promise.all(
            clients.map(async (client) => {
              // Obtén la información de la persona asociada al cliente
              const person = await this.person.findUnique({
                where: { id: client.personId },
              });
        
              // Si la persona tiene un `profileId`, obtén el perfil asociado
              const profile = person?.profileId
                ? await this.profile.findUnique({
                    where: { id: person.profileId },
                  })
                : null;
        
              return {
                ...client,
                person,
                profile,
              };
            })
          );
        
        return {
            data: detailedClients,
            meta: {
                total: totalPages,
                page: page,
                lastPage: lastPage,
            },
        };
    }

    async get_all_traders(paginationDto: PaginationDto){
        const { page, limit } = paginationDto;

        const totalPages = await this.trader.count(
        // { where: { available: true } }
        );
        const lastPage = Math.ceil(totalPages / limit);

        const traders =await this.trader.findMany({
            skip: (page - 1) * limit,
            take: limit,
        });

        const detailedTraders = await Promise.all(
            traders.map(async (trader) => {
              // Obtén la información de la persona asociada al cliente
              const person = await this.person.findUnique({
                where: { id: trader.personId },
              });
        
              // Si la persona tiene un `profileId`, obtén el perfil asociado
              const profile = person?.profileId
                ? await this.profile.findUnique({
                    where: { id: person.profileId },
                  })
                : null;
        
              return {
                ...trader,
                person,
                profile,
              };
            })
          );
        
        return {
            data: detailedTraders,
            meta: {
                total: totalPages,
                page: page,
                lastPage: lastPage,
            },
        };
    }

    async get_all_admins(paginationDto: PaginationDto){
        const { page, limit } = paginationDto;

        const totalPages = await this.admin.count(
        // { where: { available: true } }
        );
        const lastPage = Math.ceil(totalPages / limit);

        const admins =await this.admin.findMany({
            skip: (page - 1) * limit,
            take: limit,
        });

        const detailedAdmins = await Promise.all(
            admins.map(async (admin) => {
              // Obtén la información de la persona asociada al cliente
              const person = await this.person.findUnique({
                where: { id: admin.personId },
              });
        
              // Si la persona tiene un `profileId`, obtén el perfil asociado
              const profile = person?.profileId
                ? await this.profile.findUnique({
                    where: { id: person.profileId },
                  })
                : null;
        
              return {
                ...admin,
                person,
                profile,
              };
            })
          );
        
        return {
            data: detailedAdmins,
            meta: {
                total: totalPages,
                page: page,
                lastPage: lastPage,
            },
        };
    }

    // GET ONE

}
