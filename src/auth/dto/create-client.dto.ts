import { IsNumber, IsOptional, IsString } from "class-validator";

export class CreateClientDto{
    @IsString()
    personId: string;

    @IsOptional()
    @IsNumber()
    loyaltyPoints: number;
}