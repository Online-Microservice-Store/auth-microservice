import { IsString } from "class-validator";

export class CreateTrader{
    @IsString()
    personId: string;
}