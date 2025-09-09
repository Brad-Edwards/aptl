import { PrismaClient } from '../../generated/prisma';
import { GeneratorOptions } from '../types/generator';

export abstract class BaseGenerator<T> {
  protected prisma: PrismaClient;

  constructor(prisma: PrismaClient) {
    this.prisma = prisma;
  }

  abstract generate(options?: GeneratorOptions): Promise<T[]>;
  abstract saveToDatabase(data: T[]): Promise<void>;
  abstract validateData(data: T[]): void;

  protected validateRequiredFields(data: T[], requiredFields: string[]): void {
    for (const item of data) {
      for (const field of requiredFields) {
        if (!(item as any)[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
    }
  }

  protected validateUniqueFields(data: T[], uniqueFields: string[]): void {
    for (const field of uniqueFields) {
      const values = data.map(item => (item as any)[field]);
      const uniqueValues = new Set(values);
      if (values.length !== uniqueValues.size) {
        throw new Error(`Duplicate ${field} values found`);
      }
    }
  }
}
