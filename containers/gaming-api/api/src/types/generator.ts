export interface GeneratorOptions {
  count?: number;
  customData?: any[];
  [key: string]: any;
}

export interface GeneratorResult<T> {
  data: T[];
  metadata: {
    count: number;
    generatedAt: Date;
    options: GeneratorOptions;
  };
}

export interface BaseGenerator<T> {
  generate(options?: GeneratorOptions): Promise<T[]>;
  saveToDatabase(data: T[]): Promise<void>;
  validateData(data: T[]): void;
}
