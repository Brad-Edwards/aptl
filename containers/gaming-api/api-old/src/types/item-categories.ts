export interface ItemCategoryData {
  name: string;
  description: string;
  parent_id?: number | null;
}

export interface ItemCategoryOptions extends GeneratorOptions {
  count?: number;
  customData?: ItemCategoryData[];
}
