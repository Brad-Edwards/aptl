use serde::Deserialize;
use std::fs;
use crate::Result;

#[derive(Debug)]
pub enum StaticDataSection {
    AccountStatus,
    Items,
    GameLocations,
    ChatChannels,
    Users,
    CharNames,
    ClassNames,
    TransactionTypes,
}

impl StaticDataSection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountStatus => "account_status",
            Self::Items => "items",
            Self::GameLocations => "game_locations",
            Self::ChatChannels => "chat_channels",
            Self::Users => "users",
            Self::CharNames => "char_names",
            Self::ClassNames => "class_names",
            Self::TransactionTypes => "transaction_types",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StaticAccountStatus {
    pub status: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct StaticGameLocation {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct StaticItem {
    pub name: String,
    pub gold_value: i64,
    pub rarity: String,
}

#[derive(Debug, Deserialize)]
pub struct StaticCharacterClass {
    pub class_name: String,
}

#[derive(Debug, Deserialize)]
pub struct StaticUser {
    pub username: String,
    pub email: String,
    pub created_at: String,
    pub first_name: String,
    pub last_name: String,
    pub last_ip_address: String,
}

pub struct StaticDataLoader {
    data: serde_json::Value,
}

impl StaticDataLoader {
    pub fn new() -> Result<Self> {
        let json_string = fs::read_to_string("../api/data/static-data.json")?;
        let data: serde_json::Value = serde_json::from_str(&json_string)?;
        Ok(Self { data })
    }

    pub fn get_account_status(&self) -> Result<Vec<StaticAccountStatus>> {
        let section = self.data[StaticDataSection::AccountStatus.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("account_status section not found"))?;
        
        let result: Vec<StaticAccountStatus> = serde_json::from_value(section.clone().into())?;
        Ok(result)
    }

    pub fn get_game_locations(&self) -> Result<Vec<StaticGameLocation>> {
        let section = self.data[StaticDataSection::GameLocations.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("game_locations section not found"))?;
        
        let result: Vec<StaticGameLocation> = serde_json::from_value(section.clone().into())?;
        Ok(result)
    }

    pub fn get_items(&self) -> Result<Vec<StaticItem>> {
        let section = self.data[StaticDataSection::Items.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("items section not found"))?;
        
        let result: Vec<StaticItem> = serde_json::from_value(section.clone().into())?;
        Ok(result)
    }

    pub fn get_character_classes(&self) -> Result<Vec<StaticCharacterClass>> {
        let section = self.data[StaticDataSection::ClassNames.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("class_names section not found"))?;
        
        let class_names: Vec<String> = serde_json::from_value(section.clone().into())?;
        let result = class_names.into_iter()
            .map(|name| StaticCharacterClass { class_name: name })
            .collect();
        Ok(result)
    }

    pub fn get_char_names(&self) -> Result<Vec<String>> {
        let section = self.data[StaticDataSection::CharNames.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("char_names section not found"))?;
        
        let result: Vec<String> = serde_json::from_value(section.clone().into())?;
        Ok(result)
    }

    pub fn get_transaction_types(&self) -> Result<Vec<String>> {
        let section = self.data[StaticDataSection::TransactionTypes.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("transaction_types section not found"))?;
        
        let result: Vec<String> = serde_json::from_value(section.clone().into())?;
        Ok(result)
    }

    pub fn get_users(&self) -> Result<Vec<StaticUser>> {
        let section = self.data[StaticDataSection::Users.as_str()]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("users section not found"))?;
        
        let result: Vec<StaticUser> = serde_json::from_value(section.clone().into())?;
        Ok(result)
    }
}