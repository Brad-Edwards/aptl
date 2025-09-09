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

pub struct StaticDataLoader {
    data: serde_json::Value,
}

impl StaticDataLoader {
    pub fn new() -> Result<Self> {
        let json_string = fs::read_to_string("./data/static-data.json")?;
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
}