//! Gaming API - Mock MMO server for security demonstrations
//!
//! This crate provides data generation and management for simulating
//! account takeover scenarios in gaming environments.

pub mod cli;
pub mod db;
pub mod generators;
pub mod models;

pub use anyhow::{Error, Result};