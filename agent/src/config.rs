use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::{collections::HashMap};

// Lecture des des settings généraux et enregistement dans une HashMap
pub fn load_general_settings<P: AsRef<Path>>(path: P) -> Result<HashMap<String, String>> {
    let data = fs::read_to_string(&path)
        .with_context(|| format!("lecture du fichier {:?}", path.as_ref()))?;
    let v: Value = serde_json::from_str(&data)
        .with_context(|| format!("parse JSON {:?}", path.as_ref()))?;

    let mut out = HashMap::new();

    if let Value::Object(map) = v {
        for (k, v) in map {
            if let Some(s) = v.as_str() {
                out.insert(k, s.to_string());
            }
        }
    }

    Ok(out)
}


pub fn load_blocked_ips<P: AsRef<Path>>(path: P) -> Result<Vec<Ipv4Addr>> {
    let data = fs::read_to_string(&path)
        .with_context(|| format!("lecture du fichier {:?}", path.as_ref()))?;
    let v: Value = serde_json::from_str(&data)
        .with_context(|| format!("parse JSON {:?}", path.as_ref()))?;
    let mut out = Vec::new();
    match v {
        Value::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        if let IpAddr::V4(v4) = ip {
                            out.push(v4);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

pub fn load_blocked_cmds<P: AsRef<Path>>(path: P) -> Result<HashSet<String>> {
    let data = fs::read_to_string(&path)
        .with_context(|| format!("lecture du fichier {:?}", path.as_ref()))?;
    let v: Value = serde_json::from_str(&data)
        .with_context(|| format!("parse JSON {:?}", path.as_ref()))?;
    let mut out = HashSet::new();
    if let Value::Array(arr) = v {
        for item in arr {
            if let Some(s) = item.as_str() {
                if !s.is_empty() {
                    out.insert(s.to_string());
                }
            }
        }
    }
    Ok(out)
}

