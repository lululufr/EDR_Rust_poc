use anyhow::Context;
use serde_json::json;
use std::error::Error;

pub async fn send_alert_to_central(alert: &str, pid: u32) -> Result<(), Box<dyn Error>> {
    let ip = crate::ebpf_state::GENERAL_SETTINGS
        .get()
        .and_then(|m| m.get("central_server_ip"))
        .cloned()
        .context("central_server_ip not found")?;
    println!("Central server IP: {}", ip);

    let payload = json!({
        "alert": "Suspicious command execution blocked",
        "machine": hostname::get()?.to_string_lossy(),
        "cause": format!("EDR CMD BLOQUÉ: {} (pid={})", alert, pid),
        "triggered_at": chrono::Utc::now().to_rfc3339(),
    });

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{ip}/alerts"))  
        .json(&payload)
        .send()
        .await?;

    println!("status: {}", res.status());
    let body = res.text().await?;
    println!("response body: {}", body);

    Ok(())
}
