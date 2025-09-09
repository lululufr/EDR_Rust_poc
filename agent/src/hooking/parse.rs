
// parse "AABBCCDD:PPPP" -> ("a.b.c.d", port)
// Fonction de parsing Merci GPT ici
pub fn parse_addr_port_str(s: &str) -> Option<(String, u16)> {
    let mut it = s.split(':');
    let ip_hex = it.next()?;
    let port_hex = it.next()?;

    if ip_hex.len() != 8 { return None; }
    let ip = u32::from_str_radix(ip_hex, 16).ok()?;
    let b = ip.to_le_bytes(); // remet dans l'ordre réseau
    let ip_str = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    Some((ip_str, port))
}

pub fn parse_state_str(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }.to_string()
}