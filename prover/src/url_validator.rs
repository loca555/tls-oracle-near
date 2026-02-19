//! Модуль валидации URL — защита от SSRF-атак.
//!
//! Блокирует запросы к приватным IP, localhost, metadata-сервисам облаков.
//! Разрешает только HTTPS. Фильтрует опасные заголовки.

use std::net::{IpAddr, ToSocketAddrs};
use url::Url;

/// Заблокированные заголовки (нижний регистр)
const BLOCKED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "proxy-authorization",
    "cf-connecting-ip",
];

/// Максимальная длина URL
const MAX_URL_LENGTH: usize = 2048;

/// Проверяет, что URL безопасен для внешнего запроса
pub fn validate_url(raw_url: &str) -> Result<Url, String> {
    // Ограничение длины
    if raw_url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL слишком длинный: {} символов (макс {})",
            raw_url.len(),
            MAX_URL_LENGTH
        ));
    }

    let parsed =
        Url::parse(raw_url).map_err(|e| format!("Неверный URL: {e}"))?;

    // Только HTTPS
    if parsed.scheme() != "https" {
        return Err(format!(
            "Разрешён только HTTPS. Получен протокол: {}",
            parsed.scheme()
        ));
    }

    // Должен быть хост
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL без хоста".to_string())?;

    // Блок localhost и внутренних доменов
    let host_lower = host.to_lowercase();
    if host_lower == "localhost"
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".local")
    {
        return Err(format!("Запрещённый хост: {host}"));
    }

    // DNS-резолв + проверка IP (предотвращаем DNS rebinding)
    let port = parsed.port().unwrap_or(443);
    let addrs: Vec<IpAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| format!("DNS-резолв не удался для {host}: {e}"))?
        .map(|sa| sa.ip())
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS не вернул адресов для {host}"));
    }

    for ip in &addrs {
        if is_private_ip(ip) {
            return Err(format!(
                "Запрещённый IP-адрес {ip} для хоста {host}"
            ));
        }
    }

    Ok(parsed)
}

/// Проверяет, является ли IP приватным/зарезервированным
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                     // 127.0.0.0/8
            || v4.is_private()                   // 10.x, 172.16-31.x, 192.168.x
            || v4.is_link_local()                // 169.254.0.0/16 (metadata!)
            || v4.is_broadcast()                 // 255.255.255.255
            || v4.is_unspecified()               // 0.0.0.0
            || (v4.octets()[0] == 100            // 100.64.0.0/10 (CGNAT)
                && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                     // ::1
            || v6.is_unspecified()               // ::
            || {                                 // fc00::/7 (ULA)
                let s = v6.segments();
                (s[0] & 0xFE00) == 0xFC00
            }
            || {                                 // fe80::/10 (link-local)
                let s = v6.segments();
                (s[0] & 0xFFC0) == 0xFE80
            }
            || {                                 // ::ffff:0:0/96 (IPv4-mapped)
                let s = v6.segments();
                s[0] == 0 && s[1] == 0 && s[2] == 0
                    && s[3] == 0 && s[4] == 0 && s[5] == 0xFFFF
            }
        }
    }
}

/// Фильтрует заголовки, убирая опасные
pub fn filter_headers(
    headers: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| {
            let lower = k.to_lowercase();
            !BLOCKED_HEADERS.contains(&lower.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_only() {
        assert!(validate_url("http://example.com").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_blocked_hosts() {
        assert!(validate_url("https://localhost/foo").is_err());
        assert!(validate_url("https://metadata.google.internal/").is_err());
        assert!(validate_url("https://something.internal/").is_err());
        assert!(validate_url("https://printer.local/").is_err());
    }

    #[test]
    fn test_url_too_long() {
        let long = format!("https://example.com/{}", "a".repeat(2100));
        assert!(validate_url(&long).is_err());
    }

    #[test]
    fn test_private_ips() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_filter_headers() {
        let mut h = std::collections::HashMap::new();
        h.insert("Authorization".to_string(), "Bearer secret".to_string());
        h.insert("Accept".to_string(), "application/json".to_string());
        h.insert("Cookie".to_string(), "session=abc".to_string());

        let filtered = filter_headers(&h);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("Accept"));
    }

    #[test]
    fn test_valid_url() {
        // Реальные публичные URL должны проходить (если DNS резолвится)
        let result = validate_url("https://api.coingecko.com/api/v3/ping");
        assert!(result.is_ok());
    }
}
