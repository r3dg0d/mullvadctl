use super::parse::RelayEntry;

pub fn filter_relays<'a>(
    relays: &'a [RelayEntry],
    country: Option<&str>,
    city: Option<&str>,
    provider: Option<&str>,
    active_only: bool,
) -> Vec<&'a RelayEntry> {
    relays
        .iter()
        .filter(|r| {
            if active_only && !r.active {
                return false;
            }
            if let Some(c) = country {
                let c = c.to_lowercase();
                if r.country_code.to_lowercase() != c && !r.country.to_lowercase().contains(&c) {
                    return false;
                }
            }
            if let Some(c) = city {
                let c = c.to_lowercase();
                if r.city_code.to_lowercase() != c && !r.city.to_lowercase().contains(&c) {
                    return false;
                }
            }
            if let Some(p) = provider {
                let p = p.to_lowercase();
                match &r.provider {
                    Some(prov) if prov.to_lowercase().contains(&p) => {}
                    _ => return false,
                }
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mullvad::parse::RelayEntry;

    fn sample() -> Vec<RelayEntry> {
        vec![
            RelayEntry {
                hostname: "se-got-wg-001".into(),
                country_code: "se".into(),
                country: "Sweden".into(),
                city_code: "got".into(),
                city: "Gothenburg".into(),
                provider: Some("31173".into()),
                active: true,
            },
            RelayEntry {
                hostname: "de-ber-wg-001".into(),
                country_code: "de".into(),
                country: "Germany".into(),
                city_code: "ber".into(),
                city: "Berlin".into(),
                provider: Some("DataCamp".into()),
                active: true,
            },
        ]
    }

    #[test]
    fn filter_by_country() {
        let r = sample();
        let f = filter_relays(&r, Some("se"), None, None, true);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].hostname, "se-got-wg-001");
    }
}
