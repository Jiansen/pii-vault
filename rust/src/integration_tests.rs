#[cfg(test)]
mod tests {
    use crate::analyzer::Analyzer;
    use crate::anonymizer::{Anonymizer, Operator};
    use crate::recognizer;
    use crate::vault::Vault;
    use std::collections::HashMap;

    fn load_spec_recognizers() -> Vec<Box<dyn crate::recognizer::Recognizer>> {
        let spec_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()
            .join("spec/recognizers");
        crate::recognizer::load_recognizers_from_dir(&spec_dir)
    }

    #[test]
    fn test_spec_recognizers_load() {
        let recs = load_spec_recognizers();
        assert!(recs.len() >= 25, "Expected at least 25 recognizers, got {}", recs.len());
    }

    #[test]
    fn test_email_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Send to alice@company.org", &[], 0.0);
        assert_eq!(result.entities.len(), 1);
        assert_eq!(result.entities[0].entity_type.as_str(), "EMAIL_ADDRESS");
    }

    #[test]
    fn test_multiple_emails() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("alice@test.com and bob@test.com", &[], 0.0);
        let emails: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "EMAIL_ADDRESS")
            .collect();
        assert_eq!(emails.len(), 2);
    }

    #[test]
    fn test_us_ssn_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("SSN: 123-45-6789", &[], 0.0);
        let ssns: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "US_SSN")
            .collect();
        assert!(!ssns.is_empty(), "Should detect US SSN");
    }

    #[test]
    fn test_cn_id_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("身份证号: 11010519491231002X", &[], 0.0);
        let ids: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "CN_ID_CARD")
            .collect();
        assert!(!ids.is_empty(), "Should detect Chinese ID card");
    }

    #[test]
    fn test_cn_phone_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("手机号: +86 13912345678", &[], 0.0);
        let phones: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "CN_PHONE" || e.entity_type.as_str() == "PHONE_NUMBER")
            .collect();
        assert!(!phones.is_empty(), "Should detect Chinese phone number");
    }

    #[test]
    fn test_credit_card_valid() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Card: 4111111111111111", &[], 0.0);
        let cards: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "CREDIT_CARD")
            .collect();
        assert!(!cards.is_empty(), "Should detect valid credit card");
    }

    #[test]
    fn test_credit_card_invalid_luhn() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Card: 1234567890123456", &[], 0.0);
        let cards: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "CREDIT_CARD")
            .collect();
        assert!(cards.is_empty(), "Should NOT detect invalid credit card");
    }

    #[test]
    fn test_ip_address_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Server at 192.168.1.100", &[], 0.0);
        let ips: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "IP_ADDRESS")
            .collect();
        assert!(!ips.is_empty(), "Should detect IP address");
    }

    #[test]
    fn test_ip_deny_list() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("localhost is 127.0.0.1", &[], 0.0);
        let ips: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "IP_ADDRESS")
            .collect();
        assert!(ips.is_empty(), "Should NOT detect denied IP address");
    }

    #[test]
    fn test_url_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Visit https://example.com/page", &[], 0.0);
        let urls: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "URL")
            .collect();
        assert!(!urls.is_empty(), "Should detect URL");
    }

    #[test]
    fn test_uuid_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("ID: 550e8400-e29b-41d4-a716-446655440000", &[], 0.0);
        let uuids: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "UUID")
            .collect();
        assert!(!uuids.is_empty(), "Should detect UUID");
    }

    #[test]
    fn test_mac_address_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("MAC: 00:1A:2B:3C:4D:5E", &[], 0.0);
        let macs: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "MAC_ADDRESS")
            .collect();
        assert!(!macs.is_empty(), "Should detect MAC address");
    }

    #[test]
    fn test_uk_nino_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("NI number: AB 12 34 56 C", &[], 0.0);
        let ninos: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "UK_NINO")
            .collect();
        assert!(!ninos.is_empty(), "Should detect UK NINO");
    }

    #[test]
    fn test_in_pan_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("PAN: ABCDE1234F", &[], 0.0);
        let pans: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "IN_PAN")
            .collect();
        assert!(!pans.is_empty(), "Should detect Indian PAN");
    }

    #[test]
    fn test_it_fiscal_code_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("CF: RSSMRA85M01H501Z", &[], 0.0);
        let cfs: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "IT_FISCAL_CODE")
            .collect();
        assert!(!cfs.is_empty(), "Should detect Italian fiscal code");
    }

    #[test]
    fn test_br_cpf_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("CPF: 123.456.789-09", &[], 0.0);
        let cpfs: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "BR_CPF")
            .collect();
        assert!(!cpfs.is_empty(), "Should detect Brazilian CPF");
    }

    #[test]
    fn test_es_nie_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("NIE: X1234567A", &[], 0.0);
        let nies: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "ES_NIE")
            .collect();
        assert!(!nies.is_empty(), "Should detect Spanish NIE");
    }

    #[test]
    fn test_sg_nric_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("NRIC: S1234567A", &[], 0.0);
        let nrics: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "SG_NRIC")
            .collect();
        assert!(!nrics.is_empty(), "Should detect Singapore NRIC");
    }

    #[test]
    fn test_kr_rrn_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("주민등록번호: 850101-1234567", &[], 0.0);
        let rrns: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "KR_RRN")
            .collect();
        assert!(!rrns.is_empty(), "Should detect Korean RRN");
    }

    #[test]
    fn test_full_pipeline_vault() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let text = "Email alice@company.com, SSN 123-45-6789, phone 13912345678";
        let analysis = analyzer.analyze(text, &[], 0.0);

        let mut vault = Vault::new();
        let mut ops = HashMap::new();
        ops.insert("EMAIL_ADDRESS".to_string(), Operator::Vault);
        ops.insert("US_SSN".to_string(), Operator::Vault);
        ops.insert("CN_PHONE".to_string(), Operator::Vault);

        let anon = Anonymizer::anonymize(text, &analysis.entities, &ops, &Operator::default(), Some(&mut vault));

        assert!(!anon.text.contains("alice@company.com"));
        assert!(!anon.text.contains("123-45-6789"));

        let restored = vault.detokenize(&anon.text);
        assert!(restored.contains("alice@company.com"));
    }

    #[test]
    fn test_iban_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("IBAN: DE89370400440532013000", &[], 0.0);
        let ibans: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "IBAN_CODE")
            .collect();
        assert!(!ibans.is_empty(), "Should detect IBAN");
    }

    #[test]
    fn test_iban_invalid_checksum() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("IBAN: DE00370400440532013000", &[], 0.0);
        let ibans: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "IBAN_CODE")
            .collect();
        assert!(ibans.is_empty(), "Should NOT detect IBAN with invalid checksum");
    }

    #[test]
    fn test_de_tax_id_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Steuer-ID: 86095742719", &[], 0.0);
        let ids: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "DE_TAX_ID")
            .collect();
        assert!(!ids.is_empty(), "Should detect German Tax ID");
    }

    #[test]
    fn test_de_passport_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("Reisepass: C01X00T47", &[], 0.0);
        let passports: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "DE_PASSPORT")
            .collect();
        assert!(!passports.is_empty(), "Should detect German passport");
    }

    #[test]
    fn test_de_vat_id_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("USt-IdNr: DE123456789", &[], 0.0);
        let vats: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "DE_VAT_ID")
            .collect();
        assert!(!vats.is_empty(), "Should detect German VAT ID");
    }

    #[test]
    fn test_au_abn_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("ABN: 51 824 753 556", &[], 0.0);
        let abns: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "AU_ABN")
            .collect();
        assert!(!abns.is_empty(), "Should detect Australian ABN");
    }

    #[test]
    fn test_au_tfn_detection() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("TFN: 123 456 782", &[], 0.0);
        let tfns: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "AU_TFN")
            .collect();
        assert!(!tfns.is_empty(), "Should detect Australian TFN");
    }

    #[test]
    fn test_empty_text() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("", &[], 0.0);
        assert!(result.entities.is_empty());
    }

    #[test]
    fn test_no_pii_text() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let result = analyzer.analyze("The weather is nice today", &[], 0.3);
        assert!(result.entities.is_empty());
    }

    #[test]
    fn test_mixed_language_text() {
        let recs = load_spec_recognizers();
        let analyzer = Analyzer::new(recs);
        let text = "张三的邮箱是 zhangsan@example.com，手机号 13800138000";
        let result = analyzer.analyze(text, &[], 0.0);
        let emails: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type.as_str() == "EMAIL_ADDRESS")
            .collect();
        assert!(!emails.is_empty());
    }
}
