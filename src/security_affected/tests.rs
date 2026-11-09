use super::*;

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

fn rule(fix: &str, from: &[char], to: char) -> ImageRule {
    ImageRule {
        fix_id: fix.into(),
        advisory_id: "php-rce".into(),
        component: COMPONENT_PHP_RUNTIME.into(),
        platforms: vec!["linux/amd64".into(), "linux/arm64".into()],
        from_digests: from.iter().map(|c| digest(*c)).collect(),
        to_digest: digest(to),
    }
}

struct Fake {
    runtimes: Result<Vec<Runtime>, Unavailable>,
    images: Vec<(String, ImageFacts)>,
}

impl Inventory for Fake {
    fn runtimes(&self) -> Result<Vec<Runtime>, Unavailable> {
        match &self.runtimes {
            Ok(v) => Ok(v.clone()),
            Err(_) => Err(Unavailable),
        }
    }
    fn image(&self, image_id: &str) -> Result<ImageFacts, Unavailable> {
        self.images
            .iter()
            .find(|(id, _)| id == image_id)
            .map(|(_, f)| f.clone())
            .ok_or(Unavailable)
    }
}

fn runtime(service: &str, image: char) -> Runtime {
    Runtime {
        service: service.into(),
        declared_image: "ghcr.io/x/frankenphp:1".into(),
        image_id: digest(image),
        status: "running".into(),
    }
}

fn facts(platform: &str, digests: &[char]) -> ImageFacts {
    ImageFacts {
        platform: platform.into(),
        digests: digests.iter().map(|c| digest(*c)).collect(),
    }
}

fn one(verdict_of: ImageFacts, rules: &[ImageRule]) -> ComponentRow {
    let fake = Fake {
        runtimes: Ok(vec![runtime("runtime-1", '1')]),
        images: vec![(digest('1'), verdict_of)],
    };
    let mut result = evaluate(&fake, rules, 0, Freshness::Fresh);
    assert_eq!(result.inventory, "ok");
    result.components.remove(0)
}

#[test]
fn a_listed_image_is_affected_and_the_replacement_is_patched() {
    let rules = [rule("f83", &['a', 'b'], 'c')];
    assert_eq!(
        one(facts("linux/amd64", &['b']), &rules).verdict,
        Verdict::Affected
    );
    assert_eq!(
        one(facts("linux/arm64", &['c']), &rules).verdict,
        Verdict::Patched
    );
}

#[test]
fn an_image_the_catalog_does_not_name_is_unknown_never_safe() {
    let rules = [rule("f83", &['a'], 'c')];
    let row = one(facts("linux/amd64", &['d']), &rules);
    assert_eq!(row.verdict, Verdict::Unknown);
    // No registry digest at all (a locally built image).
    assert_eq!(
        one(facts("linux/amd64", &[]), &rules).verdict,
        Verdict::Unknown
    );
}

#[test]
fn a_platform_the_rule_does_not_cover_is_unknown_even_with_a_listed_digest() {
    let rules = [rule("f83", &['a'], 'c')];
    assert_eq!(
        one(facts("linux/s390x", &['a']), &rules).verdict,
        Verdict::Unknown
    );
}

#[test]
fn several_rules_take_the_worst_answer() {
    let rules = [rule("f83", &['a'], 'c'), rule("f84", &['b'], 'd')];
    let row = one(facts("linux/amd64", &['b']), &rules);
    assert_eq!(row.verdict, Verdict::Affected);
    assert_eq!(row.matches.len(), 2);
    assert_eq!(row.matches[0].verdict, Verdict::Unknown);
    assert_eq!(row.matches[1].verdict, Verdict::Affected);
}

#[test]
fn without_a_published_rule_the_runtime_has_no_rule_not_a_clean_bill() {
    assert_eq!(
        one(facts("linux/amd64", &['a']), &[]).verdict,
        Verdict::NoRule
    );
    let other = ImageRule {
        component: "mariadb".into(),
        ..rule("f", &['a'], 'c')
    };
    assert_eq!(
        one(facts("linux/amd64", &['a']), &[other]).verdict,
        Verdict::NoRule
    );
}

#[test]
fn an_image_that_cannot_be_read_is_unknown() {
    let fake = Fake {
        runtimes: Ok(vec![runtime("runtime-1", '1')]),
        images: vec![],
    };
    let row = evaluate(&fake, &[rule("f", &['a'], 'c')], 0, Freshness::Fresh)
        .components
        .remove(0);
    assert_eq!(row.verdict, Verdict::Unknown);
    assert!(row.platform.is_none() && row.digests.is_empty());
}

#[test]
fn an_unavailable_docker_gives_no_rows_and_says_so() {
    let fake = Fake {
        runtimes: Err(Unavailable),
        images: vec![],
    };
    let result = evaluate(&fake, &[rule("f", &['a'], 'c')], 2, Freshness::Expired);
    assert_eq!(result.inventory, "unavailable");
    assert!(result.components.is_empty());
    assert_eq!((result.rule_count, result.skipped_rules), (1, 2));
    assert_eq!(result.freshness, Freshness::Expired);
}

#[test]
fn only_runtime_services_are_components_and_ids_are_checked() {
    let json = format!(
        r#"[{{"Image":"{a}","Config":{{"Image":"i","Labels":{{"com.docker.compose.service":"runtime-2"}}}},"State":{{"Status":"running"}}}},
           {{"Image":"{a}","Config":{{"Image":"i","Labels":{{"com.docker.compose.service":"ingress"}}}},"State":{{"Status":"running"}}}},
           {{"Image":"{a}","Config":{{"Image":"i","Labels":{{"com.docker.compose.service":"runtime-x"}}}},"State":{{"Status":"running"}}}},
           {{"Image":"{a}","Config":{{"Image":"i","Labels":{{"com.docker.compose.service":"runtime-10"}}}},"State":{{"Status":"exited"}}}}]"#,
        a = digest('a')
    );
    let runtimes = parse_runtimes(json.as_bytes()).unwrap();
    let services: Vec<&str> = runtimes.iter().map(|r| r.service.as_str()).collect();
    assert_eq!(services, ["runtime-10", "runtime-2"]);
    assert!(parse_runtimes(br#"[{"Image":"latest","Config":{"Image":"i","Labels":{"com.docker.compose.service":"runtime-1"}},"State":{"Status":"running"}}]"#).is_none());
    assert!(parse_runtimes(b"not json").is_none());
}

#[test]
fn registry_digests_are_reduced_to_their_hash_and_malformed_ones_dropped() {
    let json = format!(
        r#"[{{"Os":"linux","Architecture":"arm64","RepoDigests":["ghcr.io/x/frankenphp@{a}","other/y@sha256:short","nodigest"]}}]"#,
        a = digest('a')
    );
    let facts = parse_image(json.as_bytes()).unwrap();
    assert_eq!(facts.platform, "linux/arm64");
    assert_eq!(facts.digests, [digest('a')]);
    assert!(parse_image(br#"[{"Os":"linux"}]"#).is_none());
}
