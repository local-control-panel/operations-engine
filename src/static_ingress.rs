//! Caddy route for validated artifacts in the dedicated read-only mount.
use crate::site::Domain;

pub fn render(domain: &Domain, spa: bool) -> String {
    // A missing URL with an extension is an asset, never an SPA navigation.
    // Rewriting only extensionless paths also keeps missing JS/CSS responses 404.
    let fallback = if spa {
        "    @navigation {\n        not path_regexp extension \\.[^/]+$\n        not file {path} {path}/index.html\n    }\n    rewrite @navigation /index.html\n"
    } else {
        ""
    };
    format!(
        "{domain} {{\n    import /etc/wcp/ingress.d/bans/*.caddy\n    root * /srv/wcp-static/{domain}/current\n    header Cache-Control \"no-cache\"\n    header /wcp-release.txt Cache-Control \"no-store\"\n{fallback}    file_server\n}}\n"
    )
}

#[cfg(any())]
mod tests {
    use super::*;
    #[test]
    fn html_has_no_fallback_listing_or_application_handler() {
        let route = render(&Domain::parse("example.test").unwrap(), false);
        assert!(route.contains("root * /srv/wcp-static/example.test/current"));
        assert!(!route.contains("rewrite"));
        for forbidden in ["browse", "php_fastcgi", "reverse_proxy", "/var/www"] {
            assert!(!route.contains(forbidden));
        }
    }
    #[test]
    fn spa_fallback_excludes_extension_paths() {
        let route = render(&Domain::parse("example.test").unwrap(), true);
        assert!(route.contains("not path_regexp extension \\.[^/]+$"));
        assert!(route.contains("rewrite @navigation /index.html"));
    }
    /// Real Caddy test, opt-in because it requires a Docker daemon/image.
    #[test]
    #[ignore = "requires Docker and WCP_STATIC_TEST_IMAGE containing Caddy and curl"]
    fn docker_serves_static_and_spa_without_writable_mount() {
        use std::{fs, process::Command, thread, time::Duration};
        struct Container(String);
        impl Drop for Container {
            fn drop(&mut self) {
                let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
            }
        }
        let image = std::env::var("WCP_STATIC_TEST_IMAGE").expect("set WCP_STATIC_TEST_IMAGE");
        let executable =
            std::env::var("WCP_STATIC_TEST_EXECUTABLE").unwrap_or_else(|_| "caddy".into());
        for spa in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let public = temp.path().join("public/example.test/releases/one");
            fs::create_dir_all(public.join("assets")).unwrap();
            fs::write(public.join("index.html"), "STATIC_INDEX").unwrap();
            fs::write(public.join("assets/app.js"), "STATIC_ASSET").unwrap();
            std::os::unix::fs::symlink(
                "releases/one",
                temp.path().join("public/example.test/current"),
            )
            .unwrap();
            fs::create_dir(temp.path().join("bans")).unwrap();
            let route = render(&Domain::parse("example.test").unwrap(), spa).replacen(
                "example.test {",
                "http://example.test {",
                1,
            );
            fs::write(temp.path().join("Caddyfile"), route).unwrap();
            let container = Container(format!("wcp-static-test-{}", uuid::Uuid::new_v4()));
            let started = Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--name",
                    &container.0,
                    "--entrypoint",
                    &executable,
                    "--mount",
                    &format!(
                        "type=bind,src={},dst=/srv/wcp-static,readonly",
                        temp.path().join("public").display()
                    ),
                    "--mount",
                    &format!(
                        "type=bind,src={},dst=/etc/wcp/ingress.d/bans,readonly",
                        temp.path().join("bans").display()
                    ),
                    "--mount",
                    &format!(
                        "type=bind,src={},dst=/etc/caddy/Caddyfile,readonly",
                        temp.path().join("Caddyfile").display()
                    ),
                    &image,
                    "run",
                    "--config",
                    "/etc/caddy/Caddyfile",
                ])
                .output()
                .unwrap();
            assert!(
                started.status.success(),
                "{}",
                String::from_utf8_lossy(&started.stderr)
            );
            let fetch = |path: &str| {
                Command::new("docker")
                    .args([
                        "exec",
                        &container.0,
                        "curl",
                        "-sS",
                        "--max-time",
                        "2",
                        "-H",
                        "Host: example.test",
                        "-w",
                        "\n%{http_code}",
                        &format!("http://127.0.0.1{path}"),
                    ])
                    .output()
                    .unwrap()
            };
            let mut ready = false;
            for _ in 0..40 {
                let output = fetch("/");
                if output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("STATIC_INDEX")
                {
                    ready = true;
                    break;
                }
                thread::sleep(Duration::from_millis(250));
            }
            if !ready {
                let logs = Command::new("docker")
                    .args(["logs", &container.0])
                    .output()
                    .unwrap();
                panic!("Caddy failed: {}", String::from_utf8_lossy(&logs.stderr));
            }
            for (path, status) in [
                ("/", "200"),
                ("/assets/app.js", "200"),
                ("/assets/missing.js", "404"),
                ("/deep/link", if spa { "200" } else { "404" }),
            ] {
                let output = fetch(path);
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .trim_end()
                        .ends_with(status),
                    "{path}: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            let write = Command::new("docker")
                .args(["exec", &container.0, "touch", "/srv/wcp-static/forbidden"])
                .output()
                .unwrap();
            assert!(
                !write.status.success(),
                "publishing mount must be read-only"
            );
        }
    }
}
