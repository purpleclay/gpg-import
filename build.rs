use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GPG_IMPORT_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GPG_IMPORT_GIT_REF");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // Picks up new commits and checkouts. HEAD changes on checkout, and the
    // branch ref (loose or packed) on commit, even with reflogs disabled.
    // Cargo treats a missing watched file as changed and reruns every build,
    // so only watch paths that exist (none in Nix builds or source archives)
    let branch_ref = run("git", &["symbolic-ref", "-q", "HEAD"]);
    let watched = ["HEAD", "logs/HEAD", "packed-refs"]
        .map(String::from)
        .into_iter()
        .chain(branch_ref);
    for path in watched {
        if let Some(path) = run("git", &["rev-parse", "--git-path", &path])
            && std::path::Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    set_env("GPG_IMPORT_TARGET", env::var("TARGET").ok());
    set_env(
        "GPG_IMPORT_RUSTC",
        run(
            &env::var("RUSTC").unwrap_or_else(|_| "rustc".into()),
            &["-V"],
        ),
    );
    set_env(
        "GPG_IMPORT_GIT_SHA",
        env::var("GPG_IMPORT_GIT_SHA")
            .ok()
            .or_else(|| run("git", &["rev-parse", "HEAD"])),
    );
    set_env(
        "GPG_IMPORT_GIT_REF",
        env::var("GPG_IMPORT_GIT_REF")
            .ok()
            .or_else(|| run("git", &["symbolic-ref", "--short", "-q", "HEAD"])),
    );
    set_env("GPG_IMPORT_COMMIT_DATE", commit_date());
}

fn set_env(key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        println!("cargo:rustc-env={key}={value}");
    }
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .env("TZ", "UTC")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// Prefers git over SOURCE_DATE_EPOCH, as the Nix dev shell exports a fixed
// 1980 timestamp. The Nix sandbox has no .git and sets it to the commit time
fn commit_date() -> Option<String> {
    run(
        "git",
        &[
            "log",
            "-1",
            "--format=%cd",
            "--date=format-local:%Y-%m-%dT%H:%M:%SZ",
        ],
    )
    .filter(|date| !date.is_empty())
    .or_else(|| {
        let epoch = env::var("SOURCE_DATE_EPOCH").ok()?.parse().ok()?;
        Some(format_utc(epoch))
    })
}

// Formats a Unix timestamp as RFC 3339 in UTC, using Howard Hinnant's
// days_from_civil algorithm in reverse
pub fn format_utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}
