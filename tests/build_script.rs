// Nix builds have no .git, so build.rs formats SOURCE_DATE_EPOCH by hand
#[allow(dead_code)]
#[path = "../build.rs"]
mod build;

#[test]
fn formats_every_day_from_1900_to_9999_as_a_utc_date() {
    const DAY: i64 = 86_400;
    for day in -25_567..2_932_897 {
        // Vary the time of day too, so every hour/minute/second gets exercised
        let epoch = day * DAY + (day * 7_919).rem_euclid(DAY);
        let expected = chrono::DateTime::from_timestamp(epoch, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        assert_eq!(build::format_utc(epoch), expected, "epoch {epoch}");
    }
}
