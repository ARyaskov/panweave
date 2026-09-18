//! Civil date arithmetic on UTCTime (seconds since 2000-01-01 00:00:00
//! UTC): days from the epoch to (year, month, day) and back (proleptic
//! Gregorian, Howard Hinnant's algorithms), weekdays and the calendar
//! cluster's [`Date`] of an instant.

use crate::clusters::calendar::Date;

/// Days from 1970-01-01 to 2000-01-01.
const EPOCH_DAYS_1970: i64 = 10_957;

/// The seconds of a day.
pub const DAY: u32 = 86_400;

/// (year, month, day) of the day `days` after 2000-01-01.
pub fn from_days(days: i64) -> (i64, u32, u32) {
    let z = days + EPOCH_DAYS_1970 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days after 2000-01-01 of (year, month, day).
pub fn to_days(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468 - EPOCH_DAYS_1970
}

/// Days in a month.
pub fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// The weekday of the day `days` after 2000-01-01 (a Saturday), 1 =
/// Monday to 7 = Sunday as the calendar cluster counts.
pub fn weekday(days: i64) -> u8 {
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let monday_based = (days + 5).rem_euclid(7) as u8;
    monday_based + 1
}

/// The calendar cluster [`Date`] and minute of the day of a UTCTime
/// instant (`None` for a year the date's octet cannot hold).
pub fn date_of(utc: u32) -> Option<(Date, u16)> {
    let days = i64::from(utc / DAY);
    let (y, m, d) = from_days(days);
    let year = u8::try_from(y - 1900).ok()?;
    #[allow(clippy::cast_possible_truncation)]
    let minute = ((utc % DAY) / 60) as u16;
    Some((
        Date {
            year,
            month: u8::try_from(m).ok()?,
            day: u8::try_from(d).ok()?,
            weekday: weekday(days),
        },
        minute,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip_and_weekdays_count_from_monday() {
        assert_eq!(from_days(0), (2000, 1, 1));
        assert_eq!(weekday(0), 6, "2000-01-01 was a Saturday");
        assert_eq!(weekday(2), 1, "2000-01-03 a Monday");
        assert_eq!(to_days(2024, 2, 29), 8825);
        assert_eq!(from_days(8825), (2024, 2, 29));
        assert_eq!(days_in_month(2100, 2), 28);
        let (date, minute) = date_of(2 * DAY + 61 * 60).unwrap();
        assert_eq!(
            (date.year, date.month, date.day, date.weekday),
            (100, 1, 3, 1)
        );
        assert_eq!(minute, 61);
    }
}
