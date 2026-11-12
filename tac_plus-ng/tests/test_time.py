"""Time ranges: "time" declarations and the "time == <name>" condition, in UTC.

Each test builds its ranges from the current time. A range that must hold
also holds for the next hour, so a test that runs across a boundary (an
hour, a day, a month) gives the same result. Each range that holds adds
"tactest-<name>=yes" to the shell authorization, as in test_policy.
"""

import calendar
import time
import unittest

from test_policy import USER, PolicyTestCase, shell_profile

UUCP_DAYS = ("Su", "Mo", "Tu", "We", "Th", "Fr", "Sa")


def utc_now_and_soon():
    """The current UTC time and the UTC time one hour later, as struct_time."""
    now = time.time()
    return time.gmtime(now), time.gmtime(now + 3600)


def sunday_first(t):
    """The day of week of a struct_time, 0 for Sunday (tm_wday is 0 for Monday)."""
    return (t.tm_wday + 1) % 7


class TimeRanges(PolicyTestCase):
    CONFIG = None

    def holds_at(self, times):
        """Start a daemon with "time <name> { <entry> }" for each (name, entry); return the names that hold."""
        decls = "".join(f"\ttime {name} {{ {entry} }}\n" for name, entry in times)
        conditions = [(name, f"time == {name}") for name, _ in times]
        self.daemon = self.start_daemon(USER + "\ttime zone = UTC\n" + decls + shell_profile(conditions))
        return self.holds()

    def test_cron_numeric_month_is_1_to_12(self):
        """crontab(5) months are 1-12; tm_mon is 0-11, so "11" held in October and "10" in November."""
        now, soon = utc_now_and_soon()
        months = sorted({now.tm_mon, soon.tm_mon})
        numbers = ",".join(map(str, months))
        names = ",".join(calendar.month_abbr[m] for m in months)
        previous = (now.tm_mon - 2) % 12 + 1
        days = ",".join(map(str, sorted({now.tm_mday, soon.tm_mday})))
        self.assertEqual(self.holds_at([
            ("month-number", f'"* * * {numbers} *"'),
            ("month-name", f'"* * * {names} *"'),
            ("previous-month", f'"* * * {previous} *"'),
            ("day-of-month", f'"* * {days} * *"'),
        ]), ["day-of-month", "month-name", "month-number"])

    def test_cron_day_of_week_7_is_sunday_in_a_range(self):
        """crontab(5): 0 and 7 are Sunday. "1-7" became "1-0" and held on no day."""
        self.assertEqual(self.holds_at([
            ("one-to-seven", '"* * * * 1-7"'),
            ("zero-to-six", '"* * * * 0-6"'),
            ("mon-to-sun", '"* * * * Mon-Sun"'),
        ]), ["mon-to-sun", "one-to-seven", "zero-to-six"])


    def test_uucp_day_list_keeps_every_day(self):
        """Each item of "Th,Su" replaced the one before it: only the last day held."""
        now, soon = utc_now_and_soon()
        held = [UUCP_DAYS[d] for d in sorted({sunday_first(now), sunday_first(soon)})]
        other = UUCP_DAYS[(sunday_first(now) + 3) % 7]
        today_first = ",".join([*held, other])
        today_last = ",".join([other, *held])
        self.assertEqual(self.holds_at([
            ("today-first", f'"{today_first}"'),
            ("today-last", f'"{today_last}"'),
            ("other-day", f'"{other}"'),
        ]), ["today-first", "today-last"])

    def test_uucp_time_range_over_two_hours(self):
        """"Any0600-0758" became "* 6 * * *", the last of its cron parts: at 07:01 it did not hold."""
        now = time.gmtime()
        # the current hour is a partial hour of the range, not its last cron part
        if now.tm_min:
            start, end = f"{now.tm_hour:02d}01", f"{(now.tm_hour + 1) % 24:02d}58"
        else:
            start, end = f"{(now.tm_hour - 1) % 24:02d}00", f"{now.tm_hour:02d}58"
        self.assertEqual(self.holds_at([
            ("range", f'"Any{start}-{end}"'),
        ]), ["range"])


if __name__ == "__main__":
    unittest.main()
