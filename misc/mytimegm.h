// timegm() emulation
// (C)2026 Marc.Huber@web.de
//
// No error checking, input is supposed to be sane.

#ifdef HAVE_TIMEGM
#define mytimegm timegm
#else
static inline int leapday(int y)
{
    return ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)) ? 1 : 0;
}

time_t mytimegm(const struct tm *tm)
{
    int year = tm->tm_year + 1900;
    time_t days = tm->tm_mday - 1 + (year - 1970) * 365;

    for (int y = 1972; y < year; y += 4)
	days += leapday(y);
    if (tm->tm_mon < 3)
	days += leapday(year);

    int mdays[12] = { 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    if (tm->tm_mon > 1)
	days += mdays[tm->tm_mon - 2];

    return days * 86400 + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
}
#endif
