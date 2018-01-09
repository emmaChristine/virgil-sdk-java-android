package com.virgilsecurity.sdk.web;

import java.util.Date;
import java.util.concurrent.TimeUnit;

public class TimeSpan {

    private Date date;

    public TimeSpan(Date date) {
        this.date = date;
    }

    public TimeSpan(long milliseconds) {
        this.date = new Date(milliseconds);
    }

    /**
     *
     * @param time in specified by second argument unit. Must be >= 0.
     * @param timeUnit supported TimeUnit: SECONDS, MINUTES, HOURS, DAYS.
     * @return TimeSpan instance with time span in specified unit.
     *         For unsupported units time span in minutes will be returned.
     */
    public static TimeSpan fromTime(int time, TimeUnit timeUnit) {
        if (time <= 0)
            throw new IllegalArgumentException("Time should be more that zero (0)");

        long span;
        switch (timeUnit) {
            case SECONDS:
                span = time * 1000;
            case MINUTES:
                span = time * (1000 * 60);
            case HOURS:
                span = time * (1000 * 60 * 60);
            case DAYS:
                span = time * (1000 * 60 * 60 * 24);
            default:
                span = time * (1000 * 60);
        }

        return new TimeSpan(span);
    }

    public static TimeSpan fromTime(int milliseconds) {
        long span = new Date().getTime() + milliseconds;
        return new TimeSpan(span);
    }

    /**
     * If TimeSpan was cleared - time span will be added to the current time.
     *
     * @param milliseconds
     */
    public void add(long milliseconds) {
        if (date == null)
            date = new Date();

        this.date.setTime(date.getTime() + milliseconds);
    }

    /**
     * If TimeSpan was cleared - time span will be added to the current time.
     *
     * @param time
     * @param timeUnit supported TimeUnit: SECONDS, MINUTES, HOURS, DAYS.
     *                 Otherwise minutes unit will be used as default.
     */
    public void add(int time, TimeUnit timeUnit) {
        if (date == null)
            date = new Date();

        switch (timeUnit) {
            case SECONDS:
                this.date.setTime(date.getTime() + time * 1000);
            case MINUTES:
                this.date.setTime(date.getTime() + time * (1000 * 60));
            case HOURS:
                this.date.setTime(date.getTime() + time * (1000 * 60 * 60));
            case DAYS:
                this.date.setTime(date.getTime() + time * (1000 * 60 * 60 * 24));
            default:
                this.date.setTime(date.getTime() + time * (1000 * 60));
        }
    }

    public void decrease(long milliseconds) {
        this.date.setTime(date.getTime() - milliseconds);
    }

    public void clear() {
        date = null;
    }

    public long getMilliseconds() {
        if (date != null)
            return date.getTime();
        else
            return 0;
    }

    /**
     * Get span in specified TimeUnit
     *
     * @param timeUnit supported TimeUnit: SECONDS, MINUTES, HOURS, DAYS.
     *                 Otherwise milliseconds will be returned.
     * @return Time Span in specified unit.
     * For unsupported units milliseconds will be returned.
     * If TimeSpan was cleared - 0 will be returned.
     */
    public long getSpan(TimeUnit timeUnit) {
        if (date == null)
            return 0;

        switch (timeUnit) {
            case SECONDS:
                return (new Date().getTime() -  date.getTime()) / 1000;
            case MINUTES:
                return date.getTime() / (1000 * 60);
            case HOURS:
                return date.getTime() / (1000 * 60 * 60);
            case DAYS:
                return date.getTime() / (1000 * 60 * 60 * 24);
            default:
                return date.getTime();

        }
    }

    public Date getExpireDate() {
        return date;
    }

    public void setExpireDate(Date date) {
        this.date = date;
    }
}
