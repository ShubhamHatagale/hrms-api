package com.opethic.hrms.HRMSNew.common;

import lombok.Data;

import java.time.LocalDate;
import java.time.Month;

@Data
public class GenerateDates {
    private LocalDate currentdate;

    public GenerateDates() {
        //Getting the current date value
        currentdate = LocalDate.now();
    }

    public LocalDate getCurrentDate() {
        //Getting the current Date
        return currentdate;
    }

    public int getCurrentDay() {
        //Getting the current day
        int currentDay = currentdate.getDayOfMonth();
        return currentDay;
    }

    public String getCurrentMonth() {
        //Getting the current month
        Month currentMonth = currentdate.getMonth();
        return currentMonth.toString();
    }

    public int getCurrentYear() {
        //getting the current year
        int currentYear = currentdate.getYear();
        return currentYear;
    }
}

