package com.opethic.hrms.HRMSNew.scheduler;

import com.opethic.hrms.HRMSNew.models.master.Attendance;
import com.opethic.hrms.HRMSNew.models.master.Break;
import com.opethic.hrms.HRMSNew.models.master.Employee;
import com.opethic.hrms.HRMSNew.repositories.master.AttendanceRepository;
import com.opethic.hrms.HRMSNew.repositories.master.BreakRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeRepository;
import com.opethic.hrms.HRMSNew.services.master.AttendanceService;
import com.opethic.hrms.HRMSNew.services.master.BreakService;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Date;
import java.util.List;

import static java.time.temporal.ChronoUnit.SECONDS;

@Service
public class SchedulerService {
    @Autowired
    private AttendanceService attendanceService;
    @Autowired
    private AttendanceRepository attendanceRepository;
    @Autowired
    private BreakRepository breakRepository;
    @Autowired
    private Utility utility;
    @Autowired
    private BreakService breakService;
    @Autowired
    private EmployeeRepository employeeRepository;

    public void checkEmployeeOutTime() throws ParseException {
        List<Attendance> attendanceList = attendanceRepository.findByCheckOutTimeIsNull();
        System.out.println("Attendance size " + attendanceList.size());
        if (attendanceList.size() > 0) {
            for (Attendance attendance : attendanceList) {
                LocalDate currentDate = LocalDate.now();
                LocalTime currentTime = attendance.getEmployee().getShift().getEndTime();
                LocalDateTime checkOutTime = LocalDateTime.of(currentDate,currentTime);
                System.out.println("Attendance Id: " + attendance.getId());
//                Integer hours = checkDateTimeDiffInTime(attendance.getCheckInTime(), checkOutTime);
//                System.out.println("hours " + hours);
//                LocalTime timeToCompare = attendance.getEmployee().getShift().getThreshold();
                LocalTime latePunchTime = LocalTime.of(14,30,00);
//                if (hours >= 8) {
                    try {
                        endAllRemainingTasks(attendance);
//                        attendance.setTotalTime(totalTime);
                        attendance.setCheckOutTime(checkOutTime);
                        attendance.setUpdatedAt(LocalDateTime.now());

                        String[] timeParts = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), checkOutTime).toString().split(":");
                        int hour = Integer.parseInt(timeParts[0]);
                        int minutes = Integer.parseInt(timeParts[1]);
                        double workedHours = utility.getTimeInDouble(hour+":"+minutes);
                        if(attendance.getCheckInTime().toLocalTime().compareTo(latePunchTime) > 0 || workedHours < 6) {
                            attendance.setIsHalfDay(true);
                        }

                        LocalTime totalTime = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), checkOutTime);
                        if (totalTime != null) {
                            System.out.println("totalTime =>>>>>>>>>>>>>>>>>>>>>>" + totalTime);
                            attendance.setTotalTime(totalTime);
                        }

                        Double lunchTimeInMin = breakRepository.getSumOfBreakTime(attendance.getId());
                        if (lunchTimeInMin != null) {
                            attendance.setLunchTime(lunchTimeInMin);
                            double actualWorkTime = workedHours - lunchTimeInMin;
                            attendance.setActualWorkTime(actualWorkTime);
                        }
                        attendance.setHoursWorked(workedHours);
                        attendance.setLunchTime(lunchTimeInMin);

                        Attendance attendance1 = attendanceRepository.save(attendance);
                        System.out.println("check out updated");
                    } catch (Exception e) {
                        System.out.println("Exception " + e);
                    }
//                }
            }
        }
    }

    private void endAllRemainingTasks(Attendance attendance) throws ParseException {
        List<Break> breakList = breakRepository.findByAttendanceIdAndStatusAndBreakEndTimeIsNull(attendance.getId(), true);

        for (Break mBreak : breakList) {
            if (mBreak != null) {
                mBreak.setBreakStatus("complete");

                LocalTime startTime = mBreak.getBreakStartTime();
                LocalTime endTime = startTime.plusHours(1);
//                LocalTime endTime = LocalTime.now();
                mBreak.setBreakEndTime(endTime);
                System.out.println("SECONDS To MINUTES " + (SECONDS.between(startTime, endTime) / 60));
                double totalTime = SECONDS.between(startTime, endTime) / 60.0;
                double time = totalTime;
                System.out.println("total time in min " + time);
                mBreak.setTotalBreakTime(time);
                mBreak.setUpdatedAt(LocalDateTime.now());
                try {
                    Break savedBreak = breakRepository.save(mBreak);
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("auto end mBreak Exception " + e.getMessage());
                }
            }
        }
    }


    public Integer checkDateTimeDiffInTime(LocalDateTime fromDate, LocalDateTime toDate) throws ParseException {
        System.out.println("fromDate " + fromDate);
        System.out.println("toDate " + toDate);

        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm");
        Date d1 = df.parse(fromDate.toString());
        Date d2 = df.parse(toDate.toString());
        long d = d2.getTime() - d1.getTime();
        long hh = d / (3600 * 1000);
        long mm = (d - hh * 3600 * 1000) / (60 * 1000);
        System.out.printf("\n %02d:%02d \n", hh, mm);

        Integer totalTime = 0;
        if (hh > 23) {
            totalTime = 16;
        } else {
            totalTime = Math.toIntExact(hh);
        }
        System.out.println("totalTime " + totalTime);
        return totalTime;
    }
}
