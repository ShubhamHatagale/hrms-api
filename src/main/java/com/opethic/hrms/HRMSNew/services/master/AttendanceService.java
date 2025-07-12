package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.config.AppConfig;
import com.opethic.hrms.HRMSNew.fileConfig.FileStorageProperties;
import com.opethic.hrms.HRMSNew.fileConfig.FileStorageService;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.WeekDaysRepository;
import com.opethic.hrms.HRMSNew.repositories.config.AppConfigRepository;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import com.opethic.hrms.HRMSNew.views.AttendanceView;
import org.apache.commons.math3.util.Precision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.time.temporal.ChronoUnit.SECONDS;

@Service
public class AttendanceService {

    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AttendanceRepository attendanceRepository;
    @Autowired
    private Utility utility;
    @Autowired
    FileStorageService fileStorageService;
    @Autowired
    private BreakMasterRepository breakMasterRepository;
    private static final Logger attendanceLogger = LoggerFactory.getLogger(AttendanceService.class);
    @Autowired
    private AppConfigRepository appConfigRepository;
    @Autowired
    private BreakRepository breakRepository;
    @Autowired
    private EmployeeLeaveRepository employeeLeaveRepository;
    @Autowired
    private EmployeeRepository employeeRepository;
    @Autowired
    private ShiftRepository shiftRepository;
    @Autowired
    private EmployeePayrollRepository employeePayrollRepository;
    @Autowired
    private WeekDaysRepository weekDaysRepository;
    @Autowired
    private EmployeePayheadRepository employeePayheadRepository;

    public JsonObject saveAttendance(MultipartHttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        FileStorageProperties fileStorageProperties = new FileStorageProperties();
        Map<String, String[]> paramMap = request.getParameterMap();
        LocalTime timeToCompare = employee.getShift().getGraceInPeriod();
        LocalTime latePunchTime = employee.getShift().getSecondHalfPunchInTime();

        try {
            LocalDate attendanceDate = LocalDate.now();
            int daysInMonth = getTotalDaysFromYearAndMonth(attendanceDate.getYear(), attendanceDate.getMonthValue());
            System.out.println("totalDays" + daysInMonth);

            List<AppConfig> list = new ArrayList<>();
            if (employee.getBranch() != null) {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchId(employee.getCompany().getId(), true, employee.getBranch().getId());
            } else {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchIsNull(employee.getCompany().getId(), true);
            }

            Double wagesPerDay = employee.getExpectedSalary() / daysInMonth;
            System.out.println("wagesPerDay =" + wagesPerDay);

            double wagesPerHour = (wagesPerDay / utility.getTimeInDouble(employee.getShift().getWorkingHours().toString()));

            if (Boolean.parseBoolean(request.getParameter("attendanceStatus"))) {
                Attendance attendanceExist = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee.getId(), LocalDate.now(), true);

                if (attendanceExist == null) {
                    Attendance attendance = new Attendance();
                    attendance.setAttendanceDate(LocalDate.now());
                    attendance.setEmployee(employee);
                    attendance.setShift(employee.getShift());
                    LocalDateTime inTime = LocalDateTime.now();
                    System.out.println("inTime " + inTime);
                    attendance.setCheckInTime(inTime);
                    attendance.setWagesPerDay(wagesPerDay);
                    attendance.setWagesPerHour(wagesPerHour);
                    if(list.stream().filter(p -> p.getConfigName().equals("late_attendance_deduction") && p.getConfigValue() == 1) != null){
                        if(inTime.toLocalTime().compareTo(timeToCompare) > 0){
                            if(inTime.toLocalTime().compareTo(latePunchTime) > 0)
                                attendance.setIsLate(false);
                            else
                                attendance.setIsLate(true);
                        }
                    }
                    attendance.setCreatedBy(employee.getId());
                    attendance.setCreatedAt(LocalDateTime.now());
                    attendance.setStatus(true);
                    if (request.getFile("punch_in_image") != null) {
                        MultipartFile image = request.getFile("punch_in_image");
                        fileStorageProperties.setUploadDir("." + File.separator + "uploads" + File.separator + "punch-in" + File.separator);
                        String imagePath = fileStorageService.storeFile(image, fileStorageProperties);
                        if (imagePath != null) {
                            attendance.setPunchInImage(File.separator + "uploads" + File.separator + "punch-in" + File.separator + imagePath);
                        } else {
                            responseMessage.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
                            responseMessage.addProperty("message","Failed to upload image. Please try again!");
                            return responseMessage;
                        }
                    }
                    try {
                        Attendance attendance1 = attendanceRepository.save(attendance);
                        if(attendance1!=null) {
                            responseMessage.addProperty("message", "Check-in successfully");
                            responseMessage.addProperty("attendance_id", attendance1.getId());
                            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
                        } else {
                            responseMessage.addProperty("message", "Trouble while checking in");
                            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Exception " + e.getMessage());
                        responseMessage.addProperty("message","Failed to check-in");
                        responseMessage.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                } else {
                    responseMessage.addProperty("message","Already checked In");
                    responseMessage.addProperty("responseStatus",HttpStatus.BAD_REQUEST.value());
                }
            } else if (!Boolean.parseBoolean(request.getParameter( "attendanceStatus"))) {
                Attendance attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee.getId(), LocalDate.now(), true);
                if(attendance != null) {
                    if (attendance.getCheckInTime() != null && attendance.getCheckOutTime() == null) {
                        try {
                            LocalDateTime outTime = LocalDateTime.now();
                            System.out.println("outTime " + outTime);
                            LocalTime timeDiff = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), outTime);
                            String[] timeParts = timeDiff.toString().split(":");
                            int hours = Integer.parseInt(timeParts[0]);
                            int minutes = Integer.parseInt(timeParts[1]);
                            double workedHours = utility.getTimeInDouble(hours + ":" + minutes);
                            if (attendance.getCheckInTime().toLocalTime().compareTo(latePunchTime) > 0 || workedHours < 6) {
                                attendance.setIsHalfDay(true);
                            }
                            attendance.setCheckOutTime(outTime);
                            attendance.setUpdatedAt(LocalDateTime.now());
                            attendance.setUpdatedBy(employee.getId());
                            if (request.getFile("punch_out_image") != null) {
                                MultipartFile image = request.getFile("punch_out_image");
                                fileStorageProperties.setUploadDir("." + File.separator + "uploads" + File.separator + "punch-out" + File.separator);
                                String imagePath = fileStorageService.storeFile(image, fileStorageProperties);
                                if (imagePath != null) {
                                    attendance.setPunchOutImage(File.separator + "uploads" + File.separator + "punch-out" + File.separator + imagePath);
                                } else {
                                    responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                                    responseMessage.addProperty("message", "Failed to upload image. Please try again!");
                                    return responseMessage;
                                }
                            }

                            LocalTime totalTime = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), outTime);
                            if (totalTime != null) {
                                System.out.println("totalTime =>>>>>>>>>>>>>>>>>>>>>>" + totalTime);
                                attendance.setTotalTime(totalTime);
                            }

                            if (list.stream().filter(p -> p.getConfigName().equals("overtime_calculation") && p.getConfigValue() == 1) != null) {
                                if (workedHours > (employee.getShift().getWorkingHours().getHour() + employee.getShift().getWorkingHours().getMinute())) {
                                    LocalTime otDiff = utility.getTimeDiffFromTimes(employee.getShift().getEndTime(), outTime.toLocalTime());
                                    int hour = otDiff.getHour();
                                    System.out.println("\nHour is = " + hour);
                                    int minute = otDiff.getMinute();
                                    System.out.println("Minute is = " + minute);
                                    int otTime = (hour * 60) + minute;
                                    attendance.setOvertime(otTime);
                                    attendance.setOvertimeAmount(otTime * 1.0);
                                } else {
                                    attendance.setOvertime(0);
                                    attendance.setOvertimeAmount(0.0);
                                }
                            }

                            Double lunchTimeInMin = breakRepository.getSumOfBreakTime(attendance.getId());
                            if (lunchTimeInMin != null) {
                                attendance.setLunchTime(lunchTimeInMin);
                                double actualWorkTime = workedHours - lunchTimeInMin;
                                attendance.setActualWorkTime(actualWorkTime);
                            }
                            attendance.setHoursWorked(workedHours);

                            if (employee.getWagesOptions().equals("hour")) {
                                double wagesHourBasis = workedHours * wagesPerHour;
                                attendance.setWagesPerHour(wagesPerHour);
                                attendance.setWagesHourBasis(wagesHourBasis);
                            } else {
                                attendance.setWagesPerDay(wagesPerDay);
                            }

                            if (paramMap.containsKey("remark")) {
                                String remark = request.getParameter("remark");
                                if (!remark.equalsIgnoreCase("")) {
                                    attendance.setRemark(remark);
                                }
                            }

                            Attendance attendance1 = attendanceRepository.save(attendance);
                            if (attendance1 != null) {
                                responseMessage.addProperty("message", "Checkout successfully");
                                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
                            } else {
                                responseMessage.addProperty("message", "Trouble while checking out");
                                responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                            }
                        } catch (Exception e) {

                            attendanceLogger.error("Failed to checkout Exception ===> " + e);
                            e.printStackTrace();
                            System.out.println("Exception " + e.getMessage());
                            responseMessage.addProperty("message", "Failed to checkout");
                            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                        }
                    } else if (attendance.getCheckInTime() != null && attendance.getCheckOutTime() != null) {
                        attendanceLogger.info("attendnace", "You already done checkout ...........");
                        responseMessage.addProperty("message", "You already done checkout");
                        responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
                    } else {
                        responseMessage.addProperty("message", "Please process checkin first");
                        responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
                    }
                } else {
//                    attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee.getId(), LocalDate.now(), true);
                    responseMessage.addProperty("message", "Your previous is not checked out");
                    responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
                }
            }
        } catch (Exception e) {
            attendanceLogger.error("Data inconsistency, please validate data ===> " + e);
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message","Data inconsistency, please validate data");
            responseMessage.addProperty("responseStatus",HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public Integer getTotalDaysFromYearAndMonth(int userYear, int userMonth) {
        // Get the number of days in that month
        YearMonth yearMonthObject = YearMonth.of(userYear, userMonth);
        int daysInMonth = yearMonthObject.lengthOfMonth(); //28
        return daysInMonth;
    }

    public JsonObject checkAttendanceStatus(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));

        try {
            LocalDate localDate = LocalDate.now();
            System.out.println("localDate " + localDate);
            JsonObject jsonObject = new JsonObject();
            Long attendanceId = Long.valueOf(0);
            Boolean todayAttendance = false;
            Boolean checkInStatus = false;
            Boolean checkOutStatus = false;
            LocalDateTime checkInTime = null;
            LocalDateTime checkOutTime = null;
            LocalTime totalTime = null;

            LocalTime fromTime = employee.getShift().getStartTime();
            LocalTime toTime = employee.getShift().getEndTime();
            LocalTime totalHours = employee.getShift().getWorkingHours();

            Attendance attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee.getId(), LocalDate.now(), true);
            if (attendance != null) {
                todayAttendance = true;
                attendanceId = attendance.getId();
                if (attendance.getCheckInTime() != null) {
                    checkInStatus = true;
                    checkInTime = attendance.getCheckInTime();
                }
                if (attendance.getCheckOutTime() != null) {
                    checkOutStatus = true;
                    checkOutTime = attendance.getCheckOutTime();
                    totalTime = utility.getDateTimeDiffInTime(checkInTime, checkOutTime);
                }
            } else {
                Attendance oldAttendance = attendanceRepository.findLastRecordOfEmployeeWithoutCheckOut(employee.getId(), true);
                if (oldAttendance != null) {
                    attendanceId = oldAttendance.getId();
                    if (oldAttendance.getCheckInTime() != null) {
                        checkInStatus = true;
                        checkInTime = oldAttendance.getCheckInTime();
                    }
                    if (oldAttendance.getCheckOutTime() != null) {
                        checkOutStatus = true;
                        checkOutTime = oldAttendance.getCheckOutTime();
                    }
                }
                todayAttendance = false;
            }

            Attendance oldSecondAttendance = attendanceRepository.findLastSecondRecordOfEmployee(employee.getId(), localDate);
            if (oldSecondAttendance != null) {
                jsonObject.addProperty("oldAttendanceDate", String.valueOf(oldSecondAttendance.getAttendanceDate()));
                jsonObject.addProperty("oldCheckInTime", String.valueOf(oldSecondAttendance.getCheckInTime()));
                jsonObject.addProperty("oldCheckOutTime", String.valueOf(oldSecondAttendance.getCheckOutTime()));
            } else {
                jsonObject.addProperty("oldAttendanceDate", "null");
                jsonObject.addProperty("oldCheckInTime", "null");
                jsonObject.addProperty("oldCheckOutTime", "null");
            }

            jsonObject.addProperty("currentTime", String.valueOf(LocalTime.now()));
            jsonObject.addProperty("currentDate", String.valueOf(LocalDate.now()));
            jsonObject.addProperty("shiftFromTime", String.valueOf(fromTime));
            jsonObject.addProperty("shiftToTime", String.valueOf(toTime));
            jsonObject.addProperty("shiftTotalHours", String.valueOf(totalHours));
            jsonObject.addProperty("todayAttendance", todayAttendance);
            jsonObject.addProperty("attendanceId", attendanceId);
            jsonObject.addProperty("checkInStatus", checkInStatus);
            jsonObject.addProperty("checkInTime", checkInTime != null ? checkInTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "");
            jsonObject.addProperty("checkOutTime", checkOutTime != null ? checkOutTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "");
            jsonObject.addProperty("checkOutStatus", checkOutStatus);
            jsonObject.addProperty("totalTime", totalTime != null ? totalTime.toString() : "");

            System.out.println("jsonObject " + jsonObject);
            responseMessage.add("response", jsonObject);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            attendanceLogger.error("Data inconsistency, please validate data " + e);
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Data inconsistency, please validate data");
            responseMessage.addProperty("responseStatus", HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public JsonObject getAttendanceList(Map<String, String> jsonRequest, HttpServletRequest request) {
        System.out.println("jsonRequest " + jsonRequest);
        JsonObject response = new JsonObject();
        JsonObject res = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        JsonArray taskList = new JsonArray();
        List<WeekDays> weekDaysList = weekDaysRepository.findAll();
        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            System.out.println("employee.getId() " + employee.getId());

            LocalDate currentDate = LocalDate.now();
            Integer totalDays = 0;
            Integer pDays = 0;
            Integer lDays = 0;
            Boolean flag = false;
            if (!jsonRequest.get("currentMonth").equals("")) {
                System.out.println("jsonRequest " + jsonRequest.get("currentMonth"));
                String[] currentMonth = jsonRequest.get("currentMonth").split("-");
                String userMonth = currentMonth[0];
                String userYear = currentMonth[1];
                String userDay = "01";

                String newUserDate = userYear + "-" + userMonth + "-" + userDay;
                System.out.println("newUserDate " + newUserDate);
                currentDate = LocalDate.parse(newUserDate);
                totalDays = getTotalDaysFromYearAndMonth(Integer.parseInt(userYear), Integer.parseInt(userMonth));
                flag = true;
            }
            System.out.println("currentDate " + currentDate);
            LocalDate firstDateOfMonth = currentDate.withDayOfMonth(1);
            System.out.println("firstDateOfMonth " + firstDateOfMonth);
            LocalDate lastDateOfMonth = currentDate.withDayOfMonth(currentDate.lengthOfMonth());
            System.out.println("lastDateOfMonth " + lastDateOfMonth);
            totalDays = getTotalDaysFromYearAndMonth(currentDate.getYear(), currentDate.getMonthValue());

            if (flag) {
                currentDate = lastDateOfMonth;
                totalDays = getTotalDaysFromYearAndMonth(currentDate.getYear(), currentDate.getMonthValue());
            }
            currentDate = currentDate.plusDays(1);

            List<LocalDate> localDates = firstDateOfMonth.datesUntil(currentDate).collect(Collectors.toList());
            System.out.println("dates " + localDates);

            for (LocalDate localDate : localDates) {
                System.out.println("localDate " + localDate);
                Attendance attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee.getId(), localDate, true);
                if (attendance != null) {
                    JsonObject jsonObject = new JsonObject();
                    if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())) {
                        jsonObject.addProperty("attendanceStatus", "WP");
                    } else {
                        jsonObject.addProperty("attendanceStatus", "P");
                    }
                    jsonObject.addProperty("shiftName", attendance.getShift() != null ? attendance.getShift().getShiftName() : "");
                    jsonObject.addProperty("attendanceId", attendance.getId());
                    jsonObject.addProperty("attendanceDate", String.valueOf(attendance.getAttendanceDate()));
                    jsonObject.addProperty("checkInTime", attendance.getCheckInTime() != null ? attendance.getCheckInTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "");
                    jsonObject.addProperty("checkOutTime", attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "");
//                    jsonObject.addProperty("totalTime", attendance.getTotalTime() != null ? String.valueOf(attendance.getTotalTime()) : "");
                    LocalTime totalTime = null;
                    if(attendance.getCheckOutTime() != null)
                        totalTime = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), attendance.getCheckOutTime());
                    jsonObject.addProperty("totalTime", totalTime != null ? totalTime.toString() : "");
                    jsonObject.addProperty("status", attendance.getAttendanceStatus() != null ? attendance.getAttendanceStatus() : "pending");
                    jsonObject.addProperty("workingHours", attendance.getHoursWorked() != null ? Precision.round(attendance.getHoursWorked(), 2) : 0);
                    jsonObject.addProperty("salaryType", attendance.getSalaryType() != null ? attendance.getSalaryType() : "");
                    jsonObject.addProperty("daySalary", attendance.getSalaryType() != null ? attendance.getSalaryType().equals("hour") ? Precision.round(attendance.getWagesHourBasis(), 2) : Precision.round(attendance.getWagesPerDay(), 2):null);
                    jsonObject.addProperty("lunchTimeInMin", attendance.getLunchTime() != null ? attendance.getLunchTime() : null);

                    List<Break> breakList = breakRepository.findByAttendanceIdAndStatus(attendance.getId(), true);
                    JsonArray breakArray = new JsonArray();
                    for(Break mBreak : breakList) {
                        JsonObject breakObj = new JsonObject();
                        if (mBreak != null) {
                            breakObj.addProperty("id", mBreak.getId());
                            breakObj.addProperty("breakStartTime", mBreak.getBreakStartTime().toString());
                            breakObj.addProperty("breakEndTime", mBreak.getBreakEndTime().toString());
                            breakObj.addProperty("totalBreakTime", mBreak.getTotalBreakTime().toString());
                            breakArray.add(breakObj);
                        }
                    }
                    jsonObject.add("breakArray",breakArray);
                    jsonArray.add(jsonObject);
                    pDays++;
                } else {
                    JsonObject jsonObject = new JsonObject();
                    EmployeeLeave employeeLeave = employeeLeaveRepository.findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqual(employee.getId(), localDate, localDate);
                    if (employeeLeave != null) {
                        if (employeeLeave.getLeaveStatus().equals("Approved")) {
                            jsonObject.addProperty("attendanceStatus", "PL");
                            jsonObject.addProperty("shiftName", employee.getShift() != null ? employee.getShift().getShiftName() : "");
                            jsonObject.addProperty("attendanceDate", String.valueOf(localDate));
                            jsonObject.addProperty("leaveName", employeeLeave.getLeaveMaster().getName());
                            jsonObject.addProperty("leaveReason", employeeLeave.getReason());
                            jsonObject.addProperty("approvedBy", employeeLeave.getLeaveApprovedBy());
                            jsonObject.addProperty("leaveRemark", employeeLeave.getLeaveRemark());

                            lDays++;
                        } else {
                            jsonObject.addProperty("attendanceStatus", "L");
                            jsonObject.addProperty("shiftName", employee.getShift() != null ? employeeLeave.getLeaveMaster().getName() : "");
                            jsonObject.addProperty("attendanceDate", String.valueOf(localDate));
                        }
                    } else if (localDate.isBefore(LocalDate.now())) {
                        if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())) {
                            jsonObject.addProperty("attendanceStatus", "WO");
                        } else {
                            jsonObject.addProperty("attendanceStatus", "A");
                        }
                        jsonObject.addProperty("shiftName", employee.getShift() != null ? employee.getShift().getShiftName() : "");
                        jsonObject.addProperty("attendanceDate", String.valueOf(localDate));
                    }
                    System.out.println("jsonObject.size() " + jsonObject.size());
                    if (jsonObject.size() > 0)
                        jsonArray.add(jsonObject);
                }
            }
            res.add("list", jsonArray);
            res.add("taskList", taskList);
            res.addProperty("totalDays", totalDays);
            res.addProperty("pDays", pDays);
            res.addProperty("lDays", lDays);

            response.add("response", res);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            attendanceLogger.error("attendnaceList " + e);
            System.out.println("exception  " + e.getMessage());
            e.printStackTrace();
        }
        return response;
    }

    public JsonObject getEmpMonthlyPresenty(Map<String, String> jsonRequest, HttpServletRequest request) {
        System.out.println("jsonRequest " + jsonRequest);
        JsonObject response = new JsonObject();
        JsonObject res = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<WeekDays> weekDaysList = weekDaysRepository.findAll();
        JsonArray pEmpArr = new JsonArray();
        JsonArray hEmpArr = new JsonArray();
        JsonArray lEmpArr = new JsonArray();
        JsonArray abEmpArr = new JsonArray();
        JsonArray totalabandl = new JsonArray();
        JsonArray abPer = new JsonArray();
        try {
            int totalDays = 0;
            int sumofAllEmployeeTotalDays = 0;
            int sumOfAllEmployeePresenty = 0;
            double sumOfAllEmployeeAbsenty = 0.0;
            int sumOfAllEmployeeLeaves = 0;
            double sumOfAllEmployeeHalfDays = 0.0;

            Double totalEmployees = 0.0;
            Double presentEmployees = 0.0;
            int leaveEmployees = 0;
            int halfDayEmployees = 0;
            Double absentEmployees = 0.0;
            Double totalAbsentAndLeave = 0.0;

            String[] currentMonth = jsonRequest.get("currentMonth").split("-");
            String userMonth = currentMonth[1];
            String userYear = currentMonth[0];
            String userDay = "01";
            String newUserDate = userYear + "-" + userMonth + "-" + userDay;
            LocalDate currentDate = LocalDate.parse(newUserDate);
            totalDays = getTotalDaysFromYearAndMonth(Integer.parseInt(userYear), Integer.parseInt(userMonth));
            LocalDate firstDateOfMonth = currentDate.withDayOfMonth(1);
            LocalDate lastDateOfMonth = currentDate.withDayOfMonth(currentDate.lengthOfMonth()).plusDays(1);
            List<LocalDate> localDates = firstDateOfMonth.datesUntil(lastDateOfMonth).collect(Collectors.toList());
            List<LocalDate> localDates1 = firstDateOfMonth.datesUntil(lastDateOfMonth).collect(Collectors.toList());
            JsonObject jsonObject = new JsonObject();

            if (jsonRequest.get("employeeId").equalsIgnoreCase("all")) {
                List<Employee> employees = null;
                if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                    employees = employeeRepository.findByCompanyIdAndStatusOrderByFirstNameAsc(users.getCompany().getId(), true);
                } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                    employees = employeeRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
                }

                Double absentPer = 0.0;
                if (employees.size() > 0) {
                    for (LocalDate localDate : localDates1) {
                        totalEmployees = employeeRepository.getEmployeeCount(true, users.getCompany().getId());
                        presentEmployees = attendanceRepository.getPresentEmployeeCount(localDate, users.getCompany().getId());
                        leaveEmployees = attendanceRepository.getLeaveEmployeeCount(localDate, users.getCompany().getId());
                        halfDayEmployees = attendanceRepository.getHalfDayEmployeeCount(localDate);
                        absentEmployees = totalEmployees - (presentEmployees + leaveEmployees);
                        totalAbsentAndLeave = leaveEmployees + absentEmployees;

                        if (presentEmployees > 0) {
                            absentPer = Precision.round(Double.valueOf(totalAbsentAndLeave) / Double.valueOf(presentEmployees) * 100, 0);
                            System.out.println(" absentPer " + absentPer);
                        }
                        pEmpArr.add(presentEmployees);
                        lEmpArr.add(leaveEmployees);
                        abEmpArr.add(absentEmployees);
                        totalabandl.add(totalAbsentAndLeave);
                        abPer.add(absentPer);
                        hEmpArr.add(halfDayEmployees);
                    }
                }
                for (Employee employee1 : employees) {
                    Integer pDays = 0;
                    Integer lDays = 0;
                    double hDays = 0;
                    Integer extraDays = 0;
                    double extraHalfDays = 0;
                    double aDays = 0.0;
                    Integer weeklyOffDays = 0;
                    Integer woDays = 0;
                    JsonObject empObj = new JsonObject();

                    empObj.addProperty("id", employee1.getId());
                    empObj.addProperty("employeeName", utility.getEmployeeName(employee1));

                    int i = 0;
                    for (LocalDate localDate : localDates) {
                        Attendance attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee1.getId(), localDate, true);
                        if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee1.getWeeklyOffDay()).getName())){
                            weeklyOffDays++;
                        }
                        if (attendance != null) {
                            if (attendance.getAttendanceDate().getDayOfWeek().toString().contains(weekDaysList.get(employee1.getWeeklyOffDay()).getName())) {
                                if(attendance.getIsHalfDay() != null && attendance.getIsHalfDay()) {
                                    jsonObject.addProperty("attendanceStatus" + i, "EH");
                                    empObj.addProperty("attendanceStatus" + i, "EH");
                                    extraHalfDays++;
                                } else {
                                    jsonObject.addProperty("attendanceStatus" + i, "EP");
                                    empObj.addProperty("attendanceStatus" + i, "EP");
                                    extraDays++;
                                }
                            } else {
                                if(attendance.getIsHalfDay() != null && attendance.getIsHalfDay()){
                                    jsonObject.addProperty("attendanceStatus" + i, "H");
                                    empObj.addProperty("attendanceStatus" + i, "H");
                                    hDays++;
                                    aDays+=0.5;
                                } else {
                                    jsonObject.addProperty("attendanceStatus" + i, "P");
                                    empObj.addProperty("attendanceStatus" + i, "P");
                                    pDays++;
                                }
                            }
                        } else {
                            EmployeeLeave employeeLeave = employeeLeaveRepository.findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqualAndLeaveStatus(employee1.getId(), localDate, localDate, "Approved");
                            if (employeeLeave != null) {
                                empObj.addProperty("attendanceStatus" + i, "L");
                                lDays++;
                            } else if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee1.getWeeklyOffDay()).getName())) {
                                empObj.addProperty("attendanceStatus" + i, "W/O");
                                woDays++;
                            } else {
                                empObj.addProperty("attendanceStatus" + i, "A");
                                aDays++;
                            }
                        }
                        i++;

                    }
                    double totalDaysOfEmployee = pDays + lDays + aDays + hDays + extraDays + extraHalfDays;
                    sumofAllEmployeeTotalDays = sumofAllEmployeeTotalDays + totalDays;
                    sumOfAllEmployeePresenty = sumOfAllEmployeePresenty + pDays;
                    sumOfAllEmployeeAbsenty = sumOfAllEmployeeAbsenty + aDays;
                    sumOfAllEmployeeLeaves = sumOfAllEmployeeLeaves + lDays;
                    sumOfAllEmployeeHalfDays = sumOfAllEmployeeHalfDays + hDays;
                    empObj.addProperty("id", employee1.getId());
                    empObj.addProperty("employeeName", utility.getEmployeeName(employee1));
                    empObj.addProperty("pDays", pDays);
                    empObj.addProperty("lDays", lDays);
                    empObj.addProperty("hDays", hDays);
                    empObj.addProperty("aDays", aDays);
                    empObj.addProperty("extraDays", extraDays);
                    empObj.addProperty("extraHalfDays", extraHalfDays);
                    empObj.addProperty("weeklyOffDays", weeklyOffDays);
                    empObj.addProperty("totalDays", totalDays);
                    empObj.addProperty("woDays", woDays);
                    empObj.addProperty("totalDaysOfEmployee", totalDaysOfEmployee);
                    jsonArray.add(empObj);
                }
            } else {
                Long employeeId = Long.valueOf(jsonRequest.get("employeeId"));
                Employee employee = employeeRepository.findByIdAndStatus(employeeId, true);
                Integer pDays = 0;
                Integer lDays = 0;
                double hDays = 0;
                Integer extraDays = 0;
                double extraHalfDays = 0;
                double aDays = 0;
                Integer weeklyOffDays = 0;
                Integer woDays = 0;
                if (employee != null) {
                    int i = 0;
                    for (LocalDate localDate : localDates) {
                        System.out.println(" localDate " + localDate);
                        Attendance attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employee.getId(), localDate, true);
                        if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())){
                            weeklyOffDays++;
                        }
                        if (attendance != null) {
                            System.out.println("attendanceStatus =>" + i);
                            if (attendance.getAttendanceDate().getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())) {
                                if(attendance.getIsHalfDay() != null && attendance.getIsHalfDay()) {
                                    jsonObject.addProperty("attendanceStatus" + i, "EH");
                                    extraHalfDays++;
                                } else {
                                    jsonObject.addProperty("attendanceStatus" + i, "EP");
                                    extraDays++;
                                }
                            } else {
                                if(attendance.getIsHalfDay() != null && attendance.getIsHalfDay()){
                                    jsonObject.addProperty("attendanceStatus" + i, "H");
                                    hDays++;
                                    aDays+=0.5;
                                } else {
                                    jsonObject.addProperty("attendanceStatus" + i, "P");
                                    pDays++;
                                }
                            }
                        } else {
                            EmployeeLeave employeeLeave = employeeLeaveRepository.findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqual(employee.getId(), localDate, localDate);
                            if (employeeLeave != null) {
                                if (employeeLeave.getLeaveStatus().equals("Approved")) {
                                    jsonObject.addProperty("attendanceStatus" + i, "L");
                                    lDays++;
                                } else {
                                    jsonObject.addProperty("attendanceStatus" + i, "A");
                                    aDays++;
                                }
                            } else if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())) {
                                jsonObject.addProperty("attendanceStatus" + i, "W/O");
                                woDays++;
                            } else {
                                jsonObject.addProperty("attendanceStatus" + i, "A");
                                aDays++;
                            }
                        }
                        i++;
                    }
                    double totalDaysOfEmployee = pDays + lDays + aDays + hDays + extraDays + extraHalfDays;
                    jsonObject.addProperty("employeeName", utility.getEmployeeName(employee));
                    jsonObject.addProperty("designation", employee.getDesignation().getDesignationName());
                    jsonObject.addProperty("pDays", pDays);
                    jsonObject.addProperty("lDays", lDays);
                    jsonObject.addProperty("aDays", aDays);
                    jsonObject.addProperty("hDays", hDays);
                    jsonObject.addProperty("extraDays", extraDays);
                    jsonObject.addProperty("extraHalfDays", extraHalfDays);
                    jsonObject.addProperty("weeklyOffDays", weeklyOffDays);
                    jsonObject.addProperty("totalDays", totalDays);
                    jsonObject.addProperty("woDays", woDays);
                    jsonObject.addProperty("totalDaysOfEmployee", totalDaysOfEmployee);
                    jsonArray.add(jsonObject);
                }
            }
            res.add("list", jsonArray);
            res.add("pList", pEmpArr);
            res.add("lList", lEmpArr);
            res.add("abList", abEmpArr);
            res.add("hList",hEmpArr);
            res.add("tAbAndLeaveList", totalabandl);
            res.add("absentPercentage", abPer);
            res.addProperty("totalDays", totalDays);
            res.addProperty("sumofAllEmployeeTotalDays", sumofAllEmployeeTotalDays);
            res.addProperty("sumOfAllEmployeePresenty", sumOfAllEmployeePresenty);
            res.addProperty("sumOfAllEmployeeAbsenty", sumOfAllEmployeeAbsenty);
            res.addProperty("sumOfAllEmployeeLeaves", sumOfAllEmployeeLeaves);
            res.addProperty("sumOfAllEmployeeHalfDays", sumOfAllEmployeeHalfDays);
            res.addProperty("totalEmployee", totalEmployees);
            res.addProperty("presentEmployees", presentEmployees);
            res.addProperty("halfDayEmployees",halfDayEmployees);
            res.addProperty("leaveEmployees", leaveEmployees);
            res.addProperty("absentEmployees", absentEmployees);
            response.add("response", res);
            response.addProperty("userDay", userDay);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            attendanceLogger.error("attendnaceList " + e);
            System.out.println("exception  " + e.getMessage());
            e.printStackTrace();
        }
        return response;
    }

    public Object updateAttendance(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        DateTimeFormatter myTimeObj = DateTimeFormatter.ofPattern("HH:mm");
        SimpleDateFormat df2 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm");
        try {
            List<AppConfig> list = new ArrayList<>();
            if (users.getBranch() != null) {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchId(users.getCompany().getId(), true, users.getBranch().getId());
            } else {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchIsNull(users.getCompany().getId(), true);
            }
            Long attendanceId = Long.valueOf(requestParam.get("attendanceId"));
            Attendance attendance = attendanceRepository.findByIdAndStatus(attendanceId, true);

            if (attendance != null) {
                LocalTime timeToCompare = attendance.getEmployee().getShift().getGraceInPeriod();
                LocalTime latePunchTime = LocalTime.of(14,30,00);
                int daysInMonth = getTotalDaysFromYearAndMonth(attendance.getAttendanceDate().getYear(), attendance.getAttendanceDate().getMonthValue());
                Double wagesPerDay = attendance.getEmployee().getExpectedSalary() / daysInMonth;
                double wagesPerHour = (wagesPerDay / utility.getTimeInDouble(attendance.getEmployee().getShift().getWorkingHours().toString()));
                attendance.setAttendanceDate(LocalDate.parse(requestParam.get("attendanceDate")));

                attendance.setCheckInTime(null);
                if (!requestParam.get("checkInTime").equalsIgnoreCase("")) {
                    LocalDateTime localDateTime = LocalDateTime.parse(requestParam.get("checkInTime"), myFormatObj);
                    attendance.setCheckInTime(localDateTime);
                    if(list.stream().filter(p -> p.getConfigName().equals("late_attendance_deduction") && p.getConfigValue() == 1) != null) {
                        if (localDateTime.toLocalTime().compareTo(timeToCompare) > 0) {
                            if (localDateTime.toLocalTime().compareTo(latePunchTime) > 0)
                                attendance.setIsLate(false);
                            else
                                attendance.setIsLate(true);
                        } else {
                            attendance.setIsLate(false);
                        }
                    }
                }
                attendance.setCheckOutTime(null);
                LocalTime totalTime = LocalTime.parse("00:00:00");
                if (!requestParam.get("checkOutTime").equalsIgnoreCase("")) {
                    LocalDateTime checkInTime = LocalDateTime.parse(requestParam.get("checkInTime"), myFormatObj);
                    LocalDateTime checkOutTime = LocalDateTime.parse(requestParam.get("checkOutTime"), myFormatObj);
                    attendance.setCheckOutTime(checkOutTime);
                    LocalTime timeDiff = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), checkOutTime);
                    String[] timeParts = timeDiff.toString().split(":");
                    int hours = Integer.parseInt(timeParts[0]);
                    int minutes = Integer.parseInt(timeParts[1]);
                    double workedHours = utility.getTimeInDouble(hours+":"+minutes);
                    if(checkInTime.toLocalTime().compareTo(latePunchTime) > 0 || workedHours < 6){
                        attendance.setIsHalfDay(true);
                    } else {
                        attendance.setIsHalfDay(false);
                    }
                    Break runningTask = breakRepository.findTop1ByAttendanceIdAndStatusAndBreakStatus(attendanceId, true, "in-progress");
                    if (runningTask == null) {
                        /* From Attendance Data */
                        totalTime = utility.getDateTimeDiffInTime(checkInTime, checkOutTime);
                        System.out.println("totalTime =>>>>>>>>>>>>>>>>>>>>>>" + totalTime);
                        attendance.setTotalTime(totalTime);

                        if(list.stream().filter(p -> p.getConfigName().equals("overtime_calculation") && p.getConfigValue() == 1) != null) {
                            if (workedHours > (attendance.getEmployee().getShift().getWorkingHours().getHour() + attendance.getEmployee().getShift().getWorkingHours().getMinute())) {
                                LocalTime otDiff = utility.getTimeDiffFromTimes(attendance.getEmployee().getShift().getEndTime(), checkOutTime.toLocalTime());
                                int hour = otDiff.getHour();
                                System.out.println("\nHour is = " + hour);
                                int minute = otDiff.getMinute();
                                System.out.println("Minute is = " + minute);
                                int otTime = (hour * 60) + minute;
                                attendance.setOvertime(otTime);
                                attendance.setOvertimeAmount(otTime * 1.0);
                            } else {
                                attendance.setOvertime(0);
                                attendance.setOvertimeAmount(0.0);
                            }
                        }

                        double lunchTimeInMin = breakRepository.getSumOfBreakTime(attendance.getId());
                        attendance.setLunchTime(lunchTimeInMin);
                        double actualWorkTime = workedHours - lunchTimeInMin;
                        attendance.setActualWorkTime(actualWorkTime);
                        attendance.setHoursWorked(workedHours);

                        if(attendance.getEmployee().getWagesOptions().equals("hour")){
                            double wagesHourBasis = workedHours * wagesPerHour;
                            attendance.setWagesPerHour(wagesPerHour);
                            attendance.setWagesHourBasis(wagesHourBasis);
                        } else {
                            attendance.setWagesPerDay(wagesPerDay);
                        }
                    } else {
                        responseMessage.setMessage("Task already running, Please end running task.");
                        responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                        return responseMessage;
                    }
                }

//                if (!requestParam.get("adminRemark").equalsIgnoreCase("")) {
//                    attendance.setAdminRemark(requestParam.get("adminRemark"));
//                }

                try {
                    attendance.setUpdatedAt(LocalDateTime.now());
                    attendance.setUpdatedBy(users.getId());
                    attendanceRepository.save(attendance);
                    responseMessage.setMessage("Attendance updated successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    System.out.println("Exception " + e.getMessage());
                    e.printStackTrace();
                    responseMessage.setMessage("Failed to update attendance");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }
        } catch (Exception e) {
            attendanceLogger.error("Failed to update attendance " + e);
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.setMessage("Failed to update attendance");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject addManualAttendance(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            LocalTime latePunchTime = LocalTime.of(14,30,00);
            DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            Long employeeId = Long.valueOf(requestParam.get("employeeId"));
            Employee employee = employeeRepository.findByIdAndStatus(employeeId, true);
            LocalTime timeToCompare = employee.getShift().getGraceInPeriod();
            LocalDate attendanceDate = LocalDate.parse(requestParam.get("attendanceDate"));
            Attendance attendance = attendanceRepository.findByEmployeeIdAndAttendanceDateAndStatus(employeeId, attendanceDate, true);
            List<AppConfig> list = new ArrayList<>();
            if (users.getBranch() != null) {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchId(users.getCompany().getId(), true, users.getBranch().getId());
            } else {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchIsNull(users.getCompany().getId(), true);
            }
            if (attendance == null) {
                attendance = new Attendance();

                int daysInMonth = getTotalDaysFromYearAndMonth(attendanceDate.getYear(), attendanceDate.getMonthValue());
                double wagesPerDay = employee.getExpectedSalary() / daysInMonth;
                double wagesPerHour = (wagesPerDay / utility.getTimeInDouble(employee.getShift().getWorkingHours().toString()));


                attendance.setWagesPerDay(wagesPerDay);
                attendance.setWagesPerHour(wagesPerHour);
                attendance.setShift(employee.getShift());
                attendance.setEmployee(employee);
                attendance.setAttendanceDate(attendanceDate);

                attendance.setCheckInTime(null);
                if (!requestParam.get("checkInTime").equalsIgnoreCase("")) {
                    LocalDateTime localDateTime = LocalDateTime.parse(requestParam.get("checkInTime"), myFormatObj);
                    attendance.setCheckInTime(localDateTime);
                    if(list.stream().filter(p -> p.getConfigName().equals("late_attendance_deduction") && p.getConfigValue() == 1) != null) {
                        if (localDateTime.toLocalTime().compareTo(timeToCompare) > 0) {
                            if (localDateTime.toLocalTime().compareTo(latePunchTime) > 0)
                                attendance.setIsLate(false);
                            else
                                attendance.setIsLate(true);
                        }
                        attendance.setIsManualPunchIn(true);
                    }
                }
                attendance.setCheckOutTime(null);
                if (!requestParam.get("checkOutTime").equalsIgnoreCase("")) {
                    LocalDateTime checkOutTime = LocalDateTime.parse(requestParam.get("checkOutTime"), myFormatObj);
                    attendance.setCheckOutTime(checkOutTime);
                    attendance.setIsManualPunchOut(true);
                    LocalTime timeDiff = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), attendance.getCheckOutTime());
                    String[] timeParts = timeDiff.toString().split(":");
                    int hours = Integer.parseInt(timeParts[0]);
                    int minutes = Integer.parseInt(timeParts[1]);
                    double workedHours = utility.getTimeInDouble(hours+":"+minutes);

                    if(attendance.getCheckInTime().toLocalTime().compareTo(latePunchTime) > 0 || workedHours < 6){
                        attendance.setIsHalfDay(true);
                    }

                    if(list.stream().filter(p -> p.getConfigName().equals("overtime_calculation") && p.getConfigValue() == 1) != null) {
                        if (workedHours > (attendance.getEmployee().getShift().getWorkingHours().getHour() + attendance.getEmployee().getShift().getWorkingHours().getMinute())) {
                            LocalTime otDiff = utility.getTimeDiffFromTimes(attendance.getEmployee().getShift().getEndTime(), checkOutTime.toLocalTime());
                            int hour = otDiff.getHour();
                            System.out.println("\nHour is = " + hour);
                            int minute = otDiff.getMinute();
                            System.out.println("Minute is = " + minute);
                            int otTime = (hour * 60) + minute;
                            attendance.setOvertime(otTime);
                            attendance.setOvertimeAmount(otTime * 1.0);
                        } else {
                            attendance.setOvertime(0);
                            attendance.setOvertimeAmount(0.0);
                        }
                    }
                    double lunchTimeInMin = Double.parseDouble(requestParam.get("lunchTimeInMin"));
                    attendance.setLunchTime(lunchTimeInMin);
                    double actualWorkTime = workedHours - (lunchTimeInMin/60);
                    attendance.setActualWorkTime(actualWorkTime);
                    attendance.setHoursWorked(workedHours);
                    if (!requestParam.get("totalTime").equalsIgnoreCase("")) {
                        attendance.setTotalTime(LocalTime.parse(requestParam.get("totalTime")));
                    }

                    if(attendance.getEmployee().getEmployeeWagesType().equals("hour")){
                        double wagesHourBasis = workedHours * wagesPerHour;
                        attendance.setWagesPerHour(wagesPerHour);
                        attendance.setWagesHourBasis(wagesHourBasis);
                    } else {
                        attendance.setWagesPerDay(wagesPerDay);
                    }
                }

                if (requestParam.containsKey("adminRemark") && !requestParam.get("adminRemark").equalsIgnoreCase("")) {
                    attendance.setAdminRemark(requestParam.get("adminRemark"));
                }

                try {
                    attendance.setStatus(true);
                    attendance.setCreatedAt(LocalDateTime.now());
                    attendance.setCreatedBy(users.getId());
                    attendanceRepository.save(attendance);
                    response.addProperty("message", "Attendance saved successfully");
                    response.addProperty("responseStatus", HttpStatus.OK.value());
                } catch (Exception e) {
                    System.out.println("Exception " + e.getMessage());
                    e.printStackTrace();
                    response.addProperty("message", "Failed to save attendance");
                    response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                response.addProperty("message", "Employee attendance already exists.");
                response.addProperty("responseStatus", HttpStatus.CONFLICT.value());
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            response.addProperty("message", "Failed to save attendance");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
    public JsonObject deleteAttendance(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Long attendanceId = Long.valueOf(request.getParameter("attendanceId"));
            Attendance attendance = attendanceRepository.findByIdAndStatus(attendanceId, true);

            if (attendance != null) {
                List<Break> mBreak = breakRepository.findByAttendanceIdAndStatus(attendanceId, true);
                if (mBreak != null && mBreak.size() > 0) {
                    response.addProperty("message", "Delete tasks before going to delete attendance");
                    response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                    return response;
                } else {
                    try {
                        attendance.setStatus(false);
                        attendance.setUpdatedBy(users.getId());
                        attendance.setUpdatedAt(LocalDateTime.now());
                        attendance.setAdminRemark("Attendance Deleted by " + users.getUsername() + " - " + users.getId());
                        attendanceRepository.save(attendance);

                        response.addProperty("message", "Attendance deleted successfully");
                        response.addProperty("responseStatus", HttpStatus.OK.value());
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Exception " + e.getMessage());
                        attendanceLogger.error("Exception => deleteAttendance " + e);

                        response.addProperty("message", "Failed to delete attendance");
                        response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());

                    }
                    return response;
                }
            } else {
                response.addProperty("message", "Attendance not exists");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            attendanceLogger.error("Exception => deleteAttendance " + e);

            response.addProperty("message", "Failed to delete attendance");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
    public JsonObject getOverviewData(Map<String, String> jsonRequest, HttpServletRequest request) {
        Users user = null;
        JsonObject response = new JsonObject();
        LocalDate date = null;
//        DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        try{
            JsonObject object = new JsonObject();
            user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(jsonRequest.containsKey("date")){
                date = LocalDate.parse(jsonRequest.get("date"));
            } else {
                date = LocalDate.now();
            }
            Double present = attendanceRepository.getPresentEmployeeCount(date, user.getCompany().getId());
            Double empCount = employeeRepository.getEmployeeCount(true, user.getCompany().getId());
            List<EmployeeLeave> employeeLeaves = employeeLeaveRepository.getEmployeesOnLeave(date.toString());
            int leaveCount = employeeLeaves.size();
            Double notLogged = empCount - (present + leaveCount);
            Double presentPer = (present/empCount)*100.00;
            Double notLoggedPer = (notLogged/empCount)*100.00;
            Double leavePer = (leaveCount/empCount)*100.00;
            object.addProperty("present",present);
            object.addProperty("notLogged",notLogged);
            object.addProperty("presentPer",presentPer);
            object.addProperty("notLoggedPer",notLoggedPer);
            object.addProperty("onLeave",leaveCount);
            object.addProperty("leavePer",leavePer);
            object.addProperty("empCount",empCount);
            response.add("response",object);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception in getOverviewData:" + e.getMessage());
            response.addProperty("message", "Failed to update salary");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public JsonObject getAttendanceData(Map<String, String> jsonRequest, HttpServletRequest request) {
        Users user = null;
        JsonObject response = new JsonObject();
        List<Employee> allEmployees = null;
        List<Attendance> presentEmployees = null;
        List<Employee> employeesOnLeave = null;
        List<Employee> empNotLoggedIn = null;
        String attendanceDate = null;
        try {
            JsonObject responseObj = new JsonObject();
            JsonArray allEmpArray = new JsonArray();
//            JsonArray leaveArray = new JsonArray();
//            JsonArray notLoggedArray = new JsonArray();
            user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(jsonRequest.get("attendanceDate") != null)
                attendanceDate = jsonRequest.get("attendanceDate");
            else
                attendanceDate = LocalDate.now().toString();
            allEmployees = employeeRepository.findByCompanyIdAndStatus(user.getCompany().getId(), true);
            presentEmployees = attendanceRepository.getPresentEmployees(attendanceDate);
            employeesOnLeave = employeeRepository.getEmployeesOnLeave(attendanceDate);
            empNotLoggedIn = new ArrayList<>();
            for(Employee employee : allEmployees){
                if (!presentEmployees.contains(employee) || !employeesOnLeave.contains(employee)) {
                    empNotLoggedIn.add(employee);
                }
            }
            for(Attendance attendance : presentEmployees){
                JsonObject object = new JsonObject();
                object.addProperty("name",utility.getEmployeeName(attendance.getEmployee()));
                object.addProperty("designation",attendance.getEmployee().getDesignation().getDesignationName());
                object.addProperty("checkIn",attendance.getCheckInTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")));
                object.addProperty("checkOut",attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "-");
                object.addProperty("emp_status","present");
                allEmpArray.add(object);
            }
            for(Employee employee : employeesOnLeave){
                JsonObject object = new JsonObject();
                object.addProperty("name",utility.getEmployeeName(employee));
                object.addProperty("designation",employee.getDesignation().getDesignationName());
                object.addProperty("checkIn","-");
                object.addProperty("checkOut","-");
                object.addProperty("emp_status","on-leave");
                allEmpArray.add(object);
            }
            for(Employee employee : empNotLoggedIn){
                JsonObject object = new JsonObject();
                object.addProperty("name",utility.getEmployeeName(employee));
                object.addProperty("designation",employee.getDesignation().getDesignationName());
                object.addProperty("checkIn","-");
                object.addProperty("checkOut","-");
                object.addProperty("emp_status","not-logged-in");
                allEmpArray.add(object);
            }
            responseObj.add("allEmpArray", allEmpArray);
//            responseObj.add("leaveList", leaveArray);
//            responseObj.add("notLoggedList", notLoggedArray);
            response.add("response",responseObj);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception in getOverviewData:" + e.getMessage());
            response.addProperty("message", "Failed to update salary");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public JsonObject getEmpAttendanceHistory(Map<String, String> jsonRequest, HttpServletRequest request) {
        Users user = null;
        JsonObject response = new JsonObject();
        try{
            JsonArray array = new JsonArray();
            String[] currentMonth;
            String month = null, year = null;
            Long employeeId = Long.parseLong(jsonRequest.get("employee_id"));
            if(jsonRequest.containsKey("currentMonth")) {
                if(!jsonRequest.get("currentMonth").equalsIgnoreCase("")){
                    currentMonth = jsonRequest.get("currentMonth").split("-");
                    month = currentMonth[1];
                    year = currentMonth[0];
                } else {
                    LocalDate localDate = LocalDate.now();
                    year = String.valueOf(localDate.getYear());
                    int monthValue = localDate.getMonthValue();
                    if(monthValue < 10){
                        month = "0"+monthValue;
                    } else {
                        month = String.valueOf(monthValue);
                    }
                }
            }
            user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            List<Attendance> attendanceList = attendanceRepository.getAttendanceOfEmployee(year, month, employeeId);
            if(attendanceList != null){
                for(Attendance attendance : attendanceList){
                    JsonObject object = new JsonObject();
                    object.addProperty("attendanceId",attendance.getId());
                    object.addProperty("attendanceDate",attendance.getAttendanceDate().toString());
                    object.addProperty("inTime",attendance.getCheckInTime() != null ? attendance.getCheckInTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "-");
                    object.addProperty("outTime",attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "-");
                    array.add(object);
                }
                response.add("response", array);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }else{
                response.addProperty("message", "Attendance not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception in getOverviewData:" + e.getMessage());
            response.addProperty("message", "Failed to update salary");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public JsonObject approveAttendance(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            String jsonStr = request.getParameter("list");
            if(jsonStr != null){
                JsonArray approvalList = new JsonParser().parse(jsonStr).getAsJsonArray();
                for (int i = 0; i < approvalList.size(); i++) {
                    JsonObject mObject = approvalList.get(i).getAsJsonObject();
                    Attendance attendance = attendanceRepository.findByIdAndStatus(mObject.get("id").getAsLong(), true);
                    if (attendance != null) {
                        if(mObject.get("employeeWagesType").equals("hour")) {
                            attendance.setWagesHourBasis(Double.parseDouble(mObject.get("wagesHourBasis").toString()));
                            attendance.setWagesPerHour(Double.parseDouble(mObject.get("wagesPerHour").toString()));
                        } else
                            attendance.setWagesPerDay(Double.valueOf(mObject.get("wagesPerDay").toString()));
                        attendance.setSalaryType(String.valueOf(mObject.get("employeeWagesType")));
                        attendance.setAttendanceStatus(mObject.get("attendanceStatus").getAsString().equals("true") ? "approve" : "");
                        attendance.setIsAttendanceApproved(true);
                        attendance.setUpdatedBy(users.getId());
                        attendance.setUpdatedAt(LocalDateTime.now());
                        attendance.setRemark(null);
                        attendance.setAdminRemark(null);
                        if (mObject.has("remark") && !mObject.get("remark").isJsonNull()) {
                            if(!mObject.get("remark").getAsString().equalsIgnoreCase(""))
                                attendance.setRemark(request.getParameter("remark"));
                        }
                        if (mObject.has("adminRemark") && !mObject.get("adminRemark").isJsonNull()) {
                            if(!mObject.get("adminRemark").getAsString().equalsIgnoreCase(""))
                                attendance.setAdminRemark(request.getParameter("adminRemark"));
                        }
                        try {
                            attendanceRepository.save(attendance);
                            updateSalaryForDay(attendance, users);
                        } catch (Exception e) {
                            e.printStackTrace();
                            System.out.println("updateSalaryForDay -> Exception ====>>>>>>" + e.getMessage());
                            response.addProperty("message", "Failed to update salary");
                            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                            return response;
                        }
                        response.addProperty("message", "Attendance Approved successfully");
                        response.addProperty("responseStatus", HttpStatus.OK.value());
                    } else {
                        response.addProperty("message", "Failed to update salary");
                        response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                }
            } else {
                Long attendanceId = Long.parseLong(request.getParameter("attendanceId").toString());
                Attendance attendance = attendanceRepository.findByIdAndStatus(attendanceId, true);
                if (attendance != null) {
                    if(request.getParameter("employeeWagesType").equals("hour")) {
                        attendance.setWagesHourBasis(Double.parseDouble(request.getParameter("wagesHourBasis")));
                        attendance.setWagesPerHour(Double.parseDouble(request.getParameter("wagesPerHour")));
                    } else
                        attendance.setWagesPerDay(Double.valueOf(request.getParameter("wagesPerDay")));
                    attendance.setSalaryType(request.getParameter("employeeWagesType"));
                    attendance.setAttendanceStatus(request.getParameter("attendanceStatus").equals("true") ? "approve" : "");
                    attendance.setIsAttendanceApproved(true);
                    attendance.setUpdatedBy(users.getId());
                    attendance.setUpdatedAt(LocalDateTime.now());
                    attendance.setRemark(null);
                    attendance.setAdminRemark(null);
                    if(request.getParameterMap().containsKey("remark") && request.getParameter("remark") != null){
                        if (!request.getParameter("remark").equalsIgnoreCase("")) {
                            attendance.setRemark(request.getParameter("remark"));
                        }
                    }
                    if(request.getParameterMap().containsKey("adminRemark") && request.getParameter("adminRemark") != null){
                        if (!request.getParameter("adminRemark").equalsIgnoreCase("")) {
                            attendance.setAdminRemark(request.getParameter("adminRemark"));
                        }
                    }

                    try {
                        attendanceRepository.save(attendance);
                        updateSalaryForDay(attendance, users);
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("updateSalaryForDay -> Exception ====>>>>>>" + e.getMessage());
                        response.addProperty("message", "Failed to update salary");
                        response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                        return response;
                    }
                    response.addProperty("message", "Attendance Approved successfully");
                    response.addProperty("responseStatus", HttpStatus.OK.value());
                } else {
                    response.addProperty("message", "Failed to update salary");
                    response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }
            return response;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());

            response.addProperty("message", "Failed to update salary");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public void updateSalaryForDay(Attendance attendance1, Users users) {
        try {
            Long employeeId = attendance1.getEmployee().getId();
            LocalDate attendanceDate = attendance1.getAttendanceDate();
            String monthValue = attendanceDate.getMonthValue() < 10 ? "0"+attendanceDate.getMonthValue() : String.valueOf(attendanceDate.getMonthValue());
            String yearMonth = attendanceDate.getYear() + "-" + monthValue;
            int year = attendanceDate.getYear();
            int month = attendanceDate.getMonthValue();
            List<WeekDays> weekDaysList = weekDaysRepository.findAll();
            Employee employee = employeeRepository.findByIdAndStatus(employeeId, true);
            String wagesType = employee.getEmployeeWagesType();

            List<AppConfig> list = new ArrayList<>();
            if (employee.getBranch() != null) {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchId(employee.getCompany().getId(), true, employee.getBranch().getId());
            } else {
                list = appConfigRepository.findByCompanyIdAndStatusAndBranchIsNull(employee.getCompany().getId(), true);
            }

            int daysInMonth = getTotalDaysFromYearAndMonth(year, month);
            System.out.println("totalDays" + daysInMonth);
            int totalDays = daysInMonth;
//            if(daysInMonth == 31){
//                totalDays = 27;
//            } else if (daysInMonth == 30){
//                totalDays = 26;
//            } else {
//                totalDays = 24;
//            }
//            Double wagesPerDay = employee.getExpectedSalary() / daysInMonth;
            double monthlyPay = employee.getExpectedSalary();
            Double wagesPerDaySalary = monthlyPay / daysInMonth;
            double perDaySalary = 0;
            double perHourSalary = 0;
            if (wagesPerDaySalary != null) {
                perDaySalary = wagesPerDaySalary;
                perHourSalary = (wagesPerDaySalary / utility.getTimeInDouble(employee.getShift().getWorkingHours().toString()));
            }

            System.out.println("perDaySalary " + perDaySalary);
            System.out.println("perHourSalary " + perHourSalary);
            double totalDaysInMonth = attendanceRepository.getPresentDaysOfEmployeeOfMonth(year, month, employeeId, true, "approve");
            System.out.println("totalDaysInMonth " + totalDaysInMonth);

            double totalHoursInMonth = 0;
            double netSalaryInHours = 0;
            double netSalaryInDays = 0;
            double final_day_salary = 0;

            List<Attendance> attendanceList = attendanceRepository.getAttendanceListOfEmployee(year, month, employeeId, true, "approve");

            double presentDays = 0;
            Integer leaveDays = 0;
            double absentDays = 0;
            double extraDays = 0;
            double halfDays = 0;
            double extraHalfDays = 0.0;
            double weeklyOffDays = 0.0;
//            double workedHours = 0.0;
            for (Attendance attendance: attendanceList) {

                int hours = 0;
                int minutes = 0;
                if (attendance != null) {
                    LocalDateTime checkInTime = attendance.getCheckInTime();
                    LocalDateTime checkOutTime = attendance.getCheckOutTime();
                    if(checkOutTime != null){
//                        LocalTime timeDiff = utility.getDateTimeDiffInTime(checkInTime, checkOutTime);
////                            LocalTime time = employee.getShift().getWorkingHours();
//                        String[] timeParts = timeDiff.toString().split(":");
//                        hours = Integer.parseInt(timeParts[0]);
//                        minutes = Integer.parseInt(timeParts[1]);
//                        workedHours = utility.getTimeInDouble(hours+":"+minutes);
//                        if(workedHours > 0){
//
//                        }
                        if (attendance.getAttendanceDate().getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())) {
                            if(attendance.getIsHalfDay() != null && attendance.getIsHalfDay()){
                                extraHalfDays+=0.5;
                            }else {
                                extraDays++;
                            }
                        } else {
                            if(attendance.getIsHalfDay() != null && attendance.getIsHalfDay()) {
                                halfDays+=0.5;
                                absentDays+=0.5;
                            }else{
                                presentDays++;
                            }
                        }
                    }
                } else {
                    EmployeeLeave employeeLeave = employeeLeaveRepository.findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqual(employee.getId(), attendance.getAttendanceDate(), attendance.getAttendanceDate());
                    if (employeeLeave != null) {
                        if (employeeLeave.getLeaveStatus().equals("Approved")) {
                            leaveDays++;
                        }
                    } else if (!attendance.getAttendanceDate().getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())){
                        absentDays++;
                    }
                }
            }
            Double otAmount = 0.0;
            Long otCount = attendanceRepository.getOvertimeCount(employee.getId(), String.valueOf(year), monthValue);
            if(otCount!=null){
                otAmount = attendanceRepository.getOvertimeAmount(employee.getId(), String.valueOf(year), monthValue);
            }

            DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("yyyy-MM-dd");
            String newUserDate = year + "-" + monthValue + "-01";
            LocalDate currentDate = LocalDate.parse(newUserDate, myFormatObj);
            LocalDate firstDateOfMonth = currentDate.withDayOfMonth(1);
            LocalDate lastDateOfMonth = currentDate.withDayOfMonth(currentDate.lengthOfMonth()).plusDays(1);
            List<LocalDate> localDates = firstDateOfMonth.datesUntil(lastDateOfMonth).collect(Collectors.toList());
            for (LocalDate localDate : localDates) {
                if (localDate.getDayOfWeek().toString().contains(weekDaysList.get(employee.getWeeklyOffDay()).getName())) {
                    weeklyOffDays+=1.0;
                }
            }

            double totalDaysOfEmployee = presentDays + leaveDays + absentDays + halfDays + extraHalfDays + weeklyOffDays;
            double presentDaysSalary = 0.0;
            double absentDaysSalary = 0.0;
            double extraDaysSalary = 0.0;
            double extraHalfDaysSalary = 0.0;
            double halfDaysSalary = 0.0;
            double salaryDrawn = 0.0;
            double weeklyOffSalary = 0.0;
            presentDaysSalary = presentDays * perDaySalary;
            absentDaysSalary = absentDays * perDaySalary;
            extraDaysSalary = extraDays * perDaySalary;
            halfDaysSalary = halfDays * perDaySalary;
            extraHalfDaysSalary = extraHalfDays * perDaySalary;
            weeklyOffSalary = weeklyOffDays * perDaySalary;
            salaryDrawn = presentDaysSalary +  extraDaysSalary + halfDaysSalary + extraHalfDaysSalary + otAmount + weeklyOffSalary;

            System.out.println("totalHoursInMonth " + totalHoursInMonth);
            System.out.println("presentDaysSalary"+presentDaysSalary);
            System.out.println("extraDaysSalary"+extraDaysSalary);
            System.out.println("salaryDrawn"+salaryDrawn);

            double netSalary = 0;
            double basicPer = 0;
            double basic = 0;
            double specialAllowance = 0;
            double pfPer = 0;
            double pf = 0;
            double esiPer = 0;
            double esi = 0;
            double pfTax = 0;
            double totalDeduction = 0;
            double payableAmount = 0;
            double advance = 0;
            double incentive = 0;
            double netPayableAmount = 0;
            double allowanceAmount = 0;
            double deductionAmount = 0;
            Long lateCount = 0L;
            double daysToBeDeducted = 0.0;
            double hoursToBeDeducted = 0.0;
            double latePunchDeductionAmt = 0.0;

            EmployeePayroll employeePayroll = null;
            employeePayroll = employeePayrollRepository.findByEmployeeIdAndYearMonth(employee.getId(), yearMonth);
            if (employeePayroll == null) {
                employeePayroll = new EmployeePayroll();
            }

            netSalary = salaryDrawn;
            System.out.println("netSalary " + netSalary);

            List<EmployeePayhead> employeePayheadList = employee.getEmployeePayheadList();

            for(EmployeePayhead employeePayhead : employeePayheadList){
                if(employeePayhead.getPayhead().getIsDefault() != null && employeePayhead.getPayhead().getIsDefault()){                     // if this payhead is maraked as default
                    if(employeePayhead.getPayhead().getPercentageOf() != null){
                        if(employeePayhead.getPayhead().getName().toLowerCase().contains("basic")){
                            basicPer = employeePayhead.getPayhead().getPercentage();
                            basic = (employee.getExpectedSalary() * basicPer) / 100;
                            employeePayhead.setAmount(basic);
                        } else if(employeePayhead.getPayhead().getName().toLowerCase().contains("special")){
                            specialAllowance = (employee.getExpectedSalary() * employeePayhead.getPayhead().getPercentage()) / 100;
                            employeePayhead.setAmount(specialAllowance);
                        }
                    }
                } else {
                    if(employeePayhead.getPayhead().getPercentageOf() != null){
                        if(employeePayhead.getPayhead().getName().toLowerCase().contains("pf") && employee.getEmployeeHavePf() != null && employee.getEmployeeHavePf()){
                            pfPer = employeePayhead.getPayhead().getPercentage();
                            pf = (basic * (pfPer / 100.0));
                            employeePayhead.setAmount(pf);
                        } else if(employeePayhead.getPayhead().getName().toLowerCase().contains("esi") && employee.getEmployeeHaveEsi() != null && employee.getEmployeeHaveEsi()){
                            esiPer = employeePayhead.getPayhead().getPercentage();
                            esi = (basic * (esiPer / 100.0));
                            employeePayhead.setAmount(esi);
                        } else if(employeePayhead.getPayhead().getName().toLowerCase().contains("pt") && employee.getEmployeeHaveProfTax() != null && employee.getEmployeeHaveProfTax()) {
                            if(employee.getGender().equalsIgnoreCase("male")) {
                                if (netSalary >= 7500 && netSalary < 10000) {
                                    pfTax = 175;
                                    employeePayhead.setAmount(pfTax);
                                } else if (netSalary >= 10000) {
                                    pfTax = 200;
                                    if (month == 3) {
                                        pfTax = 300;
                                    }
                                    employeePayhead.setAmount(pfTax);
                                }
                            } else {
                                if (netSalary < 25000) {
                                    pfTax = 0;
                                    employeePayhead.setAmount(pfTax);
                                } else if (netSalary > 25000) {
                                    pfTax = 200;
                                    if (month == 3) {
                                        pfTax = 300;
                                    }
                                    employeePayhead.setAmount(pfTax);
                                }
                            }
                        } else if(employeePayhead.getPayhead().getName().toLowerCase().contains("advance")){

                        }
                    }
                }
                employeePayheadRepository.save(employeePayhead);
            }
            if(list.stream().filter(p -> p.getConfigName().equals("late_attendance_deduction") && p.getConfigValue() == 1) != null) {
                lateCount = attendanceRepository.getLateCount(employee.getId(), monthValue);
                Shift shift = shiftRepository.findByIdAndStatus(employee.getShift().getId(), true);
                if (shift != null && shift.getConsiderationCount()!= null && lateCount > shift.getConsiderationCount()) {
                    if (shift.getIsDayDeduction()) {
                        employeePayroll.setIsDayDeduction(true);
//                    daysToBeDeducted = lateCount / shift.getConsiderationCount();
                        daysToBeDeducted = lateCount - 3;
                        if (shift.getDayValueOfDeduction().equalsIgnoreCase("quarter")) {
                            latePunchDeductionAmt = daysToBeDeducted * (perDaySalary / 4);
                            employeePayroll.setDeductionType(shift.getDayValueOfDeduction());
                        } else if (shift.getDayValueOfDeduction().equalsIgnoreCase("half")) {
                            latePunchDeductionAmt = daysToBeDeducted * (perDaySalary / 2);
                            employeePayroll.setDeductionType(shift.getDayValueOfDeduction());
                        } else {
                            latePunchDeductionAmt = daysToBeDeducted * perDaySalary;
                            employeePayroll.setDeductionType(shift.getDayValueOfDeduction());
                        }
                    } else {
                        hoursToBeDeducted = shift.getHourValueOfDeduction();
                        latePunchDeductionAmt = lateCount * (shift.getHourValueOfDeduction() * perHourSalary);
                        employeePayroll.setDeductionType("hour");
                        employeePayroll.setHoursToBeDeducted(hoursToBeDeducted);
                    }
                }
            }

            totalDeduction = (pf + esi + pfTax + latePunchDeductionAmt);
            if(employeePayroll.getAdvance() != null && employeePayroll.getAdvance() > 0){
                advance = employeePayroll.getAdvance();
            }

            payableAmount = (netSalary - totalDeduction);

//            double sumAdvance = advancePaymentRepository.getEmployeeAdvanceOfMonth(employee.getId(), year, month);
//            advance = sumAdvance;
            netPayableAmount = (payableAmount - advance + incentive);

            employeePayroll.setHalfDays(halfDays);
            employeePayroll.setExtraDays(extraDays);
            employeePayroll.setExtraHalfDays(extraHalfDays);
            employeePayroll.setExtraDaysSalary(extraDaysSalary);
            employeePayroll.setHalfDaysSalary(halfDaysSalary);
            employeePayroll.setExtraHalfDaysSalary(extraHalfDaysSalary);
            employeePayroll.setLateCount(lateCount);
            employeePayroll.setDaysToBeDeducted(daysToBeDeducted);
            employeePayroll.setLatePunchDeductionAmt(latePunchDeductionAmt);
            employeePayroll.setEmployee(employee);
            employeePayroll.setWagesType(wagesType);
            employeePayroll.setYearMonth(yearMonth);
            employeePayroll.setDesignation(employee.getDesignation().getDesignationName());
            employeePayroll.setPerDaySalary(perDaySalary);
            employeePayroll.setPerHourSalary(perHourSalary);
            double days = presentDays+halfDays+extraHalfDays+extraDays+weeklyOffDays;
            employeePayroll.setNoDaysPresent(days);
            employeePayroll.setTotalDaysInMonth(totalDaysInMonth);
            employeePayroll.setTotalHoursInMonth(totalHoursInMonth);
            employeePayroll.setNetSalary(netSalary);
            employeePayroll.setNetSalaryInDays(netSalaryInDays);
            employeePayroll.setNetSalaryInHours(netSalaryInHours);
            employeePayroll.setBasicPer(basicPer);
            employeePayroll.setBasic(basic);
            employeePayroll.setSpecialAllowance(specialAllowance);
            employeePayroll.setPfPer(pfPer);
            employeePayroll.setPf(pf);
            employeePayroll.setEsiPer(esiPer);
            employeePayroll.setEsi(esi);
            employeePayroll.setPfTax(pfTax);
            employeePayroll.setAllowanceAmount(allowanceAmount);
            employeePayroll.setDeductionAmount(deductionAmount);
            employeePayroll.setTotalDeduction(totalDeduction);
            employeePayroll.setPayableAmount(payableAmount);
            employeePayroll.setAbsentDaysSalary(absentDaysSalary);
            employeePayroll.setTotalDaysOfEmployee(totalDaysOfEmployee);
            employeePayroll.setAbsentDays(Double.parseDouble(String.valueOf(absentDays)));
            employeePayroll.setPresentDays(presentDays);
            employeePayroll.setLeaveDays(Double.parseDouble(String.valueOf(leaveDays)));
//            employeePayroll.setAdvance(advance);
            employeePayroll.setIncentive(incentive);
            employeePayroll.setNetPayableAmount(netPayableAmount);
            employeePayroll.setUpdatedAt(LocalDateTime.now());
            employeePayroll.setUpdatedBy(users.getId());
            employeePayroll.setTotalDays(totalDays);
            employeePayroll.setMonthlyPay(monthlyPay);
            employeePayroll.setDaysInMonth(daysInMonth);
            employeePayroll.setOvertimeAmount(otAmount);
            employeePayroll.setGrossTotal(basic+specialAllowance);
            employeePayroll.setOvertime(otCount!=null?otCount:0);
            employeePayroll.setOvertimeAmount(otAmount);
//            employeePayroll.setIsHalfDay(attendance1.getIsHalfDay());

            employeePayrollRepository.save(employeePayroll);

        } catch (Exception e) {
            attendanceLogger.error("updateSalaryForDay Exception ===>" + e);
            System.out.println("updateSalaryForDay Exception ===>" + e.getMessage());
            e.printStackTrace();
        }
    }
    public JsonObject getManualAttendanceReport(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray array = new JsonArray();
        String monthValue = null;
        String yearValue = null;
        try{
            if (!jsonRequest.get("fromMonth").equals("")) {
                String[] fromMonth = jsonRequest.get("fromMonth").split("-");
                int userMonth = Integer.parseInt(fromMonth[1]);
                int userYear = Integer.parseInt(fromMonth[0]);
                monthValue = userMonth < 10 ? "0"+userMonth : String.valueOf(userMonth);
                yearValue = String.valueOf(userYear);
            } else {
                int userYear = LocalDate.now().getYear();
                int userMonth = LocalDate.now().getMonthValue();
                monthValue = userMonth < 10 ? "0"+userMonth : String.valueOf(userMonth);
                yearValue = String.valueOf(userYear);
            }
            if (jsonRequest.get("employeeId").equalsIgnoreCase("all")) {
                List<Attendance> attendanceList = attendanceRepository.getManualAttendanceListOfAll(yearValue.toString(), monthValue);
                for (Attendance attendance : attendanceList) {
                    JsonObject jsonObj = new JsonObject();
                    jsonObj.addProperty("id", attendance.getId());
                    jsonObj.addProperty("attendanceId", attendance.getId());
                    jsonObj.addProperty("employeeName",attendance.getEmployee().getFirstName()+" "+attendance.getEmployee().getLastName());
                    jsonObj.addProperty("attendanceDate", attendance.getAttendanceDate().toString());
                    jsonObj.addProperty("attendanceStatus", attendance.getAttendanceStatus() != null ?
                            attendance.getAttendanceStatus() : "pending");
                    jsonObj.addProperty("checkInTime", attendance.getCheckInTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")));
                    jsonObj.addProperty("checkOutTime", attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "");
//                    jsonObj.addProperty("totalTime", attendance.getTotalTime() != null ? attendance.getTotalTime().toString() : "");

                    if(attendance.getCheckOutTime() != null){
//                String[] timeParts = attendance.getTotalTime().toString().split(":");
//                        LocalTime time = LocalTime.parse(attendance.getTotalTime().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
//                        String[] timeParts = time.toString().split(":");
//                        int hours, minutes, seconds, totalMinutes = 0;
//                        hours = Integer.parseInt(timeParts[0]);
//                        minutes = Integer.parseInt(timeParts[1]);
//                        if(timeParts.length > 2) {
//                            seconds = Integer.parseInt(timeParts[2]);
//                            totalMinutes = hours * 60 + minutes + (seconds / 60);
//
//                            double actualWorkingHoursInMinutes = totalMinutes - Precision.round(attendance.getLunchTime(), 2);
//                            jsonObj.addProperty("actualWorkingHoursInMinutes", actualWorkingHoursInMinutes);
//                        } else {
//                            totalMinutes = hours * 60 + minutes;
//
//                            double actualWorkingHoursInMinutes = totalMinutes - Precision.round(attendance.getLunchTime(), 2);
//                            jsonObj.addProperty("actualWorkingHoursInMinutes", actualWorkingHoursInMinutes);
//                        }
                        LocalTime totalTime = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), attendance.getCheckOutTime());
                        jsonObj.addProperty("actualWorkingHoursInMinutes", totalTime.toString());
                    } else {
                        jsonObj.addProperty("actualWorkingHoursInMinutes", "0.0");
                    }
                    array.add(jsonObj);
                }
            }else {
                Long employeeId = Long.parseLong(jsonRequest.get("employeeId"));
                Employee employee = employeeRepository.findByIdAndStatus(employeeId, true);
                List<Attendance> attendanceList = attendanceRepository.getManualAttendanceList(employee.getId(), yearValue, monthValue);
                for (Attendance attendance : attendanceList) {
                    JsonObject jsonObj = new JsonObject();
                    jsonObj.addProperty("id", attendance.getId());
                    jsonObj.addProperty("attendanceId", attendance.getId());
                    jsonObj.addProperty("employeeName",attendance.getEmployee().getFirstName()+" "+attendance.getEmployee().getLastName());
                    jsonObj.addProperty("attendanceDate", attendance.getAttendanceDate().toString());
                    jsonObj.addProperty("attendanceStatus", attendance.getAttendanceStatus() != null ?
                            attendance.getAttendanceStatus() : "pending");
                    jsonObj.addProperty("checkInTime", attendance.getCheckInTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")));
                    jsonObj.addProperty("checkOutTime", attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) : "");
//                    jsonObj.addProperty("totalTime", attendance.getTotalTime() != null ? attendance.getTotalTime().toString() : "");

                    if(attendance.getCheckOutTime() != null){
//                String[] timeParts = attendance.getTotalTime().toString().split(":");
//                        LocalTime time = LocalTime.parse(attendance.getTotalTime().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
//                        String[] timeParts = time.toString().split(":");
//                        int hours, minutes, seconds, totalMinutes = 0;
//                        hours = Integer.parseInt(timeParts[0]);
//                        minutes = Integer.parseInt(timeParts[1]);
//                        if(timeParts.length > 2) {
//                            seconds = Integer.parseInt(timeParts[2]);
//                            totalMinutes = hours * 60 + minutes + (seconds / 60);
//
//                            double actualWorkingHoursInMinutes = totalMinutes - Precision.round(attendance.getLunchTime(), 2);
//                            jsonObj.addProperty("actualWorkingHoursInMinutes", actualWorkingHoursInMinutes);
//                        } else {
//                            totalMinutes = hours * 60 + minutes;
//
//                            double actualWorkingHoursInMinutes = totalMinutes - Precision.round(attendance.getLunchTime(), 2);
//                            jsonObj.addProperty("actualWorkingHoursInMinutes", actualWorkingHoursInMinutes);
//                        }
                        LocalTime totalTime = utility.getDateTimeDiffInTime(attendance.getCheckInTime(), attendance.getCheckOutTime());
                        jsonObj.addProperty("actualWorkingHoursInMinutes", totalTime.toString());
                    } else {
                        jsonObj.addProperty("actualWorkingHoursInMinutes", "0.0");
                    }
                    array.add(jsonObj);
                }
            }

            response.add("response", array);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e){
            System.out.println(e);
        }
        return response;
    }

    public JsonObject todayEmployeeAttendance(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            LocalDate today = LocalDate.now();
            LocalDate fromDate = null;
            if (!requestParam.get("attendanceDate").equalsIgnoreCase("")) {
                today = LocalDate.parse(requestParam.get("attendanceDate"));
            }
            if (!requestParam.get("fromDate").equalsIgnoreCase("")) {
                fromDate = LocalDate.parse(requestParam.get("fromDate"));
            }
            List<AttendanceView> attendanceViewList = new ArrayList<>();

            String query = "SELECT * from hrms_new_db.attendance_view WHERE status=1";
            if (requestParam.get("fromDate").equalsIgnoreCase("")) {
                query += " AND attendance_date ='" + today + "'";
            } else if (!requestParam.get("fromDate").equalsIgnoreCase("")) {
                query += " AND attendance_date between '" + fromDate + "' AND '" + today + "'";
            }
            if (!requestParam.get("employeeId").equalsIgnoreCase("")) {
                query += " AND employee_id ='" + requestParam.get("employeeId") + "'";
            }
            if (!requestParam.get("attStatus").equalsIgnoreCase("")) {
                if (!requestParam.get("attStatus").equalsIgnoreCase("pending")) {
                    query += " AND attendance_status ='" + requestParam.get("attStatus") + "'";
                } else {
                    query += " AND attendance_status IS NULL";
                }
            }
//            if (!requestParam.get("selectedShift").equalsIgnoreCase("")) {
//                query += " AND shift_id ='" + requestParam.get("selectedShift") + "'";
//            }
            query += " ORDER BY attendance_date, first_name ASC";
            System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> query " + query);
            Query q = entityManager.createNativeQuery(query, AttendanceView.class);
            attendanceViewList = q.getResultList();
            System.out.println("attendanceViewList.size() " + attendanceViewList.size());
            for (AttendanceView attendanceView : attendanceViewList) {
                System.out.println("attendanceView.getEmployeeId() " + attendanceView.getEmployeeId() + " attendanceView.getId() " + attendanceView.getId());
                Long empId = Long.parseLong(attendanceView.getEmployeeId().toString());
                Employee employee = employeeRepository.findByIdAndStatus(empId , true);
                System.out.println("employee.getDesignation().getCode() " + employee.getDesignation().getDesignationCode());

                String empName = employee.getFirstName();
                if (employee.getLastName() != null)
                    empName = empName + " " + employee.getLastName();

                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("id", attendanceView.getId());
                jsonObject.addProperty("attendanceId", attendanceView.getId());
                jsonObject.addProperty("attendanceDate", attendanceView.getAttendanceDate().toString());
                jsonObject.addProperty("designationCode", employee.getDesignation().getDesignationCode().toUpperCase());
                jsonObject.addProperty("employeeId", employee.getId());
                jsonObject.addProperty("employeeName", empName);
                jsonObject.addProperty("employeeWagesType", attendanceView.getSalaryType() != null ?
                        attendanceView.getSalaryType() : employee.getEmployeeWagesType() != null ?
                        employee.getEmployeeWagesType() : "");
                jsonObject.addProperty("attendanceStatus",attendanceView.getAttendanceStatus() != null ? attendanceView.getAttendanceStatus().equals("approve") ? true : false : false);
                jsonObject.addProperty("isAttendanceApproved", attendanceView.getIsAttendanceApproved());
                jsonObject.addProperty("checkInTime", attendanceView.getCheckInTime().toString());
                jsonObject.addProperty("checkOutTime", attendanceView.getCheckOutTime() != null ? attendanceView.getCheckOutTime().toString() : "");
                jsonObject.addProperty("totalTime", attendanceView.getTotalTime() != null ? attendanceView.getTotalTime() : "");
                if(attendanceView.getCheckOutTime() != null) {
                    LocalTime timeDiff = utility.getDateTimeDiffInTime(attendanceView.getCheckInTime(), attendanceView.getCheckOutTime());
                    String[] parts = timeDiff.toString().split(":");
                    int hr = Integer.parseInt(parts[0]);
                    int min = Integer.parseInt(parts[1]);
                    double workedHours = utility.getTimeInDouble(hr + ":" + min);
                    if (workedHours > employee.getShift().getWorkingHours().getHour()) {
                        LocalTime overtime = utility.getTimeDiffFromTimes(employee.getShift().getEndTime(), LocalTime.parse(attendanceView.getCheckOutTime().format(DateTimeFormatter.ofPattern("HH:mm:ss"))));
                        jsonObject.addProperty("overtime", overtime.format(DateTimeFormatter.ofPattern("HH:mm:ss")));
                    }
                }
                jsonObject.addProperty("lunchTimeInMin", attendanceView.getLunchTime() != null ? Precision.round(attendanceView.getLunchTime(), 2) : 0);
                jsonObject.addProperty("actualWorkTime", attendanceView.getActualWorkTime() != null ? Precision.round(attendanceView.getActualWorkTime(), 2) : 0);
                Double sumOfAvgTaskPercentage = 0.0;

//                double wagesPerHour = (attendanceView.getWagesPerDay() / 8);
                String type = null;
                if(attendanceView.getSalaryType() != null){
                    type = attendanceView.getSalaryType();
                } else if(employee.getEmployeeWagesType() != null) {
                    type = employee.getEmployeeWagesType();
                }
                if(type != null && type.equals("day"))
                    jsonObject.addProperty("wagesPerDay", Precision.round(attendanceView.getWagesPerDay(), 2));
                else if(type != null && type.equals("hour")){
                    jsonObject.addProperty("wagesPerHour", Precision.round(attendanceView.getWagesPerHour(), 2));
                    jsonObject.addProperty("wagesHourBasis", attendanceView.getWagesHourBasis() != null ? Precision.round(attendanceView.getWagesHourBasis(), 2) : 0);
                }

                if(attendanceView.getCheckOutTime() != null){
                    String[] timeParts = attendanceView.getTotalTime().split(":");
                    int hours = Integer.parseInt(timeParts[0]);
                    int minutes = Integer.parseInt(timeParts[1]);
                    int seconds = Integer.parseInt(timeParts[2]);

                    int totalMinutes = hours * 60 + minutes + (seconds / 60);


                    double actualWorkingHoursInMinutes = totalMinutes - Precision.round(attendanceView.getLunchTime(), 2);
                    jsonObject.addProperty("actualWorkingHoursInMinutes", actualWorkingHoursInMinutes);
                } else {
                    jsonObject.addProperty("actualWorkingHoursInMinutes", "-");
                }
//                Break mBreak = breakRepository.findByAttendanceIdAndStatus(attendanceView.getId(), true);
//                if(mBreak != null) {
//                    jsonObject.addProperty("breakStartTime", mBreak.getBreakStartTime() != null ? mBreak.getBreakStartTime().toString() : "");
//                    jsonObject.addProperty("breakEndTime", mBreak.getBreakEndTime() != null ? mBreak.getBreakEndTime().toString() : "");
//                }
//                LocalDateTime firstTaskStartTime = breakRepository.getInTime(attendanceView.getId());
//                System.out.println("firstTaskStartTime =>>>>>>>>>>>>>>>>>>>>>>" + firstTaskStartTime);
//                LocalDateTime lastTaskEndTime = breakRepository.getOutTime(attendanceView.getId());
//                System.out.println("lastTaskEndTime =>>>>>>>>>>>>>>>>>>>>>>" + lastTaskEndTime);
//                jsonObject.addProperty("firstTaskStartTime", "");
//                jsonObject.addProperty("lastTaskEndTime", "");
//
//                if (attendanceView.getTotalTime() != null) {
//                    jsonObject.addProperty("firstTaskStartTime", firstTaskStartTime != null ? firstTaskStartTime.toString() : "");
//                    jsonObject.addProperty("lastTaskEndTime", lastTaskEndTime != null ? lastTaskEndTime.toString() : "");
//                }

                jsonObject.addProperty("remark", attendanceView.getRemark() != null ? attendanceView.getRemark() : null);
                jsonObject.addProperty("adminRemark", attendanceView.getAdminRemark() != null ? attendanceView.getAdminRemark() : null);
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
                JsonArray breaksArray = new JsonArray();
                List<Break> breakList = breakRepository.getBreakData(attendanceView.getId(),  true);
                for (Break mBreak : breakList) {
                    JsonObject breakObject = new JsonObject();
                    breakObject.addProperty("id", mBreak.toString());
                    breakObject.addProperty("breakName", mBreak.getBreakMaster().getBreakName().toString());
                    breakObject.addProperty("startTime", mBreak.getBreakStartTime().toString());
                    breakObject.addProperty("endTime", mBreak.getBreakEndTime().toString());
                    breakObject.addProperty("totalTime", mBreak.getTotalBreakTime().toString());
                    breaksArray.add(breakObject);
                }
                jsonObject.add("breakData", breaksArray);
                Double totalBreakTime = breakRepository.getBreakSummary(attendanceView.getId());
                jsonObject.addProperty("totalBreakTime",totalBreakTime);
                jsonArray.add(jsonObject);
            }
            response.add("response", jsonArray);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            attendanceLogger.error("Data inconsistency, please validate data ===> " + e);
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            response.addProperty("message", "Data inconsistency, please validate data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public JsonObject getSingleDayAttendanceDetails(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject response = new JsonObject();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        DecimalFormat df = new DecimalFormat("0.00");
        JsonObject jsonObj = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Long attendanceId = Long.valueOf(jsonRequest.get("attendanceId"));
        Attendance attendance = attendanceRepository.findByIdAndStatus(attendanceId, true);
        if(attendance != null) {
            jsonObj.addProperty("checkInTime",attendance.getCheckInTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")));
            jsonObj.addProperty("checkOutTime",attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")):"");
            jsonObj.addProperty("totalTime",attendance.getCheckOutTime() != null ? attendance.getTotalTime().toString():"");
            jsonObj.addProperty("attendanceDate",attendance.getAttendanceDate().toString());
            List<Break> breakList = breakRepository.getBreakData(attendanceId, true);
            for (Break mBreak : breakList) {
                JsonObject breakObject = new JsonObject();
                breakObject.addProperty("id", mBreak.getId());
                breakObject.addProperty("breakName", mBreak.getBreakMaster().getBreakName());
                breakObject.addProperty("startTime", mBreak.getBreakStartTime().toString());
                breakObject.addProperty("endTime", mBreak.getBreakEndTime() != null ? mBreak.getBreakEndTime().toString() :"");
                breakObject.addProperty("totalTime", mBreak.getTotalBreakTime() != null ? df.format(mBreak.getTotalBreakTime()) : "");
                breakObject.addProperty("breakStatus", mBreak.getBreakStatus().toString());
                breakObject.addProperty("breakStatus", mBreak.getBreakStatus().toString());
                jsonArray.add(breakObject);
            }
            jsonObj.add("breakArray",jsonArray);
            response.add("response", jsonObj);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } else {
            response.addProperty("message", "attendance not found");
            response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
        }
        return response;
    }

    public JsonObject getDashboardAttendanceData(Map<String, String> jsonRequest, HttpServletRequest request) {
        Users users = null;
        JsonObject response = new JsonObject();
        List<Employee> allEmployees = null;
        List<Attendance> presentEmployees = null;
        List<Employee> absentEmps = null;
        String attendanceDate = null;
        Shift shift  = null;
        try {
            JsonObject responseObj = new JsonObject();
            users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                if (jsonRequest.get("attendanceDate") != null)
                    attendanceDate = jsonRequest.get("attendanceDate");
                else
                    attendanceDate = LocalDate.now().toString();
                if (jsonRequest.get("shift") != null)
                    shift = shiftRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("shift")), true);
                if (shift != null) {
                    allEmployees = employeeRepository.findByCompanyIdAndBranchIdAndShiftIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), shift.getId(), true);
                    presentEmployees = attendanceRepository.getPresentEmployeesByDateAndSite(attendanceDate, shift.getId(), users.getCompany().getId(), users.getBranch().getId());
                }
                absentEmps = new ArrayList<>();
                if (allEmployees != null && presentEmployees != null) {
                    for (Employee employee : allEmployees) {
                        if (!presentEmployees.contains(employee)) {
                            absentEmps.add(employee);
                        }
                    }
                }
                responseObj.addProperty("totalEmp", allEmployees != null ? allEmployees.size() : 0);
                responseObj.addProperty("totalPresent", presentEmployees != null ? presentEmployees.size() : 0);
                responseObj.addProperty("totalAbsent", absentEmps != null ? absentEmps.size() : 0);
                response.add("response", responseObj);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception in getOverviewData:" + e.getMessage());
            response.addProperty("message", "Failed to update salary");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

//    public JsonObject listOfSelf(HttpServletRequest httpServletRequest){
//        Users users=jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
//        JsonObject response=new JsonObject();
//        JsonArray jsonArray=new JsonArray();
//        try{
//            if(users.getIsAdmin()){
//                LocalDate today = LocalDate.now();
//                List<Attendance> attendanceList=attendanceRepository.findAllByAttendanceDateAndStatus(today,true);
//                if (attendanceList != null) {
//                    for (Attendance attendance : attendanceList) {
//                        if(attendance.getEmployee().getDesignation().getLevel().getLevelName().equalsIgnoreCase("L3")) {
//                            JsonObject object = new JsonObject();
//                            object.addProperty("id", attendance.getId());
//                            object.addProperty("attendanceDate", attendance.getAttendanceDate().toString());
//                            object.addProperty("punchInTime", attendance.getCheckInTime().toString());
//                            object.addProperty("punchOutTime", attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().toString() : "NA");
//                            object.addProperty("totalTime", attendance.getTotalTime() != null ? attendance.getTotalTime().toString() : "");
//                            object.addProperty("punchInImage", attendance.getPunchInImage());
//                            object.addProperty("punchOutImage", attendance.getPunchOutImage() != null ? attendance.getPunchOutImage() : "NA");
//                            object.addProperty("designation",attendance.getEmployee().getDesignation().getDesignationName());
//                            object.addProperty("level",attendance.getEmployee().getDesignation().getLevel().getLevelName());
//                            object.addProperty("employeeName",attendance.getEmployee().getFullName());
//                            jsonArray.add(object);
//                        }
//                    }
//                    response.add("response", jsonArray);
//                    response.addProperty("responseStatus", HttpStatus.OK.value());
//                } else {
//                    response.addProperty("message", "Data not found");
//                    response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
//                }
//            }
//        }catch (Exception e){
//            response.addProperty("message","Failed to Load Data");
//            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return response;
//    }
//
//    public JsonObject listOfTeamAttendance(HttpServletRequest request){
//        Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        JsonObject response=new JsonObject();
//        JsonArray jsonArray=new JsonArray();
//        try{
//            if(users.getIsAdmin()){
//                LocalDate today=LocalDate.now();
//                List<Attendance> attendanceList=attendanceRepository.findAllByAttendanceDateAndStatus(today,true);
//                if(attendanceList!=null){
//                    for(Attendance attendance:attendanceList ) {
//                        if (attendance.getEmployee().getDesignation().getLevel().getLevelName().equalsIgnoreCase("L1")) {
//                            JsonObject object = new JsonObject();
//                            object.addProperty("id", attendance.getId());
//                            object.addProperty("attendanceDate", attendance.getAttendanceDate().toString());
//                            object.addProperty("punchInTime", attendance.getCheckInTime().toString());
//                            object.addProperty("punchOutTime", attendance.getCheckOutTime() != null ? attendance.getCheckOutTime().toString() : "NA");
//                            object.addProperty("totalTime", attendance.getTotalTime() != null ? attendance.getTotalTime().toString() : "");
//                            object.addProperty("punchInImage", attendance.getPunchInImage());
//                            object.addProperty("punchOutImage", attendance.getPunchOutImage() != null ? attendance.getPunchOutImage() : "NA");
//                            object.addProperty("designation", attendance.getEmployee().getDesignation().getDesignationName());
//                            object.addProperty("level", attendance.getEmployee().getDesignation().getLevel().getLevelName());
//                            object.addProperty("employeeName", attendance.getEmployee().getFullName());
//                            jsonArray.add(object);
//                        }
//                    }
//                    response.add("response",jsonArray);
//                    response.addProperty("responseStatus",HttpStatus.OK.value());
//                }else {
//                    response.addProperty("message","Data not Found");
//                    response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
//                }
//            }else {
//                response.addProperty("message","Data not Found");
//                response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
//            }
//        }catch (Exception e){
//            response.addProperty("message","Failed to Load Data");
//            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return response;
//    }
//
//    public JsonObject getPunchInList(Map<String, String> jsonRequest, HttpServletRequest request) {
//        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        JsonObject response = new JsonObject();
//        Shift shift  = null;
//        JsonArray jsonArray = new JsonArray();
//        List<Attendance> attendanceList = null;
//        try {
//            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
//                if (jsonRequest.get("shift") != null)
//                    shift = shiftRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("shift")), true);
//                if (shift != null) {
//                    attendanceList = attendanceRepository.getPunchInData(LocalDate.now().toString(), shift.getId(), users.getCompany().getId(), users.getBranch().getId());
//                    if(attendanceList != null) {
//                        for (Attendance attendance : attendanceList) {
//                            if (attendance.getEmployee().getDesignation().getLevel().getLevelName().equalsIgnoreCase("L3")) {
//                                JsonObject jsonObject = new JsonObject();
//                                jsonObject.addProperty("attendanceId", attendance.getId());
//                                jsonObject.addProperty("attendanceDate", attendance.getAttendanceDate().toString());
//                                jsonObject.addProperty("designationCode", attendance.getEmployee().getDesignation().getDesignationCode().toUpperCase());
//                                jsonObject.addProperty("employeeId", attendance.getEmployee().getId());
//                                jsonObject.addProperty("employeeName", attendance.getEmployee().getFullName());
//                                jsonObject.addProperty("employeeWagesType", attendance.getEmployee().getEmployeeWagesType() != null ?
//                                        attendance.getEmployee().getEmployeeWagesType() : "");
//                                jsonObject.addProperty("isPunchInApproved", attendance.getIsPunchInApproved());
//                                jsonObject.addProperty("checkInTime", attendance.getCheckInTime().toString());
//                                jsonArray.add(jsonObject);
//                            }
//                        }
//                        response.add("response", jsonArray);
//                        response.addProperty("responseStatus", HttpStatus.OK.value());
//                    } else {
//                        response.addProperty("message", "No Data Found");
//                        response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
//                    }
//                } else {
//                    response.addProperty("message", "No Data Found with this shift");
//                    response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
//                }
//            }
//        } catch (Exception e){
//            e.printStackTrace();
//            System.out.println("Exception in getOverviewData:" + e.getMessage());
//            response.addProperty("message", "Failed to get punch in data");
//            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return response;
//    }
//
//    public JsonObject getPunchOutList(Map<String, String> jsonRequest, HttpServletRequest request) {
//        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        JsonObject response = new JsonObject();
//        Shift shift  = null;
//        JsonArray jsonArray = new JsonArray();
//        List<Attendance> attendanceList = null;
//        try {
//            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
//                if (jsonRequest.get("shift") != null)
//                    shift = shiftRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("shift")), true);
//                if (shift != null) {
//                    attendanceList = attendanceRepository.getPunchOutData(LocalDate.now().toString(), shift.getId(), users.getCompany().getId(), users.getBranch().getId());
//                    if(attendanceList != null) {
//                        for (Attendance attendance : attendanceList) {
//                            if (attendance.getEmployee().getDesignation().getLevel().getLevelName().equalsIgnoreCase("L3")) {
//                                JsonObject jsonObject = new JsonObject();
//                                jsonObject.addProperty("attendanceId", attendance.getId());
//                                jsonObject.addProperty("attendanceDate", attendance.getAttendanceDate().toString());
//                                jsonObject.addProperty("designationCode", attendance.getEmployee().getDesignation().getDesignationCode().toUpperCase());
//                                jsonObject.addProperty("employeeId", attendance.getEmployee().getId());
//                                jsonObject.addProperty("employeeName", attendance.getEmployee().getFullName());
//                                jsonObject.addProperty("employeeWagesType", attendance.getEmployee().getEmployeeWagesType() != null ?
//                                        attendance.getEmployee().getEmployeeWagesType() : "");
//                                jsonObject.addProperty("isPunchOutApproved", attendance.getIsPunchOutApproved());
//                                jsonObject.addProperty("checkOutTime", attendance.getCheckOutTime().toString());
//                                jsonArray.add(jsonObject);
//                            }
//                        }
//                        response.add("response", jsonArray);
//                        response.addProperty("responseStatus", HttpStatus.OK.value());
//                    } else {
//                        response.addProperty("message", "No Data Found");
//                        response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
//                    }
//                } else {
//                    response.addProperty("message", "No Data Found with this shift");
//                    response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
//                }
//            }
//        } catch (Exception e){
//            e.printStackTrace();
//            System.out.println("Exception in getOverviewData:" + e.getMessage());
//            response.addProperty("message", "Failed to get punch in data");
//            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return response;
//    }
//
//    public Object approveTodayHigherLevelAttendance(String requestParam, HttpServletRequest request) {
//        JsonObject response = new JsonObject();
//        JsonParser parser = new JsonParser();
//        JsonObject json = (JsonObject) parser.parse(requestParam);
//        try {
//            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//            JsonArray approvalList = json.getAsJsonArray("selectedMembers");
//            if(approvalList != null){
//                String atttype = request.getParameter("atttype");
//                if(atttype.equalsIgnoreCase("punchin")) {
//                    for (int i = 0; i < approvalList.size(); i++) {
////                        JsonObject mObject = approvalList.get(i).getAsJsonObject();
//                        Long member = approvalList.get(i).getAsLong();
//                        Attendance attendance = attendanceRepository.findByIdAndStatus(member, true);
//                        if (attendance != null) {
//                            try {
//                                attendance.setIsPunchInApproved(true);
//                                attendance.setUpdatedBy(users.getId());
//                                attendance.setUpdatedAt(LocalDateTime.now());
//                                attendance.setRemark(null);
//                                attendance.setAdminRemark(null);
//                                attendanceRepository.save(attendance);
////                                updateSalaryForDay(attendance, users);
//                            } catch (Exception e) {
//                                e.printStackTrace();
//                                System.out.println("updateSalaryForDay -> Exception ====>>>>>>" + e.getMessage());
//                                response.addProperty("message", "Failed to update salary");
//                                response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//                                return response;
//                            }
//                            response.addProperty("message", "Attendance Approved successfully");
//                            response.addProperty("responseStatus", HttpStatus.OK.value());
//                        } else {
//                            response.addProperty("message", "Attendance not found");
//                            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//                        }
//                    }
//                } else if(atttype.equalsIgnoreCase("punchout")) {
//                    for (int i = 0; i < approvalList.size(); i++) {
//                        Long member = approvalList.get(i).getAsLong();
//                        Attendance attendance = attendanceRepository.findByIdAndStatus(member, true);
//                        if (attendance != null) {
//                            try {
//                                if(json.get("employeeWagesType").getAsString().equals("hour")) {
//                                    attendance.setWagesHourBasis(Double.parseDouble(json.get("wagesHourBasis").getAsString().toString()));
//                                    attendance.setWagesPerHour(Double.parseDouble(json.get("wagesPerHour").getAsString().toString()));
//                                } else
//                                    attendance.setWagesPerDay(Double.valueOf(json.get("wagesPerDay").getAsString().toString()));
//                                attendance.setSalaryType(json.get("employeeWagesType").getAsString());
//                                attendance.setAttendanceStatus(json.get("attendanceStatus").getAsString().equals("true") ? "approve" : "");
//                                attendance.setIsAttendanceApproved(true);
//                                attendance.setUpdatedBy(users.getId());
//                                attendance.setUpdatedAt(LocalDateTime.now());
//                                attendance.setRemark(null);
//                                attendance.setAdminRemark(null);
//                                if (json.has("remark") && !json.get("remark").isJsonNull()) {
//                                    if(!json.get("remark").getAsString().equalsIgnoreCase(""))
//                                        attendance.setRemark(request.getParameter("remark"));
//                                }
//                                if (json.has("adminRemark") && !json.get("adminRemark").isJsonNull()) {
//                                    if(!json.get("adminRemark").getAsString().equalsIgnoreCase(""))
//                                        attendance.setAdminRemark(request.getParameter("adminRemark"));
//                                }
//                                attendanceRepository.save(attendance);
//                                updateSalaryForDay(attendance, users);
//                            } catch (Exception e) {
//                                e.printStackTrace();
//                                System.out.println("updateSalaryForDay -> Exception ====>>>>>>" + e.getMessage());
//                                response.addProperty("message", "Failed to update salary");
//                                response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//                                return response;
//                            }
//                            response.addProperty("message", "Attendance Approved successfully");
//                            response.addProperty("responseStatus", HttpStatus.OK.value());
//                        } else {
//                            response.addProperty("message", "Attendance not found");
//                            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//                        }
//                    }
//                }
//            } else {
//                response.addProperty("message", "No employee list in request");
//                response.addProperty("responseStatus", HttpStatus.BAD_REQUEST.value());
//            }
//            return response;
//        } catch (Exception e) {
//            e.printStackTrace();
//            System.out.println("Exception " + e.getMessage());
//
//            response.addProperty("message", "Failed to update salary");
//            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return response;
//    }

//    public JsonObject getTodayAttendancePunchInSiteWiseList(Map<String, String> jsonRequest, HttpServletRequest request) {
//        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        JsonObject response = new JsonObject();
//        JsonArray jsonArray = new JsonArray();
//        List<Attendance> attendanceList = null;
//        //{"siteId":{"value":0,"label":"All"},"teamId":""}
//        try {
//            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
//                if(jsonRequest.get("siteId").equalsIgnoreCase("all")) {
//                    attendanceList = attendanceRepository.getPunchInListWithoutBranch(LocalDate.now().toString(), users.getCompany().getId());
//                } else {
//                    //{"siteId":{"value":156,"label":"344 Karen Imran(344)"},
//                    // "teamId":{"value":465,"label":"344 - Calistus Baraza","id":465,"teamName":"344 - Calistus Baraza","isActive":true,
//                    // "createdBy":1,"createdDate":"2022-03-30T09:02:53.368497","updatedBy":1,"updatedDate":"2022-11-24T08:35:17.707025",
//                    // "siteId":156}}
//                    Long teamId = Long.parseLong(jsonRequest.get("teamId"));
//                    attendanceList = attendanceRepository.getPunchInSiteWiseList(LocalDate.now().toString(), users.getCompany().getId(), Long.parseLong(jsonRequest.get("siteId")));
//                }
//            }
//        } catch (Exception e){
//            e.printStackTrace();
//            System.out.println("Exception in getOverviewData:" + e.getMessage());
//            response.addProperty("message", "Failed to get punch in data");
//            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
//        }
//        return response;
//    }
}
