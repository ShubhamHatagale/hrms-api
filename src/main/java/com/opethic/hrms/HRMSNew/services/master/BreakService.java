package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.master.AttendanceRepository;
import com.opethic.hrms.HRMSNew.repositories.master.BreakMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.BreakRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.apache.commons.math3.util.Precision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

import static java.time.temporal.ChronoUnit.SECONDS;

@Service
public class BreakService {
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AttendanceRepository attendanceRepository;
    @Autowired
    private Utility utility;
    private static final Logger breakLogger = LoggerFactory.getLogger(BreakService.class);
    @Autowired
    private BreakRepository breakRepository;
    @Autowired
    private BreakMasterRepository breakMasterRepository;

    public JsonObject startBreak(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Break mBreak = new Break();
        try {
            BreakMaster breakMaster = breakMasterRepository.findByIdAndStatus(Long.parseLong(requestParam.get("breakMasterId")), true);
            mBreak.setBreakMaster(breakMaster);

            Attendance attendance = attendanceRepository.findByIdAndStatus(Long.valueOf(requestParam.get("attendanceId")), true);
            mBreak.setAttendance(attendance);

            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            mBreak.setEmployee(employee);

            if(requestParam.containsKey("remark"))
                mBreak.setRemark(requestParam.get("remark"));
            mBreak.setBreakStatus("in-progress");
            mBreak.setBreakDate(LocalDate.now());
            mBreak.setBreakStartTime(LocalTime.now());

            mBreak.setCreatedAt(LocalDateTime.now());
            mBreak.setCreatedBy(employee.getId());
            mBreak.setStatus(true);
            try {
                Break savedBreak = breakRepository.save(mBreak);
                responseMessage.addProperty("breakId",savedBreak.getId());
                responseMessage.addProperty("breakStatus",savedBreak.getBreakStatus());
                responseMessage.addProperty("message","Break StartedSuccessfully");
                responseMessage.addProperty("responseStatus",HttpStatus.OK.value());
            } catch (Exception e) {
                breakLogger.error("Failed to start task " + e);
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.addProperty("message","Failed to start break");
                responseMessage.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            breakLogger.error("Failed to start break " + e);
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message","Failed to start break");
            responseMessage.addProperty("responseStatus",HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public Object endBreak(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long breakId = Long.valueOf(requestParam.get("breakId"));
            Break mBreak = breakRepository.findByIdAndStatus(breakId, true);
            if (mBreak != null) {
                mBreak.setBreakStatus("complete");
                LocalTime startTime = mBreak.getBreakStartTime();
                LocalTime endTime = LocalTime.now();
                mBreak.setBreakEndTime(endTime);
                System.out.println("SECONDS To MINUTES " + (SECONDS.between(startTime, endTime) / 60));
                double totalTime = SECONDS.between(startTime, endTime) / 60.0;
                double time = totalTime;
                System.out.println("total time in min " + time);
                mBreak.setTotalBreakTime(time);

                if (requestParam.containsKey("remark")) {
                    String endRemark = requestParam.get("remark");
                    if (!endRemark.equalsIgnoreCase("")) {
                        mBreak.setRemark(endRemark);
                    }
                }
                mBreak.setUpdatedAt(LocalDateTime.now());
                mBreak.setUpdatedBy(employee.getId());
                try {
                    Break savedBreak = breakRepository.save(mBreak);
                    if(savedBreak != null) {
//                    updateEmployeeTaskSummary(task.getAttendance());
                        responseMessage.setMessage("Break Ended Successfully");
                        responseMessage.setResponseStatus(HttpStatus.OK.value());
                    } else {
                        responseMessage.setMessage("Trouble while ending break");
                        responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                } catch (Exception e) {
                    breakLogger.error("Failed to finish task " + e);
                    e.printStackTrace();
                    System.out.println("Exception " + e.getMessage());
                    responseMessage.setMessage("Failed to finish task");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }
        } catch (Exception e) {
            breakLogger.error("failed to finish task" + e);
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to finish task");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public JsonObject getTodaysBreaks(Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        DecimalFormat df = new DecimalFormat("0.00");
        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
            Long attendanceId = Long.valueOf(request.get("attendanceId"));
            List<Break> breakList = breakRepository.getBreakData(attendanceId, true);
            for (Break mBreak : breakList) {
                JsonObject breakObject = new JsonObject();
                breakObject.addProperty("id", mBreak.getId());
                breakObject.addProperty("breakName", mBreak.getBreakMaster().getBreakName());
                breakObject.addProperty("startTime", mBreak.getBreakStartTime().toString());
                breakObject.addProperty("endTime", mBreak.getBreakEndTime() != null ? mBreak.getBreakEndTime().toString() :"");
                breakObject.addProperty("totalTime", mBreak.getTotalBreakTime() != null ? df.format(mBreak.getTotalBreakTime()) : "");
                breakObject.addProperty("breakStatus", mBreak.getBreakStatus().toString());
                jsonArray.add(breakObject);
            }
            responseMessage.add("response", jsonArray);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());

        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.addProperty("message", "Failed to load Data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
}
