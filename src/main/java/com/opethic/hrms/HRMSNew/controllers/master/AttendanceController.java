package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.AttendanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class AttendanceController {
    @Autowired
    private AttendanceService attendanceService;

    @PostMapping(path = "/mobile/saveAttendance")
    public Object saveAttendance( MultipartHttpServletRequest request) {
        JsonObject jsonObject = attendanceService.saveAttendance(request);
        return jsonObject.toString();
    }
    @GetMapping(path = "/mobile/checkAttendanceStatus")
    public Object checkAttendanceStatus(HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.checkAttendanceStatus(request);
        return jsonObject.toString();
    }
    @PostMapping(path = "/mobile/getAttendanceList")
    public Object getAttendanceList(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getAttendanceList(jsonRequest, request);
        return jsonObject.toString();
    }

    @PostMapping(path = "/getEmpMonthlyPresenty")
    public Object getEmpMonthlyPresenty(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getEmpMonthlyPresenty(jsonRequest, request);
        return jsonObject.toString();
    }
    @PostMapping(path = "/updateAttendance")
    public Object updateAttendance(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return attendanceService.updateAttendance(requestParam, request);
    }
    @PostMapping(path = "/bo/addManualAttendance")
    public Object addManualAttendance(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return attendanceService.addManualAttendance(requestParam, request).toString();
    }
    @PostMapping(path = "/todayEmployeeAttendance")
    public Object todayEmployeeAttendance(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return attendanceService.todayEmployeeAttendance(requestParam, request).toString();
    }
    @PostMapping(path = "/getManualAttendanceReport")
    public Object getManualAttendanceReport(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getManualAttendanceReport(jsonRequest, request);
        return jsonObject.toString();
    }

    @PostMapping(path = "/bo/deleteAttendance")
    public Object deleteAttendance(HttpServletRequest request) {
        return attendanceService.deleteAttendance(request).toString();
    }
    @PostMapping(path = "/mobile/getOverviewData")
    public Object getOverviewData(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getOverviewData(jsonRequest, request);
        return jsonObject.toString();
    }
    @PostMapping(path = "/mobile/getAttendanceData")
    public Object getAttendanceData(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getAttendanceData(jsonRequest, request);
        return jsonObject.toString();
    }
    @PostMapping(path = "/bo/getDashboardAttendanceData")
    public Object getDashboardAttendanceData(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getDashboardAttendanceData(jsonRequest, request);
        return jsonObject.toString();
    }

    @PostMapping(path = "/mobile/getEmpAttendanceHistory")
    public Object getEmpAttendanceHistory(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getEmpAttendanceHistory(jsonRequest, request);
        return jsonObject.toString();
    }
    @PostMapping(path = "/bo/approveAttendance")
    public Object approveAttendance(HttpServletRequest request) {
        return attendanceService.approveAttendance(request).toString();
    }
    @PostMapping(path = "/mobile/getSingleDayAttendanceDetails")
    public Object getSingleDayAttendanceDetails(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject jsonObject = attendanceService.getSingleDayAttendanceDetails(jsonRequest, request);
        return jsonObject.toString();
    }

//    @GetMapping(path = "/listOfSelf")
//    public Object listOfSelf(HttpServletRequest httpServletRequest){
//        JsonObject res=attendanceService.listOfSelf(httpServletRequest);
//        return res.toString();
//    }
//
//    @GetMapping(path = "/listOfTeamAttendance")
//    public Object listOfTeamAttendance(HttpServletRequest request){
//        JsonObject res=attendanceService.listOfTeamAttendance(request);
//        return res.toString();
//    }
//    @PostMapping(path = "/getPunchInList")
//    public Object getPunchInList(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
//        JsonObject jsonObject = attendanceService.getPunchInList(jsonRequest, request);
//        return jsonObject.toString();
//    }
//    @PostMapping(path = "/getPunchOutList")
//    public Object getPunchOutList(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
//        JsonObject jsonObject = attendanceService.getPunchOutList(jsonRequest, request);
//        return jsonObject.toString();
//    }

//    @PostMapping(path = "/getTodayAttendancePunchInSiteWiseList")
//    public Object getTodayAttendancePunchInSiteWiseList(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
//        JsonObject jsonObject = attendanceService.getTodayAttendancePunchInSiteWiseList(jsonRequest, request);
//        return jsonObject.toString();
//    }

//


//    @PostMapping(path = "/getSalaryReportMonthWise")
//    public Object getSalaryReportMonthWise(@RequestBody Map<String, String> jsonRequest, HttpServletRequest request) {
//        JsonObject jsonObject = attendanceService.getSalaryReportMonthWise(jsonRequest, request);
//        return jsonObject.toString();
//    }
}
