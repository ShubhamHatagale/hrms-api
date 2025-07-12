package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.common.Enums;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeLeaveRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeRepository;
import com.opethic.hrms.HRMSNew.repositories.master.LeaveMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.ShiftRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class EmployeeLeaveService {
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private EmployeeLeaveRepository employeeLeaveRepository;
    @Autowired
    private LeaveMasterRepository leaveMasterRepository;
    @Autowired
    private Utility utility;
    @Autowired
    private EmployeeRepository employeeRepository;
    @Autowired
    private ShiftRepository shiftRepository;

    public Object applyLeave(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        LocalDate holidayFromDate=users.getCompany().getHolidayFromDate();
        LocalDate holidayToDate=users.getCompany().getHolidayToDate();
        if(LocalDate.parse(requestParam.get("fromDate")).isAfter(holidayFromDate)&&LocalDate.parse(requestParam.get("toDate")).isBefore(holidayToDate))
        {
            EmployeeLeave employeeLeave = new EmployeeLeave();
            try {
                Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));

                EmployeeLeave employeeLeave1 =
                        employeeLeaveRepository.findByEmployeeIdAndFromDateLessThanEqualAndToDateGreaterThanEqual(
                                employee.getId(), LocalDate.parse(requestParam.get("fromDate")), LocalDate.parse(requestParam.get("toDate")));
                if (employeeLeave1 == null) {
                    Long leaveTypeId = Long.parseLong(requestParam.get("leaveId").toString());
                    LeaveMaster leaveMaster = leaveMasterRepository.findByIdAndStatus(leaveTypeId, true);
                    employeeLeave.setEmployee(employee);
                    employeeLeave.setLeaveMaster(leaveMaster);
                    employeeLeave.setCreatedBy(employee.getId());
                    employeeLeave.setAppliedOn(LocalDate.now());
                    employeeLeave.setFromDate(LocalDate.parse(requestParam.get("fromDate")));
                    employeeLeave.setToDate(LocalDate.parse(requestParam.get("toDate")));
                    employeeLeave.setTotalDays(Integer.valueOf(requestParam.get("totalDays")));
                    employeeLeave.setReason(requestParam.get("reason"));
                    employeeLeave.setLeaveStatus("Pending");
                    employeeLeave.setStatus(true);
                    try {
                        employeeLeaveRepository.save(employeeLeave);
                        responseMessage.setMessage("leave applied successfully");
                        responseMessage.setResponseStatus(HttpStatus.OK.value());
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Exception " + e.getMessage());
                        responseMessage.setMessage("Failed to apply leave");
                        responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                } else {
                    responseMessage.setMessage("You have already applied for leave for this day");
                    responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to apply leave");
                responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            }
        }else{
            responseMessage.setMessage("Leaves should be between Holiday Calendar Dates");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        }

        return responseMessage;
    }

    public JsonObject listOfLeaves(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            List<EmployeeLeave> employeeLeaveList =
                    employeeLeaveRepository.findByEmployeeIdAndStatusOrderByIdDesc(employee.getId(), true);
            for (EmployeeLeave employeeLeave : employeeLeaveList) {
                JsonObject object = new JsonObject();
                object.addProperty("id", employeeLeave.getId());
                object.addProperty("leaveName", employeeLeave.getLeaveMaster().getName());
                object.addProperty("fromDate", String.valueOf(employeeLeave.getFromDate()));
                object.addProperty("toDate", String.valueOf(employeeLeave.getToDate()));
                object.addProperty("appliedOn", String.valueOf(employeeLeave.getAppliedOn()));
                object.addProperty("totalDays", employeeLeave.getTotalDays());
                object.addProperty("reason", employeeLeave.getReason());
                object.addProperty("leaveStatus", employeeLeave.getLeaveStatus());
                object.addProperty("requestDate", String.valueOf(employeeLeave.getCreatedAt()));
                object.addProperty("leaveApprovedBy", employeeLeave.getLeaveApprovedBy());
                object.addProperty("leaveRemark", employeeLeave.getLeaveRemark());
                jsonArray.add(object);
            }
            responseMessage.add("response", jsonArray);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object updateEmployeeLeaveStatus(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long leaveId = Long.valueOf(jsonRequest.get("leaveId"));
            Boolean leaveStatus = Boolean.parseBoolean(jsonRequest.get("leaveStatus"));
            String remark = jsonRequest.get("remark");
            EmployeeLeave employeeLeave = employeeLeaveRepository.findByIdAndStatus(leaveId, true);
            if (employeeLeave != null) {
                if (!remark.isEmpty()) {
                    employeeLeave.setLeaveRemark(remark);
                }
                employeeLeave.setLeaveApprovedBy(users.getUsername());
                if(leaveStatus)
                    employeeLeave.setLeaveStatus("Approved");
                else
                    employeeLeave.setLeaveStatus("Rejected");
                employeeLeave.setUpdatedBy(users.getId());
                employeeLeave.setUpdatedAt(LocalDateTime.now());
                employeeLeaveRepository.save(employeeLeave);
                responseMessage.setMessage("Request " + employeeLeave.getLeaveStatus() + " successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Leave request not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to updated request");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject checkLeaveAvailability(Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Long leavesAllowed = 0L;
        try {
            Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            Long categoryId = Long.parseLong(requestParam.get("categoryId"));
            Long noOfDays = Long.parseLong(requestParam.get("days"));
            Long usedLeaves = leaveMasterRepository.getLeavesAlreadyApplied(employee.getId(), categoryId);
            LeaveMaster leaveMaster = leaveMasterRepository.findByIdAndStatus(categoryId, true);
            if(leaveMaster != null)
                leavesAllowed = leaveMaster.getLeavesAllowed();
            if(usedLeaves < leavesAllowed){
                Long remainingLeaves = leavesAllowed - usedLeaves;
                if(noOfDays > remainingLeaves){
                    if(remainingLeaves > 1)
                        responseMessage.addProperty("message", "You can apply leaves for "+remainingLeaves+" days");
                    else
                        responseMessage.addProperty("message", "You can apply leave for "+remainingLeaves+" day");
                    responseMessage.addProperty("flag",false);
                    responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
                } else {
                    responseMessage.addProperty("message", "Proceed to apply the leave");
                    responseMessage.addProperty("flag",true);
                    responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
                }
            } else {
                responseMessage.addProperty("message", "Leaves Exhausted");
                responseMessage.addProperty("flag",false);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject getEmployeesLeaveRequests(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try{
            JsonArray array = new JsonArray();
            List<EmployeeLeave> leaveRequests = employeeLeaveRepository.getPendingLeaveRequests();
            for(EmployeeLeave leave : leaveRequests){
                JsonObject object = new JsonObject();
                object.addProperty("leaveId",leave.getId());
                object.addProperty("empId",leave.getEmployee().getId());
                object.addProperty("empName",utility.getEmployeeName(leave.getEmployee()));
                object.addProperty("designation",leave.getEmployee().getDesignation().getDesignationName());
                object.addProperty("leaveType",leave.getLeaveMaster().getName());
                object.addProperty("appliedOn",leave.getAppliedOn().toString());
                object.addProperty("leaveFrom",leave.getFromDate().toString());
                object.addProperty("leaveTo",leave.getToDate().toString());
                object.addProperty("totalDays",leave.getTotalDays());
                object.addProperty("comment",leave.getReason());
                array.add(object);
            }
            response.add("response",array);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        }catch(Exception e){
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object approveEmpLeaves(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            Long leaveId = Long.valueOf(jsonRequest.get("leaveId"));
            String leaveStatus = jsonRequest.get("leaveStatus");
            EmployeeLeave employeeLeave = employeeLeaveRepository.findByIdAndStatus(leaveId, true);
            if (employeeLeave != null) {
                employeeLeave.setLeaveApprovedBy(users.getUsername());
                employeeLeave.setLeaveStatus(leaveStatus);
                employeeLeave.setUpdatedBy(users.getId());
                employeeLeave.setUpdatedAt(LocalDateTime.now());
                employeeLeaveRepository.save(employeeLeave);
                responseMessage.setMessage("Request " + leaveStatus + " successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Leave request not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to updated request");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject getEmpLeaveRequests(Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<EmployeeLeave> employeeLeaveList = null;
        String[] yearMonth = null;
        String userYear = null;
        String userMonth = null;
        String month = null;
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
            if (!request.get("yearMonth").equalsIgnoreCase("")) {
                yearMonth = request.get("yearMonth").split("-");
                userYear = yearMonth[0];
                userMonth = yearMonth[1];
                month = Integer.parseInt(userMonth) < 10 ? "0"+userMonth: userMonth;
            }
            if(yearMonth != null)
                employeeLeaveList = employeeLeaveRepository.getEmplLeaveRequestsOfMonth(userYear, month, users.getCompany().getId(), users.getBranch().getId());
            else {
                month = LocalDate.now().getMonthValue() < 10 ? "0"+LocalDate.now().getMonthValue(): String.valueOf(LocalDate.now().getMonthValue());
                employeeLeaveList = employeeLeaveRepository.getEmplLeaveRequestsOfMonth(String.valueOf(LocalDate.now().getYear()), month, users.getCompany().getId(), users.getBranch().getId());
            }
            if(employeeLeaveList != null) {
                for (EmployeeLeave leave : employeeLeaveList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("leaveId", leave.getId());
                    object.addProperty("empId", leave.getEmployee().getId());
                    object.addProperty("empName", utility.getEmployeeName(leave.getEmployee()));
                    object.addProperty("designation", leave.getEmployee().getDesignation().getDesignationName());
                    object.addProperty("leaveType", leave.getLeaveMaster().getName());
                    object.addProperty("appliedOn", leave.getAppliedOn().toString());
                    object.addProperty("leaveFrom", leave.getFromDate().toString());
                    object.addProperty("leaveTo", leave.getToDate().toString());
                    object.addProperty("totalDays", leave.getTotalDays());
                    object.addProperty("comment", leave.getReason());
                    object.addProperty("status", leave.getLeaveStatus());
                    jsonArray.add(object);
                }
                responseMessage.add("response", jsonArray);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message", "Data not found");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject getEmployeeLeaveData(Map<String, String> jsonRequest, HttpServletRequest request) {
        Users user = null;
        JsonObject response = new JsonObject();
        List<Employee> employeesOnLeave = null;
        List<EmployeeLeave> approvedList =null;
        List<EmployeeLeave> pendingList = null;
        String attendanceDate = null;
        Shift shift  = null;
        try {
            JsonObject responseObj = new JsonObject();
            JsonArray allEmpArray = new JsonArray();
            user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(!user.getIsSuperAdmin()) {
                if (jsonRequest.get("attendanceDate") != null)
                    attendanceDate = jsonRequest.get("attendanceDate");
                else
                    attendanceDate = LocalDate.now().toString();
                if (jsonRequest.get("shift") != null)
                    shift = shiftRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("shift")), true);

                if (shift != null) {
//                    employeesOnLeave = employeeRepository.getEmployeeLeaveDataForDashboard(attendanceDate, shift.getId(), user.getCompany().getId(), user.getBranch().getId());
                    approvedList = employeeLeaveRepository.getListByShiftAndStatus("Approved", shift.getId(), attendanceDate, user.getCompany().getId(), user.getBranch().getId());
                    pendingList = employeeLeaveRepository.getListByShiftAndStatus("Pending", shift.getId(), attendanceDate, user.getCompany().getId(), user.getBranch().getId());
                }
                if(approvedList != null) {
                    for (EmployeeLeave employeeLeave : approvedList) {
                        JsonObject object = new JsonObject();
                        object.addProperty("name", utility.getEmployeeName(employeeLeave.getEmployee()));
                        object.addProperty("designation", employeeLeave.getEmployee().getDesignation().getDesignationName());
                        object.addProperty("checkIn", "-");
                        object.addProperty("checkOut", "-");
                        object.addProperty("emp_status", "on-leave");
                        allEmpArray.add(object);
                    }
                }
                responseObj.add("empOnLeaveArray", allEmpArray);
                responseObj.addProperty("approvedCount", approvedList != null ? approvedList.size() : 0);
                responseObj.addProperty("pendingCount", pendingList != null ? pendingList.size() : 0);
                response.add("response", responseObj);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "");
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception in getOverviewData:" + e.getMessage());
            response.addProperty("message", "Failed to load employee leave data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object deleteEmployeeLeave(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        EmployeeLeave employeeLeave = employeeLeaveRepository.findByIdAndStatus(Long.parseLong(requestParam.get("leaveId")), true);
        if (employeeLeave != null) {
            employeeLeave.setStatus(false);
            employeeLeave.setUpdatedBy(user.getId());
            employeeLeave.setUpdatedAt(LocalDateTime.now());
            try {
                employeeLeaveRepository.save(employeeLeave);
                responseObject.setMessage("Employee Leave deleted successfully");
                responseObject.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseObject.setMessage("Failed to delete Employee Deleted");
                e.printStackTrace();
                System.out.println("Exception:" + e.getMessage());
            }
        } else {
            responseObject.setMessage("Data not found");
            responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseObject;
    }

    public Object getEmpLeaveStatus(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject response = new JsonObject();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        try{
            if(employee != null) {
                JsonArray jsonArray = new JsonArray();
                List<EmployeeLeave> employeeLeaveList = null;
                String[] yearMonth = null;
                String userYear = null;
                String userMonth;
                String month = null;
                if (!jsonRequest.get("yearMonth").equalsIgnoreCase("")) {
                    yearMonth = jsonRequest.get("yearMonth").split("-");
                    userYear = yearMonth[0];
                    userMonth = yearMonth[1];
                    month = Integer.parseInt(userMonth) < 10 ? "0"+userMonth: userMonth;
                }
                if(yearMonth != null)
                    employeeLeaveList = employeeLeaveRepository.getEmplLeaveStatus(userYear, month, employee.getId());
                else {
                    month = LocalDate.now().getMonthValue() < 10 ? "0"+LocalDate.now().getMonthValue(): String.valueOf(LocalDate.now().getMonthValue());
                    employeeLeaveList = employeeLeaveRepository.getEmplLeaveStatus(String.valueOf(LocalDate.now().getYear()), month, employee.getId());
                }
                if(employeeLeaveList != null) {
                    for (EmployeeLeave leave : employeeLeaveList) {
                        JsonObject object = new JsonObject();
                        object.addProperty("leaveId", leave.getId());
                        object.addProperty("empId", leave.getEmployee().getId());
                        object.addProperty("empName", utility.getEmployeeName(leave.getEmployee()));
                        object.addProperty("designation", leave.getEmployee().getDesignation().getDesignationName());
                        object.addProperty("leaveType", leave.getLeaveMaster().getName());
                        object.addProperty("appliedOn", leave.getAppliedOn().toString());
                        object.addProperty("leaveFrom", leave.getFromDate().toString());
                        object.addProperty("leaveTo", leave.getToDate().toString());
                        object.addProperty("totalDays", leave.getTotalDays());
                        object.addProperty("comment", leave.getReason());
                        object.addProperty("status", leave.getLeaveStatus());
                        jsonArray.add(object);
                    }
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Employee not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        }catch(Exception e){
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
}
