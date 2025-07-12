package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.dto.ShiftDTDTO;
import com.opethic.hrms.HRMSNew.models.master.Shift;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.ShiftRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

@Service
public class ShiftService {
    @Autowired
    ShiftRepository shiftRepository;
    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @PersistenceContext
    private EntityManager entityManager;

    public Object createShift(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        LocalTime graceInPeriod = null;
        LocalTime graceOutPeriod = null;
        Boolean isDayDeduction = false;
        try {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            LocalTime startTime = LocalTime.parse(requestParam.get("startTime"));
            if(requestParam.containsKey("graceInPeriod"))
                graceInPeriod = LocalTime.parse(requestParam.get("graceInPeriod"));
            if(requestParam.containsKey("graceOutPeriod"))
                graceOutPeriod = LocalTime.parse(requestParam.get("graceOutPeriod"));
            if(requestParam.containsKey("isDayDeduction"))
                isDayDeduction=Boolean.parseBoolean((requestParam.get("isDayDeduction")));
            if(graceInPeriod.compareTo(startTime) < 0){
                responseObject.setMessage("Grace In Period value should be greater than Punch in time");
                responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            } else {
                Shift shift = new Shift();
                shift.setShiftName(requestParam.get("shiftName"));
                shift.setStartTime(startTime);
                shift.setGraceInPeriod(graceInPeriod);
                shift.setEndTime(LocalTime.parse(requestParam.get("endTime")));
                shift.setLunchTime(Long.valueOf(requestParam.get("lunchTime")));

//                shift.setLunchStartTime(LocalTime.parse(requestParam.get("lunchStartTime")));
//                shift.setLunchEndTime(LocalTime.parse(requestParam.get("lunchEndTime")));
                shift.setIsNightShift(Boolean.parseBoolean(requestParam.get("isNightShift")));
                shift.setWorkingHours(LocalTime.parse(requestParam.get("workingHours")));
                shift.setTotalHours(LocalTime.parse(requestParam.get("totalHours")));
                shift.setGraceOutPeriod(graceOutPeriod);
                shift.setIsDayDeduction(isDayDeduction);
                shift.setStatus(true);
                shift.setCreatedBy(user.getId());
                shift.setSecondHalfPunchInTime(LocalTime.parse(requestParam.get("secondHalfPunchInTime")));
                shift.setCompany(user.getCompany());
                shift.setBranch(user.getBranch());
                shift.setCreatedAt(LocalDateTime.now());
                if(requestParam.containsKey("considerationCount")) {
                    if(Long.parseLong(requestParam.get("considerationCount").toString()) != 0) {
                        shift.setConsiderationCount(Long.valueOf(requestParam.get("considerationCount")));
                        if (isDayDeduction != null) {
                            if (isDayDeduction == true) {
                                shift.setDayValueOfDeduction(requestParam.get("dayValueOfDeduction"));
                            } else {
                                shift.setHourValueOfDeduction(Double.parseDouble(requestParam.get("hourValueOfDeduction")));
                            }
                        }
                    }
                }
                try {
                    Shift shift1 = shiftRepository.save(shift);
                    responseObject.setMessage("Shift created successfully");
                    responseObject.setResponse(shift1);
                    responseObject.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception:" + e.getMessage());
                    responseObject.setMessage("Failed to create shift");
                    responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            responseObject.setMessage("Failed to create shift");
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseObject;
    }

    public JsonObject listOfShifts(HttpServletRequest httpServletRequest){
        Users users=jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        JsonObject response=new JsonObject();
        JsonArray jsonArray=new JsonArray();
        List<Shift> shiftList=null;
        try {
            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                shiftList=shiftRepository.findByCompanyIdAndStatus(users.getCompany().getId(),true);
            } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                shiftList=shiftRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
            }
            if(shiftList!=null){
                for (Shift shift: shiftList){
                    JsonObject object=new JsonObject();
                    object.addProperty("id",shift.getId());
                    object.addProperty("shiftName",shift.getShiftName());
                    object.addProperty("startTime",shift.getStartTime().toString());
                    object.addProperty("endTime",shift.getEndTime().toString());
                    object.addProperty("isNightShift",shift.getIsNightShift());
                    object.addProperty("isDayDeduction",shift.getIsDayDeduction() != null ? shift.getIsDayDeduction() : null);
                    object.addProperty("considerationCount",shift.getConsiderationCount() != null ? shift.getConsiderationCount() : null);
                    object.addProperty("dayValueOfDeduction",shift.getDayValueOfDeduction() != null ? shift.getDayValueOfDeduction() : null);
                    object.addProperty("hourValueOfDeduction",shift.getHourValueOfDeduction());
                    jsonArray.add(object);
                }
                response.add("response",jsonArray);
                response.addProperty("responseStatus",HttpStatus.OK.value());
            }else {
                response.addProperty("message","Data not found");
                response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
            }

        }catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception"+e.getMessage());
            response.addProperty("message","Failed to load data");
            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }


    public Object updateShift(Map<String ,String>requestParam,HttpServletRequest request){
        ResponseMessage responseObject=new ResponseMessage();
        try {
            Boolean isDayDeduction = false;
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Shift shift=shiftRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
            LocalTime startTime = LocalTime.parse(requestParam.get("startTime"));
            LocalTime graceInPeriod = LocalTime.parse(requestParam.get("graceInPeriod"));
            String graceOutPeriodValue = requestParam.get("graceOutPeriod");
            if(requestParam.containsKey("isDayDeduction"))
                isDayDeduction=Boolean.parseBoolean((requestParam.get("isDayDeduction")));
            LocalTime graceOutPeriod = null;

            if(graceInPeriod.compareTo(startTime) < 0){
                responseObject.setMessage("Grace In Period value should be greater than Punch in time");
                responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            } else {
                if (shift != null) {
                shift.setShiftName(requestParam.get("shiftName"));
                shift.setStartTime(startTime);
                shift.setGraceInPeriod(graceInPeriod);
                shift.setIsDayDeduction(isDayDeduction);
                shift.setConsiderationCount(requestParam.containsKey("considerationCount") ? Long.valueOf(requestParam.get("considerationCount")) : 0);
                shift.setEndTime(LocalTime.parse(requestParam.get("endTime")));
                    shift.setLunchTime(Long.valueOf(requestParam.get("lunchTime")));
//                shift.setLunchStartTime(LocalTime.parse(requestParam.get("lunchStartTime")));
//                shift.setLunchEndTime(LocalTime.parse(requestParam.get("lunchEndTime")));
                shift.setIsNightShift(Boolean.parseBoolean(requestParam.get("isNightShift")));
                shift.setWorkingHours(LocalTime.parse(requestParam.get("workingHours")));
                shift.setTotalHours(LocalTime.parse(requestParam.get("totalHours")));
                if (graceOutPeriodValue != null && !graceOutPeriodValue.isEmpty()) {
                    graceOutPeriod = LocalTime.parse(graceOutPeriodValue);
                }else {
                    graceOutPeriod = LocalTime.MIDNIGHT; // Set to 00:00:00 instead of null
                }
                if(isDayDeduction!=null && isDayDeduction==true){
                    shift.setDayValueOfDeduction(requestParam.get("dayValueOfDeduction"));
                }else{
                    shift.setHourValueOfDeduction(Double.parseDouble(requestParam.get("hourValueOfDeduction")));
                }

                shift.setGraceOutPeriod(graceOutPeriod);
                shift.setStatus(true);
                shift.setCreatedBy(user.getId());
                shift.setCompany(user.getCompany());
                shift.setBranch(user.getBranch());
                shift.setCreatedAt(LocalDateTime.now());
                    try {
                        Shift shift1 = shiftRepository.save(shift);
                        responseObject.setMessage("Shift Updated successfully");
                        responseObject.setResponse(shift1);
                        responseObject.setResponseStatus(HttpStatus.OK.value());
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Exception:" + e.getMessage());
                        responseObject.setMessage("Failed to Update shift");
                        responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                } else {
                    responseObject.setMessage("Data not found");
                    responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            responseObject.setMessage("Failed to Update shift");
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseObject;
    }
    public Object deleteShift(Map<String,String> requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        try {
            Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Shift shift=shiftRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
            if (shift!=null){
                shift.setStatus(false);
                shift.setUpdatedAt(LocalDateTime.now());
                shift.setUpdatedBy(users.getUpdatedBy());
                shift.setCompany(users.getCompany());
                shift.setBranch(users.getBranch());
                try {
                    shiftRepository.save(shift);
                    responseMessage.setMessage("Shift deleted Successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                }catch (Exception e){
                        e.printStackTrace();
                        System.out.println("Exception"+e.getMessage());
                        responseMessage.setMessage("Failed to delete shift");
                        responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            }
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception:"+e.getMessage());
            responseMessage.setMessage("Failed to delete shift");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public Object findShift(Map<String, String> requestParam,HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        try {
            Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(users!=null){
                Shift shift = shiftRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
                System.out.println(shift);
                if (shift != null) {
                    ShiftDTDTO shiftDTDTO=convertToDTO(shift);
                    responseMessage.setResponse(shiftDTDTO);
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } else {
                    responseMessage.setMessage("Data not found");
                    responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
                }
            }else {
                responseMessage.setMessage("Invalid User");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            responseMessage.setMessage("Shift not found");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    private ShiftDTDTO convertToDTO(Shift shift) {
        ShiftDTDTO shiftDTDTO = new ShiftDTDTO();
        shiftDTDTO.setId(shift.getId());
        shiftDTDTO.setShiftName(shift.getShiftName());
        shiftDTDTO.setStartTime(String.valueOf(shift.getStartTime()));
        shiftDTDTO.setEndTime(String.valueOf(shift.getEndTime()));
//        shiftDTDTO.setLunchStartTime(String.valueOf(shift.getLunchStartTime()));
//        shiftDTDTO.setLunchEndTime(String.valueOf(shift.getLunchEndTime()));
        shiftDTDTO.setLunchTime(String.valueOf(shift.getLunchTime()));
        shiftDTDTO.setWorkingHours(String.valueOf(shift.getWorkingHours()));
        shiftDTDTO.setGraceInPeriod(String.valueOf(shift.getGraceInPeriod()));
        shiftDTDTO.setGraceOutPeriod(String.valueOf(shift.getGraceOutPeriod()));
        shiftDTDTO.setSecondHalfPunchInTime(String.valueOf(shift.getSecondHalfPunchInTime()));
        shiftDTDTO.setTotalHours(String.valueOf(shift.getTotalHours()));
        shiftDTDTO.setIsNightShift(shift.getIsNightShift());
        shiftDTDTO.setConsiderationCount(shift.getConsiderationCount());
        shiftDTDTO.setIsDayDeduction(shift.getIsDayDeduction());
        shiftDTDTO.setDayValueOfDeduction(String.valueOf(shift.getDayValueOfDeduction()));
        shiftDTDTO.setHourValueOfDeduction(shift.getHourValueOfDeduction());
        shiftDTDTO.setCreatedBy(shift.getCreatedBy());
        shiftDTDTO.setCreatedAt(String.valueOf(shift.getCreatedAt()));
        shiftDTDTO.setUpdatedBy(shift.getUpdatedBy());
        if (shift.getUpdatedAt() != null)
            shiftDTDTO.setUpdatedAt(String.valueOf(shift.getUpdatedAt()));
        return shiftDTDTO;
    }
}
