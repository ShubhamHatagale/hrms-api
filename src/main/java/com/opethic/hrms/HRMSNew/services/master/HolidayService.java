package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Holiday;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.HolidayRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class HolidayService {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private HolidayRepository holidayRepository;

    public Object createHoliday(Map<String,String> requestParam, HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        LocalDate holidayFromDate=users.getCompany().getHolidayFromDate();
        LocalDate holidayToDate=users.getCompany().getHolidayToDate();
        if(LocalDate.parse(requestParam.get("fromDate")).isAfter(holidayFromDate) && LocalDate.parse(requestParam.get("toDate")).isBefore(holidayToDate)) {
            Holiday holiday = new Holiday();
            holiday.setHolidayName(requestParam.get("holidayName"));
            holiday.setFromDate(LocalDate.parse(requestParam.get("fromDate")));
            holiday.setToDate(LocalDate.parse(requestParam.get("toDate")));
            holiday.setTotalDays(Integer.valueOf(requestParam.get("totalDays")));
            holiday.setHolidayType(Boolean.valueOf(requestParam.get("holidayType")));
            holiday.setHolidayDescription(requestParam.get("holidayDescription"));
            holiday.setStatus(true);
//        if(request.getHeader("Authorization")!=null){
//            Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//            LocalDate holidayFromDate=users.getCompany().getHolidayFromDate();
//            LocalDate holidayToDate=users.getCompany().getHolidayToDate();
//
//            holiday.setCreatedBy(users.getId());
//            holiday.setCompany(users.getCompany());
//            holiday.setBranch(users.getBranch());
//        }
            try {
                Holiday holiday1 = holidayRepository.save(holiday);
                responseMessage.setResponse(holiday1);
                responseMessage.setMessage("Holiday Added Successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                responseMessage.setMessage("Failed to Create Holiday");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                e.printStackTrace();
                System.out.println("Exception" + e.getMessage());
            }
        }else{
            responseMessage.setMessage("Holidays should be between Holiday Calendar Dates");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }

    public JsonObject listOfHoliday(HttpServletRequest httpServletRequest){
        Users users=jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        JsonObject response=new JsonObject();
        JsonArray jsonArray=new JsonArray();
        try {
            if(users.getIsAdmin()){
                List<Holiday> holidayList=holidayRepository.findAllByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(),users.getBranch().getId(),true);
                for(Holiday holiday : holidayList){
                    JsonObject object=new JsonObject();
                    object.addProperty("id",holiday.getId());
                    object.addProperty("holidayName",holiday.getHolidayName());
                    object.addProperty("fromDate",holiday.getFromDate().toString());
                    object.addProperty("toDate",holiday.getToDate().toString());
                    object.addProperty("totalDays",holiday.getTotalDays());
                    object.addProperty("holidayType",holiday.getHolidayType());
                    object.addProperty("holidayDescription",holiday.getHolidayDescription());
                    jsonArray.add(object);
                }
                response.add("response",jsonArray);
                response.addProperty("responseStatus",HttpStatus.OK.value());
            }
        }catch (Exception e){
            response.addProperty("message","Failed to Load Data");
            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public JsonObject findHoliday(Map<String ,String> requestParam,HttpServletRequest request){
        JsonObject response=new JsonObject();
        Long holidayId=Long.parseLong(requestParam.get("id"));
        try {
            Holiday holiday=holidayRepository.findByIdAndStatus(holidayId,true);
            if(holiday!=null){
                JsonObject object=new JsonObject();
                object.addProperty("id",holiday.getId());
                object.addProperty("holidayName",holiday.getHolidayName());
                object.addProperty("fromDate",holiday.getFromDate().toString());
                object.addProperty("toDate",holiday.getToDate().toString());
                object.addProperty("totalDays",holiday.getTotalDays());
                object.addProperty("holidayType",holiday.getHolidayType());
                object.addProperty("holidayDescription",holiday.getHolidayDescription());
                response.add("response",object);
                response.addProperty("responseStatus",HttpStatus.OK.value());
            }else {
                response.addProperty("message","Failed to Load Data");
                response.addProperty("responseStatus",HttpStatus.NOT_FOUND.value());
            }
        }catch (Exception e){
            System.out.println("Exception" + e.getMessage());
            e.printStackTrace();
            response.addProperty("message","Failed to Load Data");
            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object updateHoliday(Map<String,String> requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        try{
            Holiday holiday=holidayRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
            Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            LocalDate holidayFromDate=users.getCompany().getHolidayFromDate();
            LocalDate holidayToDate=users.getCompany().getHolidayToDate();
            if(LocalDate.parse(requestParam.get("fromDate")).isAfter(holidayFromDate)&&LocalDate.parse(requestParam.get("toDate")).isBefore(holidayToDate)) {
                if (holiday != null) {
                    holiday.setHolidayName(requestParam.get("holidayName"));
                    holiday.setFromDate(LocalDate.parse(requestParam.get("fromDate")));
                    holiday.setToDate(LocalDate.parse(requestParam.get("toDate")));
                    holiday.setTotalDays(Integer.valueOf(requestParam.get("totalDays")));
                    holiday.setHolidayType(Boolean.valueOf(requestParam.get("holidayType")));
                    holiday.setHolidayDescription(requestParam.get("holidayDescription"));
                    holiday.setUpdatedBy(users.getId());
                    holiday.setCompany(users.getCompany());
                    holiday.setBranch(users.getBranch());
                    try {
                        holidayRepository.save(holiday);
                        responseMessage.setMessage("Holiday Updated Successfully");
                        responseMessage.setResponseStatus(HttpStatus.OK.value());
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Exception" + e.getMessage());
                        responseMessage.setMessage("Failed to Update Holiday");
                        responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
                    }
                } else {
                    responseMessage.setMessage("Failed to Update Holiday");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }else {
                responseMessage.setMessage("Holidays should be between Holiday Calendar Dates");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        }catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception" + e.getMessage());
            responseMessage.setMessage("Failed to Update Holiday");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public Object deleteHoliday(Map<String,String> requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            if(users!=null){
                Holiday holiday=holidayRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
                if(holiday!=null){
                    holiday.setStatus(false);
                    holiday.setUpdatedAt(LocalDateTime.now());
                }
                try {
                    holidayRepository.save(holiday);
                    responseMessage.setMessage("Holiday Deleted Successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                }catch (Exception e){
                    System.out.println("Exception"+e.getMessage());
                    responseMessage.setMessage("Failed to Delete Department");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            }else {
                responseMessage.setMessage("Invalid User");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception" + e.getMessage());
            responseMessage.setMessage("Failed to Delete Holiday");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
}
