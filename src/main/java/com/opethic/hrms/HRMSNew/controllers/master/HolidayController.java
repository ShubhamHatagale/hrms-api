package com.opethic.hrms.HRMSNew.controllers.master;


import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.HolidayService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class HolidayController {

    @Autowired
    private HolidayService holidayService;

    @PostMapping(path = "/createHoliday")
    public Object createHoliday(@RequestBody Map<String,String> requestParam, HttpServletRequest request){
        return holidayService.createHoliday(requestParam,request);
    }

    @GetMapping(path = "/listOfHoliday")
    public Object listOfHoliday(HttpServletRequest httpServletRequest){
        JsonObject res=holidayService.listOfHoliday(httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/findHoliday")
    public Object findHoliday(@RequestBody Map<String ,String> requestParam,HttpServletRequest request){
        return holidayService.findHoliday(requestParam,request).toString();
    }

    @PostMapping(path = "/updateHoliday")
    public Object updateHoliday(@RequestBody Map<String,String> requestParam,HttpServletRequest request){
        return holidayService.updateHoliday(requestParam,request);
    }

    @PostMapping(path = "/deleteHoliday")
    public Object deleteHoliday(@RequestBody Map<String,String> requestParam,HttpServletRequest request){
        return holidayService.deleteHoliday(requestParam,request);
    }
}
