package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.BreakMasterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class BreakMasterController {

    @Autowired
    private BreakMasterService breakMasterService;
    @PostMapping(path = "/createBreak")
    public Object createBreak(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return breakMasterService.createBreak(requestParam, request);
    }

    @PostMapping(path = "/findBreak")
    public Object findBreak(@RequestBody Map<String, String> request) {
        return breakMasterService.findBreak(request);
    }

    @PostMapping(path = "/updateBreak")
    public Object updateBreak(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return breakMasterService.updateBreak(requestParam, request);
    }

    @PostMapping(path = "/listOfBreak")
    public Object listOfBreak(@RequestBody Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject res = breakMasterService.listOfBreak(request, httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/deleteBreak")
    public Object deleteBreak(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return breakMasterService.deleteBreak(requestParam, request);
    }
}
