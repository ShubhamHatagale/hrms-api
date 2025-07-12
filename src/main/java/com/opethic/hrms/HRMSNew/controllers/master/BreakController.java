package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.BreakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class BreakController {
    @Autowired
    private BreakService breakService;
    @PostMapping(path = "/mobile/startBreak")
    public Object startBreak(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        JsonObject result = breakService.startBreak(requestParam, request);
        return result.toString();
    }

    @PostMapping(path = "/mobile/endBreak")
    public Object endBreak(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return breakService.endBreak(requestParam, request);
    }

    @PostMapping(path = "/getTodaysBreaks")
    public Object getTodaysBreaks(@RequestBody Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject jsonObject = breakService.getTodaysBreaks(request,httpServletRequest);
        return jsonObject.toString();
    }
}
