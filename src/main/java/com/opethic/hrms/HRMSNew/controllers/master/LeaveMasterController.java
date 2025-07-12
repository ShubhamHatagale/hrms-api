package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.LeaveMasterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class LeaveMasterController {
    @Autowired
    private LeaveMasterService leaveMasterService;
    @PostMapping(path = "/createLeaveMaster")
    public Object createLeaveMaster(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return leaveMasterService.createLeaveMaster(requestParam, request);
    }
    @PostMapping(path = "/findLeaveMaster")
    public Object findLeaveMaster(@RequestBody Map<String, String> requestParam) {
        return leaveMasterService.findLeaveMaster(requestParam);
    }

    @GetMapping(path = "/listOfLeaveMasters")
    public Object listOfLeaveMasters(HttpServletRequest httpServletRequest) {
        JsonObject res = leaveMasterService.listOfLeaveMasters(httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/updateLeaveMaster")
    public Object updateLeaveMaster(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return leaveMasterService.updateLeaveMaster(requestParam, request);
    }

    @PostMapping(path = "/deleteLeaveMaster")
    public Object deleteLeaveMaster(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return leaveMasterService.deleteLeaveMaster(requestParam, request);
    }

    /*mobile app url start*/
    @GetMapping(path = "/mobile/leaveMaster/listForSelection")
    public Object listForSelection(HttpServletRequest request) {
        JsonObject res = leaveMasterService.listForSelection(request);
        return res.toString();
    }

    @GetMapping(path = "/mobile/leavesDashboard")
    public Object leavesDashboard(HttpServletRequest request) {
        JsonObject res = leaveMasterService.leavesDashboard(request);
        return res.toString();
    }
    /*mobile app url end*/
}
