package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.DesignationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class DesignationController {

    @Autowired
    private DesignationService designationService;

    @PostMapping(path = "/createDesignation")
    public ResponseEntity<?> createDesignation(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return ResponseEntity.ok(designationService.createDesignation(requestParam, request));
    }

    @PostMapping(path = "/findDesignation")
    public Object findDesignation(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return designationService.findDesignation(requestParam, request).toString();
    }

    @PostMapping(path = "/updateDesignation")
    public Object updateDesignation(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return designationService.updateDesignation(requestParam, request);
    }

    @GetMapping(path = "/listOfDesignation")
    public Object listOfDesignation(HttpServletRequest httpServletRequest) {
        JsonObject res = designationService.listOfDesignation(httpServletRequest);
        return res.toString();
    }

    @PostMapping(path = "/deleteDesignation")
    public Object deleteDesignation(@RequestBody Map<String, String> requestParam, HttpServletRequest request) {
        return designationService.deleteDesignation(requestParam, request);
    }
}
