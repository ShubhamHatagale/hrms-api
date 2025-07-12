package com.opethic.hrms.HRMSNew.controllers.master;


import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.StateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class StateController {
    @Autowired
    private StateService service;

    /* get all States  */
    @GetMapping(path = "/getState")
    public Object getState(HttpServletRequest request) {
        JsonObject jsonObject = service.getState(request);
        return jsonObject.toString();
    }

    /* get all States of India Country */
    @GetMapping(path = "/getIndianState")
    public Object getIndianState(HttpServletRequest request) {
        JsonObject jsonObject = service.getIndianState(request);
        return jsonObject.toString();
    }
}
